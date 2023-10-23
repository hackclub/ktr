use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use quick_cache::unsync::Cache;
use rand::Rng;
use thiserror::Error;

use crate::peeringdb::{Network, PeeringDbError, PeeringDbManager};
use crate::traceroute_net::{PacketId, TracerouteChannel, TracerouteError, TracerouteResult};
use crate::whois_net::{Asn, AsnFinder, AsnResult};

#[derive(Error, Debug)]
pub enum TraceError {
    #[error("Traceroute error")]
    Traceroute(#[from] TracerouteError),
    #[error("ASN lookup error")]
    AsnLookup(#[source] io::Error),
    #[error("Reverse DNS lookup error")]
    Rdns(#[source] io::Error),
    #[error("PeeringDB search error")]
    PeeringDb(#[from] PeeringDbError),
}

#[cfg(feature = "serde")]
impl serde::Serialize for TraceError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("TraceError", 2)?;
        state.serialize_field(
            "kind",
            match self {
                TraceError::Traceroute(_) => "Traceroute",
                TraceError::AsnLookup(_) => "AsnLookup",
                TraceError::PeeringDb(_) => "PeeringDb",
                TraceError::Rdns(_) => "Rdns",
            },
        )?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TraceConfig {
    /// The maximum number of hops.
    pub max_hops: u8,
    /// How long to wait for a response from each hop before moving to the next.
    pub wait_time_per_hop: Duration,
    /// After all initial pings are sent, how long between retries.
    pub retry_frequency: Duration,
    /// How long to wait to reach the destination before giving up.
    pub destination_timeout: Duration,
    /// After reaching the destination, how long to wait for a response from every
    /// hop before giving up.
    pub completion_timeout: Duration,
    /// Size of the cache for IP to ASN WHOIS lookups.
    pub asn_cache_size: usize,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NetworkInfo {
    pub asn: Asn,
    pub network: Option<Network>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind"))]
pub enum Hop {
    Unused,

    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    #[non_exhaustive]
    Pending {
        id: PacketId,
    },

    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    #[non_exhaustive]
    FindingAsn {
        ip: IpAddr,
        #[cfg_attr(feature = "serde", serde(skip))]
        finder: AsnFinder,
    },

    #[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
    #[non_exhaustive]
    Done {
        ip: IpAddr,
        hostname: Option<String>,
        network_info: Option<NetworkInfo>,
    },
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum TerminationReason {
    Done,
    DestinationUnreachable,
    DestinationTimeout,
    CompletionTimeout,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DidUpdate {
    Yes,
    No,
}

impl DidUpdate {
    pub fn or(&self, other: Self) -> Self {
        match (self, other) {
            (DidUpdate::Yes, _) => DidUpdate::Yes,
            (_, DidUpdate::Yes) => DidUpdate::Yes,
            (DidUpdate::No, DidUpdate::No) => DidUpdate::No,
        }
    }
}

#[derive(Debug)]
enum TraceState {
    NotStarted,
    OnHop { when: Instant, index: u8 },
    SentAllRequests { when: Instant, last_retry: Instant },
    ReachedDestination { when: Instant, last_retry: Instant },
    Terminated(TerminationReason),
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_documentation())
        }
        IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_multicast() || ip.is_unspecified()),
    }
}

fn get_network_info(asn: Asn, peeringdb: &PeeringDbManager) -> Result<NetworkInfo, TraceError> {
    Ok(NetworkInfo {
        asn,
        network: peeringdb
            .network_by_asn(asn)
            .map_err(TraceError::PeeringDb)?,
    })
}

fn do_rdns(ip: &IpAddr) -> Result<Option<String>, TraceError> {
    match dns_lookup::lookup_addr(ip) {
        Ok(hostname) => Ok(Some(hostname)),
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(TraceError::Rdns(error))
            }
        }
    }
}

#[derive(Debug)]
pub struct Trace<'a> {
    dst_ip: IpAddr,
    state: TraceState,
    config: &'a TraceConfig,
    hops_buffer: [Hop; u8::MAX as usize],
    used_hops: u8,
    /// Option<Asn> because we want to cache lookup failures as well.
    asn_cache: Cache<IpAddr, Option<Asn>>,
}

impl<'a> Trace<'a> {
    pub fn new(dst_ip: IpAddr, config: &'a TraceConfig) -> Self {
        Self {
            dst_ip,
            state: TraceState::NotStarted,
            config,
            hops_buffer: std::array::from_fn(|_| Hop::Unused),
            used_hops: 0,
            asn_cache: Cache::new(config.asn_cache_size),
        }
    }

    pub fn poll(
        &mut self,
        traceroute_channel: &mut TracerouteChannel,
        peeringdb: &PeeringDbManager,
    ) -> Result<(DidUpdate, Option<TerminationReason>), TraceError> {
        let did_update: DidUpdate = match self.state {
            TraceState::NotStarted => {
                self.start_next_hop(0, traceroute_channel)?;
                self.poll_inner(traceroute_channel, peeringdb)?
            }
            TraceState::OnHop { when, index } => {
                if when.elapsed() > self.config.wait_time_per_hop {
                    self.start_next_hop(index + 1, traceroute_channel)?;
                }
                self.poll_inner(traceroute_channel, peeringdb)?
            }
            TraceState::SentAllRequests {
                when,
                ref mut last_retry,
            } => {
                if when.elapsed() > self.config.destination_timeout {
                    self.state = TraceState::Terminated(TerminationReason::DestinationTimeout);
                    DidUpdate::Yes
                } else if last_retry.elapsed() > self.config.retry_frequency {
                    *last_retry = Instant::now();
                    self.retry_ping(traceroute_channel)?;
                    DidUpdate::No
                } else {
                    self.poll_inner(traceroute_channel, peeringdb)?
                }
            }
            TraceState::ReachedDestination { when, last_retry } => {
                if when.elapsed() > self.config.completion_timeout && !self.all_hops_done() {
                    self.state = TraceState::Terminated(TerminationReason::CompletionTimeout);
                    DidUpdate::Yes
                } else if last_retry.elapsed() > self.config.retry_frequency {
                    // Gross! But the borrow checker is annoyed otherwise.
                    if let TraceState::ReachedDestination {
                        ref mut last_retry, ..
                    } = self.state
                    {
                        *last_retry = Instant::now();
                    }

                    self.retry_ping(traceroute_channel)?;
                    DidUpdate::No
                } else if self.all_hops_done() {
                    self.state = TraceState::Terminated(TerminationReason::Done);
                    DidUpdate::Yes
                } else {
                    self.poll_inner(traceroute_channel, peeringdb)?;
                    DidUpdate::No
                }
            }
            TraceState::Terminated(_) => DidUpdate::Yes,
        };

        match self.state {
            TraceState::Terminated(reason) => Ok((did_update, Some(reason))),
            _ => Ok((did_update, None)),
        }
    }

    /// Slice of used hops.
    #[inline]
    pub fn hops(&self) -> &[Hop] {
        &self.hops_buffer[..self.used_hops as usize]
    }

    /// Mutable slice of used hops.
    #[inline]
    pub fn hops_mut(&mut self) -> &mut [Hop] {
        &mut self.hops_buffer[..self.used_hops as usize]
    }

    /// Turn into hops.
    #[inline]
    pub fn to_hops(mut self) -> Vec<Hop> {
        let mut hops = Vec::with_capacity(self.used_hops as usize);
        for hop in self.hops_mut() {
            hops.push(std::mem::replace(hop, Hop::Unused));
        }
        hops
    }

    #[inline]
    pub fn all_hops_done(&self) -> bool {
        self.hops()
            .iter()
            .all(|hop| matches!(hop, Hop::Done { .. }))
    }

    fn retry_ping(&self, traceroute_channel: &mut TracerouteChannel) -> Result<(), TraceError> {
        for (index, hop) in self.hops().iter().enumerate() {
            if let Hop::Pending { id } = hop {
                traceroute_channel.send_echo(self.dst_ip, index as u8 + 1, *id)?;
            }
        }

        Ok(())
    }

    fn start_next_hop(
        &mut self,
        index: u8,
        traceroute_channel: &mut TracerouteChannel,
    ) -> Result<(), TraceError> {
        if index == self.config.max_hops - 1 {
            self.state = TraceState::SentAllRequests {
                when: Instant::now(),
                last_retry: Instant::now(),
            };
        } else {
            let id = PacketId(rand::thread_rng().gen());
            self.state = TraceState::OnHop {
                when: Instant::now(),
                index,
            };
            self.hops_buffer[index as usize] = Hop::Pending { id };
            self.used_hops = self.used_hops.max(index + 1);
            traceroute_channel.send_echo(self.dst_ip, index + 1, id)?;
        }

        Ok(())
    }

    fn poll_inner(
        &mut self,
        traceroute_channel: &mut TracerouteChannel,
        peeringdb: &PeeringDbManager,
    ) -> Result<DidUpdate, TraceError> {
        let mut did_update: DidUpdate = match traceroute_channel.poll()? {
            Some(TracerouteResult::IcmpReply(ip, id))
            | Some(TracerouteResult::IcmpTimeExceeded(ip, id)) => {
                if let Some(hop_index) = self.hops_mut().iter_mut().position(|hop| match hop {
                    Hop::Pending { id: hop_id } => hop_id == &id,
                    _ => false,
                }) {
                    let is_destination = ip == self.dst_ip;
                    self.hops_buffer[hop_index] = if is_public(ip) {
                        if let Some(&maybe_asn) = self.asn_cache.get(&ip) {
                            Hop::Done {
                                ip,
                                hostname: do_rdns(&ip)?,
                                network_info: maybe_asn
                                    .map(|asn| get_network_info(asn, peeringdb))
                                    .transpose()?,
                            }
                        } else {
                            Hop::FindingAsn {
                                ip,
                                finder: AsnFinder::lookup(ip).map_err(TraceError::AsnLookup)?,
                            }
                        }
                    } else {
                        Hop::Done {
                            ip,
                            hostname: do_rdns(&ip)?,
                            network_info: None,
                        }
                    };

                    if is_destination {
                        self.state = TraceState::ReachedDestination {
                            when: Instant::now(),
                            last_retry: Instant::now(),
                        };
                        DidUpdate::Yes
                    } else if let TraceState::OnHop { index, .. } = self.state {
                        if index == hop_index as u8 {
                            // If this was a response to our current hop, we can move on to the next.
                            self.start_next_hop(index + 1, traceroute_channel)?;
                            self.poll_inner(traceroute_channel, peeringdb)?;
                        }
                        DidUpdate::Yes
                    } else {
                        DidUpdate::No
                    }
                } else {
                    DidUpdate::No
                }
            }
            Some(TracerouteResult::IcmpDestinationUnreachable(ip)) => {
                if ip == self.dst_ip {
                    self.state = TraceState::Terminated(TerminationReason::DestinationUnreachable);
                    DidUpdate::Yes
                } else {
                    DidUpdate::No
                }
            }
            None => DidUpdate::No,
        };

        // Can't use .hops_mut() here because the borrow checker doesn't know that we're only using part of the struct.
        for hop in &mut self.hops_buffer[..self.used_hops as usize] {
            did_update = did_update.or(if let Hop::FindingAsn { ip, finder } = hop {
                match finder.poll().map_err(TraceError::AsnLookup)? {
                    AsnResult::Found(asn) => {
                        self.asn_cache.insert(*ip, Some(asn));
                        *hop = Hop::Done {
                            ip: *ip,
                            hostname: do_rdns(ip)?,
                            network_info: Some(get_network_info(asn, peeringdb)?),
                        };
                        DidUpdate::Yes
                    }
                    AsnResult::NotFound => {
                        self.asn_cache.insert(*ip, None);
                        *hop = Hop::Done {
                            ip: *ip,
                            hostname: do_rdns(ip)?,
                            network_info: None,
                        };
                        DidUpdate::Yes
                    }
                    AsnResult::Pending => DidUpdate::No,
                }
            } else {
                DidUpdate::No
            });
        }

        Ok(did_update)
    }
}
