use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rand::Rng;
use thiserror::Error;

use crate::traceroute_net::{Id, TracerouteChannel, TracerouteError, TracerouteResult};
use crate::whois_net::{Asn, AsnFinder};

#[derive(Error, Debug)]
pub enum TraceError {
    #[error("traceroute error")]
    Traceroute(#[from] TracerouteError),
    #[error("asn lookup error")]
    AsnLookup(#[source] io::Error),
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
    /// AFter reaching the destination, how long to wait for a response from every
    /// hop before giving up.
    pub completion_timeout: Duration,
}

#[derive(Debug)]
pub enum Hop {
    Unused,
    Pending(Id),
    FindingAsn(IpAddr, AsnFinder),
    Done(IpAddr, Option<Asn>),
}

#[derive(Debug, Clone, Copy)]
pub enum TerminationReason {
    Done,
    DestinationUnreachable,
    DestinationTimeout,
    CompletionTimeout,
}

#[derive(Debug)]
enum TraceState {
    NotStarted,
    OnHop { when: Instant, index: u8 },
    SentAllRequests { when: Instant, last_retry: Instant },
    ReachedDestination { when: Instant, last_retry: Instant },
    Terminated(TerminationReason),
}

#[derive(Debug)]
pub struct Trace<'a> {
    dst_ip: IpAddr,
    state: TraceState,
    config: &'a TraceConfig,
    hops_buffer: [Hop; u8::MAX as usize],
    used_hops: u8,
}

impl<'a> Trace<'a> {
    pub fn new(dst_ip: IpAddr, config: &'a TraceConfig) -> Self {
        Self {
            dst_ip,
            state: TraceState::NotStarted,
            config,
            hops_buffer: std::array::from_fn(|_| Hop::Unused),
            used_hops: 0,
        }
    }

    pub fn poll(
        &mut self,
        traceroute_channel: &mut TracerouteChannel,
    ) -> Result<Option<TerminationReason>, TraceError> {
        match self.state {
            TraceState::NotStarted => {
                self.start_next_hop(0, traceroute_channel)?;
                self.poll_inner(traceroute_channel)?;
            }
            TraceState::OnHop { when, index } => {
                if when.elapsed() > self.config.wait_time_per_hop {
                    self.start_next_hop(index + 1, traceroute_channel)?;
                }
                self.poll_inner(traceroute_channel)?;
            }
            TraceState::SentAllRequests {
                when,
                ref mut last_retry,
            } => {
                if when.elapsed() > self.config.destination_timeout {
                    self.state = TraceState::Terminated(TerminationReason::DestinationTimeout);
                } else if last_retry.elapsed() > self.config.retry_frequency {
                    *last_retry = Instant::now();
                    self.retry_ping(traceroute_channel)?;
                } else {
                    self.poll_inner(traceroute_channel)?;
                }
            }
            TraceState::ReachedDestination { when, last_retry } => {
                if when.elapsed() > self.config.completion_timeout && !self.all_hops_done() {
                    self.state = TraceState::Terminated(TerminationReason::CompletionTimeout);
                } else if last_retry.elapsed() > self.config.retry_frequency {
                    // Gross! But the borrow checker is annoyed otherwise.
                    if let TraceState::ReachedDestination {
                        ref mut last_retry, ..
                    } = self.state
                    {
                        *last_retry = Instant::now();
                    }

                    self.retry_ping(traceroute_channel)?;
                } else if self.all_hops_done() {
                    self.state = TraceState::Terminated(TerminationReason::Done);
                } else {
                    self.poll_inner(traceroute_channel)?;
                }
            }
            TraceState::Terminated(reason) => return Ok(Some(reason)),
        }
        Ok(None)
    }

    /// Slice of used hops.
    pub fn hops(&self) -> &[Hop] {
        &self.hops_buffer[..self.used_hops as usize]
    }

    /// Mutable slice of used hops.
    pub fn hops_mut(&mut self) -> &mut [Hop] {
        &mut self.hops_buffer[..self.used_hops as usize]
    }

    pub fn all_hops_done(&self) -> bool {
        self.hops().iter().all(|hop| matches!(hop, Hop::Done(_, _)))
    }

    fn retry_ping(&self, traceroute_channel: &mut TracerouteChannel) -> Result<(), TraceError> {
        for (index, hop) in self.hops().iter().enumerate() {
            if let Hop::Pending(id) = hop {
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
            let id = Id(rand::thread_rng().gen());
            self.state = TraceState::OnHop {
                when: Instant::now(),
                index,
            };
            self.hops_buffer[index as usize] = Hop::Pending(id);
            self.used_hops = self.used_hops.max(index + 1);
            traceroute_channel.send_echo(self.dst_ip, index + 1, id)?;
        }

        Ok(())
    }

    fn poll_inner(&mut self, traceroute_channel: &mut TracerouteChannel) -> Result<(), TraceError> {
        match traceroute_channel.poll()? {
            Some(TracerouteResult::IcmpReply(ip, id))
            | Some(TracerouteResult::IcmpTimeExceeded(ip, id)) => {
                if let Some(hop_index) = self.hops_mut().iter_mut().position(|hop| match hop {
                    Hop::Pending(hop_id) => hop_id == &id,
                    _ => false,
                }) {
                    let is_destination = ip == self.dst_ip;
                    self.hops_buffer[hop_index] =
                        Hop::FindingAsn(ip, AsnFinder::lookup(ip).map_err(TraceError::AsnLookup)?);

                    if is_destination {
                        self.state = TraceState::ReachedDestination {
                            when: Instant::now(),
                            last_retry: Instant::now(),
                        };
                    } else if let TraceState::OnHop { index, .. } = self.state {
                        if index == hop_index as u8 {
                            // If this was a response to our current hop, we can move on to the next.
                            self.start_next_hop(index + 1, traceroute_channel)?;
                            self.poll_inner(traceroute_channel)?;
                        }
                    }
                }
            }
            Some(TracerouteResult::IcmpDestinationUnreachable(ip)) => {
                if ip == self.dst_ip {
                    self.state = TraceState::Terminated(TerminationReason::DestinationUnreachable);
                }
            }
            None => {}
        }

        for hop in self.hops_mut() {
            if let Hop::FindingAsn(ip, asn) = hop {
                match asn.poll().map_err(TraceError::AsnLookup)? {
                    crate::whois_net::AsnResult::Found(asn) => *hop = Hop::Done(*ip, Some(asn)),
                    crate::whois_net::AsnResult::NotFound => *hop = Hop::Done(*ip, None),
                    crate::whois_net::AsnResult::Pending => {}
                }
            }
        }

        Ok(())
    }
}
