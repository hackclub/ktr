use std::net::IpAddr;

use ktr_lib::peeringdb::{Network, PeeringDbManager};
use ktr_lib::trace::{DidUpdate, Hop, TerminationReason, Trace, TraceConfig, TraceError};
use ktr_lib::traceroute_net::TracerouteChannel;
use ktr_lib::whois_net::Asn;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

/// Index into the list of traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[repr(transparent)]
pub struct TraceId(usize);

/// Trace termination reason, or an error. We never want to panic.
#[derive(Debug)]
pub enum SafeTerminationReason {
    Termination(TerminationReason),
    Error(TraceError),
}

impl Serialize for SafeTerminationReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SafeTerminationReason::Termination(reason) => {
                let mut state = serializer.serialize_struct("SafeTerminationReason", 2)?;
                state.serialize_field("kind", "Termination")?;
                state.serialize_field("reason", reason)?;
                state.end()
            }
            SafeTerminationReason::Error(error) => {
                let mut state = serializer.serialize_struct("SafeTerminationReason", 2)?;
                state.serialize_field("kind", "Error")?;
                state.serialize_field("error", error)?;
                state.end()
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum ControllerResult<'a> {
    #[serde(rename_all = "camelCase")]
    TraceUpdate { id: TraceId, hops: &'a [Hop] },
    #[serde(rename_all = "camelCase")]
    TraceDone {
        id: TraceId,
        hops: Vec<Hop>,
        reason: SafeTerminationReason,
    },
}

pub struct ControllerConfig<'a> {
    pub traceroute_channel: TracerouteChannel,
    pub peeringdb: PeeringDbManager,
    pub trace_config: &'a TraceConfig,
}

pub struct Controller<'a> {
    traceroute_channel: TracerouteChannel,
    peeringdb: PeeringDbManager,
    trace_config: &'a TraceConfig,
    traces: Vec<Option<Trace<'a>>>,
    next_id: usize,
    iter_cursor: usize,
}

macro_rules! handle_poll_result {
    ($self: ident, $trace_id: expr, $poll_result: expr) => {
        match $poll_result {
            Ok((DidUpdate::No, _)) => {}
            Ok((DidUpdate::Yes, None)) => {
                return Some(ControllerResult::TraceUpdate {
                    id: TraceId($trace_id),
                    hops: $self.traces[$trace_id].as_ref().unwrap().hops(),
                });
            }
            Ok((DidUpdate::Yes, Some(termination_reason))) => {
                $self.next_id = $self.iter_cursor.min($self.next_id);
                return Some(ControllerResult::TraceDone {
                    id: TraceId($trace_id),
                    hops: $self.traces[$trace_id].take().unwrap().to_hops(),
                    reason: SafeTerminationReason::Termination(termination_reason),
                });
            }
            Err(error) => {
                $self.next_id = $trace_id.min($self.next_id);
                return Some(ControllerResult::TraceDone {
                    id: TraceId($trace_id),
                    hops: $self.traces[$trace_id].take().unwrap().to_hops(),
                    reason: SafeTerminationReason::Error(error),
                });
            }
        }
    };
}

impl<'a> Controller<'a> {
    pub fn new(config: ControllerConfig<'a>) -> Self {
        Self {
            traceroute_channel: config.traceroute_channel,
            peeringdb: config.peeringdb,
            trace_config: config.trace_config,
            traces: vec![],
            next_id: 0,
            iter_cursor: 0,
        }
    }

    pub fn try_next<'b>(&'b mut self) -> Option<ControllerResult<'b>>
    where
        'a: 'b,
    {
        if self.traces.is_empty() {
            return None;
        }

        match self.traceroute_channel.poll() {
            Ok(Some(result)) => {
                for (i, trace) in self.traces.iter_mut().enumerate() {
                    if let Some(trace) = trace {
                        let poll_result = trace.perhaps_use_packet(
                            &result,
                            &mut self.traceroute_channel,
                            &self.peeringdb,
                        );
                        handle_poll_result!(self, i, poll_result);
                    }
                }
            }
            Err(error) => {
                eprintln!("Error polling traceroute channel: {:?}", error);
            }
            Ok(None) => {}
        };

        let start_cursor = self.iter_cursor;
        loop {
            if let Some(trace) = &mut self.traces[self.iter_cursor] {
                let poll_result =
                    trace.non_packet_poll(&mut self.traceroute_channel, &self.peeringdb);
                handle_poll_result!(self, self.iter_cursor, poll_result);
            }

            self.iter_cursor = (self.iter_cursor + 1) % self.traces.len();

            // If we've polled everything without any result, we're done for now.
            if self.iter_cursor == start_cursor {
                break None;
            }
        }
    }

    pub fn start_trace(&mut self, ip: IpAddr) -> TraceId {
        if self.next_id < self.traces.len() {
            let id = self.next_id;
            self.traces[self.next_id] = Some(Trace::new(ip, self.trace_config));

            // Pick next id
            for i in (id + 1)..=self.traces.len() {
                if i == self.traces.len() || self.traces[i].is_none() {
                    self.next_id = i;
                    break;
                }
            }

            TraceId(id)
        } else {
            self.traces.push(Some(Trace::new(ip, self.trace_config)));
            self.next_id = self.traces.len();
            TraceId(self.next_id - 1)
        }
    }

    pub fn lookup_asn(&self, asn: Asn) -> Option<Network> {
        match self.peeringdb.network_by_asn(asn) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("Returning None due to ASN lookup error: {:?}", error);
                None
            }
        }
    }
}
