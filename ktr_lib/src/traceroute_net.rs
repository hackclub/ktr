use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use thiserror::Error;

use pnet::datalink::{channel, Channel, Config, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{icmp, icmpv6, ipv4, ipv6, Packet};
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{transport_channel, TransportProtocol, TransportSender};
use pnet::util::checksum;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(transparent)]
pub struct PacketId(pub u16);

#[derive(Error, Debug)]
pub enum TracerouteError {
    #[error("Error constructing packet")]
    PacketConstruction,
    #[error("IO error in RX channel: {0}")]
    RxChannelIo(#[source] io::Error),
    #[error("IO error in IPv4 channel: {0}")]
    Ipv4ChannelIo(#[source] io::Error),
    #[error("IO error in IPv6 channel: {0}")]
    Ipv6ChannelIo(#[source] io::Error),
    #[error("Tried to use IPv6 but enable_ipv6 was set to false")]
    Ipv6Disabled,
    #[error("Unknown and unexpected error")]
    Unknown,
}

#[derive(Debug)]
pub enum TracerouteResult {
    IcmpReply(IpAddr, PacketId),
    IcmpTimeExceeded(IpAddr, PacketId),
    IcmpDestinationUnreachable(IpAddr),
}

pub struct TracerouteChannel {
    rx: Box<dyn DataLinkReceiver>,
    v4_tx: TransportSender,
    v6_tx: Option<TransportSender>,
    /// Sequence number that increments per request. Not used for matching.
    sequence_number: u16,
}

impl TracerouteChannel {
    pub fn from_interface(
        interface: NetworkInterface,
        enable_ipv6: bool,
    ) -> Result<Self, TracerouteError> {
        let (_, rx) = match channel(
            &interface,
            Config {
                read_timeout: Some(Duration::from_millis(50)),
                ..Default::default()
            },
        ) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(TracerouteError::Unknown),
            Err(e) => return Err(TracerouteError::RxChannelIo(e)),
        };

        let (v4_tx, _) = match transport_channel(
            512,
            Layer3(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        ) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => return Err(TracerouteError::Ipv4ChannelIo(e)),
        };
        let v6_tx = if enable_ipv6 {
            let (v6_tx, _) = match transport_channel(
                512,
                Layer3(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
            ) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => return Err(TracerouteError::Ipv6ChannelIo(e)),
            };
            Some(v6_tx)
        } else {
            None
        };

        Ok(Self {
            rx,
            v4_tx,
            v6_tx,
            sequence_number: 0,
        })
    }

    pub fn send_echo(
        &mut self,
        dst_ip: IpAddr,
        ttl: u8,
        id: PacketId,
    ) -> Result<(), TracerouteError> {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        match dst_ip {
            IpAddr::V4(dst_ipv4) => {
                let icmp_len = icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size();
                let ip_len = ipv4::MutableIpv4Packet::minimum_packet_size() + icmp_len;
                let ip_header_len = ipv4::MutableIpv4Packet::minimum_packet_size() / 4;

                // Construct the IP packet
                let mut ip_buffer = vec![0; ip_len];
                let mut ip_packet = ipv4::MutableIpv4Packet::new(&mut ip_buffer)
                    .ok_or(TracerouteError::PacketConstruction)?;

                ip_packet.set_version(4);
                ip_packet.set_header_length(ip_header_len as u8);
                ip_packet.set_total_length(ip_len as u16);
                ip_packet.set_identification(id.0);
                ip_packet.set_flags(ipv4::Ipv4Flags::DontFragment);
                ip_packet.set_ttl(ttl);
                ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                ip_packet.set_source(Ipv4Addr::UNSPECIFIED);
                ip_packet.set_destination(dst_ipv4);

                // Construct the ICMP packet
                let mut icmp_buffer = vec![0; icmp_len];
                let mut icmp_packet =
                    icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer)
                        .ok_or(TracerouteError::PacketConstruction)?;

                icmp_packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);
                icmp_packet.set_icmp_code(icmp::echo_request::IcmpCodes::NoCode);
                icmp_packet.set_identifier(id.0);
                icmp_packet.set_sequence_number(self.sequence_number);

                let icmp_checksum = checksum(icmp_packet.packet(), 1);
                icmp_packet.set_checksum(icmp_checksum);

                // Send!
                ip_packet.set_payload(icmp_packet.packet());
                self.v4_tx
                    .send_to(ip_packet, dst_ip)
                    .map_err(TracerouteError::Ipv4ChannelIo)?;
            }
            IpAddr::V6(dst_ipv6) => {
                let icmpv6_len =
                    icmpv6::echo_request::MutableEchoRequestPacket::minimum_packet_size();
                let ipv6_len = ipv6::MutableIpv6Packet::minimum_packet_size() + icmpv6_len;

                // Construct the IP packet
                let mut ipv6_buffer = vec![0; ipv6_len];
                let mut ipv6_packet = ipv6::MutableIpv6Packet::new(&mut ipv6_buffer)
                    .ok_or(TracerouteError::PacketConstruction)?;

                ipv6_packet.set_version(6);
                ipv6_packet.set_flow_label(id.0 as u32);
                ipv6_packet.set_payload_length(icmpv6_len as u16);
                ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
                ipv6_packet.set_hop_limit(ttl);
                ipv6_packet.set_source(Ipv6Addr::UNSPECIFIED);
                ipv6_packet.set_destination(dst_ipv6);

                // Construct the ICMPv6 packet
                let mut icmpv6_buffer = vec![0; icmpv6_len];
                let mut icmpv6_packet =
                    icmpv6::echo_request::MutableEchoRequestPacket::new(&mut icmpv6_buffer)
                        .ok_or(TracerouteError::PacketConstruction)?;

                icmpv6_packet.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);
                icmpv6_packet.set_icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode);
                icmpv6_packet.set_identifier(id.0);
                icmpv6_packet.set_sequence_number(self.sequence_number);

                // ICMPv6 checksum should be calculated in the kernel.

                // Send!
                ipv6_packet.set_payload(icmpv6_packet.packet());
                self.v6_tx
                    .as_mut()
                    .ok_or(TracerouteError::Ipv6Disabled)?
                    .send_to(ipv6_packet, dst_ip)
                    .map_err(TracerouteError::Ipv6ChannelIo)?;
            }
        }

        Ok(())
    }

    pub fn poll(&mut self) -> Result<Option<TracerouteResult>, TracerouteError> {
        match self.rx.next() {
            Ok(packet) => Ok((|| {
                let packet = EthernetPacket::new(packet)?;

                match packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let packet = ipv4::Ipv4Packet::new(packet.payload())?;
                        let source_ip = packet.get_source();
                        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                            let packet = icmp::IcmpPacket::new(packet.payload())?;
                            match packet.get_icmp_type() {
                                icmp::IcmpTypes::EchoReply => {
                                    let packet =
                                        icmp::echo_reply::EchoReplyPacket::new(packet.packet())?;
                                    Some(TracerouteResult::IcmpReply(
                                        IpAddr::V4(source_ip),
                                        PacketId(packet.get_identifier()),
                                    ))
                                }
                                icmp::IcmpTypes::TimeExceeded => {
                                    let packet = icmp::time_exceeded::TimeExceededPacket::new(
                                        packet.packet(),
                                    )?;
                                    let packet = ipv4::Ipv4Packet::new(packet.payload())?;

                                    Some(TracerouteResult::IcmpTimeExceeded(
                                        IpAddr::V4(source_ip),
                                        PacketId(packet.get_identification()),
                                    ))
                                }
                                icmp::IcmpTypes::DestinationUnreachable => {
                                    Some(TracerouteResult::IcmpDestinationUnreachable(IpAddr::V4(
                                        source_ip,
                                    )))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    EtherTypes::Ipv6 => {
                        let packet = ipv6::Ipv6Packet::new(packet.payload()).unwrap();
                        let source_ip = packet.get_source();
                        if packet.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
                            let packet = icmpv6::Icmpv6Packet::new(packet.payload())?;
                            match packet.get_icmpv6_type() {
                                icmpv6::Icmpv6Types::EchoReply => {
                                    let packet =
                                        icmp::echo_reply::EchoReplyPacket::new(packet.packet())?;
                                    Some(TracerouteResult::IcmpReply(
                                        IpAddr::V6(source_ip),
                                        PacketId(packet.get_identifier()),
                                    ))
                                }
                                icmpv6::Icmpv6Types::TimeExceeded => {
                                    let packet = icmp::time_exceeded::TimeExceededPacket::new(
                                        packet.packet(),
                                    )?;
                                    let packet = ipv4::Ipv4Packet::new(packet.payload())?;

                                    Some(TracerouteResult::IcmpTimeExceeded(
                                        IpAddr::V6(source_ip),
                                        PacketId(packet.get_identification()),
                                    ))
                                }
                                icmpv6::Icmpv6Types::DestinationUnreachable => {
                                    Some(TracerouteResult::IcmpDestinationUnreachable(IpAddr::V6(
                                        source_ip,
                                    )))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })()),
            Err(error) if error.kind() == ErrorKind::TimedOut => Ok(None),
            Err(error) => Err(TracerouteError::RxChannelIo(error)),
        }
    }
}

pub fn interface_from_name(name: &str) -> Option<NetworkInterface> {
    let interfaces = pnet::datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == name)
}
