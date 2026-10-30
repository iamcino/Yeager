//! Packet parsing & reconstruction for IPv4 / IPv6 / TCP.

#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    pub ip_version: u8,
    pub ip_header_len: usize,
    pub ip_total_len: usize,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub tcp_header_len: usize,
    pub tcp_payload_offset: usize,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_flags: u8,
    pub payload: &'a [u8],
}

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;

/// Compact, copyable packet header metadata used to reconstruct [`ParsedPacket`] in worker threads
/// with zero re-parsing overhead and zero heap allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMetadata {
    pub ip_version: u8,
    pub ip_header_len: usize,
    pub ip_total_len: usize,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub tcp_header_len: usize,
    pub tcp_payload_offset: usize,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_flags: u8,
}

impl PacketMetadata {
    /// Reconstructs a [`ParsedPacket`] reference directly from cached header offsets without re-parsing.
    #[inline]
    pub fn to_parsed<'a>(&self, buf: &'a [u8]) -> ParsedPacket<'a> {
        let actual_total = std::cmp::min(self.ip_total_len, buf.len());
        let payload = if actual_total >= self.tcp_payload_offset {
            &buf[self.tcp_payload_offset..actual_total]
        } else {
            &[]
        };

        ParsedPacket {
            ip_version: self.ip_version,
            ip_header_len: self.ip_header_len,
            ip_total_len: actual_total,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            tcp_header_len: self.tcp_header_len,
            tcp_payload_offset: self.tcp_payload_offset,
            src_port: self.src_port,
            dst_port: self.dst_port,
            tcp_seq: self.tcp_seq,
            tcp_ack: self.tcp_ack,
            tcp_flags: self.tcp_flags,
            payload,
        }
    }
}

impl<'a> ParsedPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }

        let version = buf[0] >> 4;
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];

        let (ip_header_len, ip_total_len, next_proto) = match version {
            4 => {
                if buf.len() < 20 {
                    return None;
                }
                let ihl = ((buf[0] & 0x0F) * 4) as usize;
                let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                let proto = buf[9];

                // IPv4-mapped IPv6 representation
                src_ip[10] = 0xff;
                src_ip[11] = 0xff;
                src_ip[12..16].copy_from_slice(&buf[12..16]);

                dst_ip[10] = 0xff;
                dst_ip[11] = 0xff;
                dst_ip[12..16].copy_from_slice(&buf[16..20]);

                (ihl, total_len, proto)
            }
            6 => {
                if buf.len() < 40 {
                    return None;
                }
                let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
                let next_header = buf[6];

                src_ip.copy_from_slice(&buf[8..24]);
                dst_ip.copy_from_slice(&buf[24..40]);

                (40, 40 + payload_len, next_header)
            }
            _ => return None,
        };

        if next_proto != 6 {
            // Not TCP
            return None;
        }

        if buf.len() < ip_header_len + 20 {
            return None;
        }

        let tcp_slice = &buf[ip_header_len..];
        let data_offset = ((tcp_slice[12] >> 4) * 4) as usize;
        if data_offset < 20 || tcp_slice.len() < data_offset {
            return None;
        }

        let src_port = u16::from_be_bytes([tcp_slice[0], tcp_slice[1]]);
        let dst_port = u16::from_be_bytes([tcp_slice[2], tcp_slice[3]]);
        let tcp_seq = u32::from_be_bytes([tcp_slice[4], tcp_slice[5], tcp_slice[6], tcp_slice[7]]);
        let tcp_ack = u32::from_be_bytes([tcp_slice[8], tcp_slice[9], tcp_slice[10], tcp_slice[11]]);
        let tcp_flags = tcp_slice[13];

        let payload_offset = ip_header_len + data_offset;
        let actual_total = std::cmp::min(ip_total_len, buf.len());
        if actual_total < payload_offset {
            return None;
        }

        let payload = &buf[payload_offset..actual_total];

        Some(Self {
            ip_version: version,
            ip_header_len,
            ip_total_len: actual_total,
            src_ip,
            dst_ip,
            tcp_header_len: data_offset,
            tcp_payload_offset: payload_offset,
            src_port,
            dst_port,
            tcp_seq,
            tcp_ack,
            tcp_flags,
            payload,
        })
    }

    /// Extracts lightweight, copyable packet header metadata to avoid redundant re-parsing in worker threads.
    #[inline]
    pub fn metadata(&self) -> PacketMetadata {
        PacketMetadata {
            ip_version: self.ip_version,
            ip_header_len: self.ip_header_len,
            ip_total_len: self.ip_total_len,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            tcp_header_len: self.tcp_header_len,
            tcp_payload_offset: self.tcp_payload_offset,
            src_port: self.src_port,
            dst_port: self.dst_port,
            tcp_seq: self.tcp_seq,
            tcp_ack: self.tcp_ack,
            tcp_flags: self.tcp_flags,
        }
    }

    /// Checks if the destination IP address belongs to RFC 1918 Private, Loopback, Link-Local, or Multicast.
    /// Connections to these local/internal addresses should pass through unmodified without transport segmentation.
    #[inline]
    pub fn is_private_or_local_dst(&self) -> bool {
        match self.ip_version {
            4 => {
                let b0 = self.dst_ip[12];
                let b1 = self.dst_ip[13];
                // 127.0.0.0/8 (Loopback)
                b0 == 127
                // 10.0.0.0/8 (Private RFC 1918)
                || b0 == 10
                // 172.16.0.0/12 (Private RFC 1918)
                || (b0 == 172 && (16..=31).contains(&b1))
                // 192.168.0.0/16 (Private RFC 1918)
                || (b0 == 192 && b1 == 168)
                // 169.254.0.0/16 (Link-Local)
                || (b0 == 169 && b1 == 254)
                // 224.0.0.0/4 (Multicast) or 240.0.0.0/4 (Reserved)
                || b0 >= 224
            }
            6 => {
                let dst = &self.dst_ip;
                // ::1 (Loopback)
                (dst[..15].iter().all(|&b| b == 0) && dst[15] == 1)
                // fe80::/10 (Link-Local)
                || (dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80)
                // fc00::/7 (Unique Local)
                || ((dst[0] & 0xfe) == 0xfc)
                // ff00::/8 (Multicast)
                || dst[0] == 0xff
                // On-Link Same /64 Subnet Prefix: Local LAN peer communication (NAS, IoT, PC)
                || (self.src_ip[0] != 0 && self.src_ip[..8] == self.dst_ip[..8])
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_packet(dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL = 5
        pkt[2] = 0; pkt[3] = 40;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 100]); // src
        pkt[16..20].copy_from_slice(&dst); // dst
        pkt[32] = 0x50; // TCP offset 5
        pkt
    }

    fn build_ipv6_packet(dst: [u8; 16]) -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60; // IPv6
        pkt[4] = 0; pkt[5] = 20; // payload 20
        pkt[6] = 6; // TCP
        pkt[24..40].copy_from_slice(&dst); // dst
        pkt[52] = 0x50; // TCP offset 5
        pkt
    }

    #[test]
    fn test_private_or_local_dst_ipv4() {
        let b1 = build_ipv4_packet([192, 168, 1, 1]);
        assert!(ParsedPacket::parse(&b1).unwrap().is_private_or_local_dst());

        let b2 = build_ipv4_packet([10, 0, 0, 5]);
        assert!(ParsedPacket::parse(&b2).unwrap().is_private_or_local_dst());

        let b3 = build_ipv4_packet([172, 20, 1, 10]);
        assert!(ParsedPacket::parse(&b3).unwrap().is_private_or_local_dst());

        let b4 = build_ipv4_packet([127, 0, 0, 1]);
        assert!(ParsedPacket::parse(&b4).unwrap().is_private_or_local_dst());

        let b5 = build_ipv4_packet([1, 1, 1, 1]);
        assert!(!ParsedPacket::parse(&b5).unwrap().is_private_or_local_dst());

        let b6 = build_ipv4_packet([66, 254, 114, 41]);
        assert!(!ParsedPacket::parse(&b6).unwrap().is_private_or_local_dst());
    }

    #[test]
    fn test_private_or_local_dst_ipv6() {
        let b1 = build_ipv6_packet([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
        assert!(ParsedPacket::parse(&b1).unwrap().is_private_or_local_dst());

        let b2 = build_ipv6_packet([0xfe, 0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
        assert!(ParsedPacket::parse(&b2).unwrap().is_private_or_local_dst());

        // 2001:ee0:4f35::30 (Public VNPT IPv6) -> MUST NOT be local when src is different
        let b3 = build_ipv6_packet([0x20, 0x01, 0x0e, 0xe0, 0x4f, 0x35, 0,0,0,0,0,0,0,0,0,0x30]);
        assert!(!ParsedPacket::parse(&b3).unwrap().is_private_or_local_dst());

        // On-Link Peer on the same /64 prefix (e.g. local NAS at ::50 communicating with local PC at ::30)
        let mut b4 = build_ipv6_packet([0x20, 0x01, 0x0e, 0xe0, 0x4f, 0x35, 0xdc, 0xff, 0,0,0,0,0,0,0,0x50]);
        // Set src_ip to same /64 prefix: 2001:ee0:4f35:dcff::30
        b4[8..24].copy_from_slice(&[0x20, 0x01, 0x0e, 0xe0, 0x4f, 0x35, 0xdc, 0xff, 0,0,0,0,0,0,0,0x30]);
        assert!(ParsedPacket::parse(&b4).unwrap().is_private_or_local_dst());
    }

    #[test]
    fn test_packet_metadata_roundtrip() {
        let b1 = build_ipv4_packet([192, 168, 1, 1]);
        let parsed = ParsedPacket::parse(&b1).unwrap();
        let meta = parsed.metadata();
        let reconstructed = meta.to_parsed(&b1);

        assert_eq!(reconstructed.ip_version, parsed.ip_version);
        assert_eq!(reconstructed.ip_header_len, parsed.ip_header_len);
        assert_eq!(reconstructed.ip_total_len, parsed.ip_total_len);
        assert_eq!(reconstructed.tcp_header_len, parsed.tcp_header_len);
        assert_eq!(reconstructed.tcp_payload_offset, parsed.tcp_payload_offset);
        assert_eq!(reconstructed.src_port, parsed.src_port);
        assert_eq!(reconstructed.dst_port, parsed.dst_port);
        assert_eq!(reconstructed.tcp_seq, parsed.tcp_seq);
        assert_eq!(reconstructed.tcp_ack, parsed.tcp_ack);
        assert_eq!(reconstructed.tcp_flags, parsed.tcp_flags);
        assert_eq!(reconstructed.payload, parsed.payload);
    }
}
