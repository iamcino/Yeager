//! Native TLS fragmentation & handshake stabilization engine.
//! Segments ClientHello packets at calibrated boundaries to ensure transport resilience against middlebox interference.

use crate::packet::ParsedPacket;
use crate::raw::{SafeHandle, WinDivertAddress, WinDivertApi};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResilienceMode {
    /// Split ClientHello payload into two segments at split position.
    Split,
    /// Send Segment 2 before Segment 1 (Out-of-order).
    Disorder,
    /// Multi-split into 3 out-of-order segments with a micro-delay.
    MultiSplit,
}


pub struct ResilienceEngine;

impl ResilienceEngine {
    /// Splits an outbound TLS ClientHello packet into 3 out-of-order segments
    /// with micro-wait timing to protect connection integrity against middlebox stream disruptions.
    pub fn fragment_and_send_multisplit(
        api: &WinDivertApi,
        handle: SafeHandle,
        packet_buf: &[u8],
        parsed: &ParsedPacket,
        sni_split: Option<usize>,
        addr: &mut WinDivertAddress,
    ) -> Result<(), String> {
        let payload = parsed.payload;
        if payload.len() < 10 {
            return Self::send_raw(api, handle, packet_buf, addr);
        }

        // Configure WinDivert 2.2 Address flags correctly for outbound & IP version
        addr.set_outbound(true);
        addr.set_ipv6(parsed.ip_version == 6);
        addr.set_impostor(true);

        // Cut points:
        // split1 = 2: Splits right in the TLS Record header ([0x16, 0x03])
        // split2: Splits right into the midpoint of the domain name to preserve transport stream stability
        let split1 = 2;
        let split2 = if let Some(cut) = sni_split {
            if cut > split1 && cut < payload.len() {
                cut
            } else {
                payload.len() / 2
            }
        } else {
            payload.len() / 2
        };

        if split2 <= split1 || split2 >= payload.len() {
            return Self::fragment_and_send(api, handle, packet_buf, parsed, split1, addr, true);
        }

        let part1 = &payload[..split1];
        let part2 = &payload[split1..split2];
        let part3 = &payload[split2..];

        // Transmission order: Segment 3 -> [Hybrid-wait 3.3-3.5ms] -> Segment 2 -> [Hybrid-wait 3.3-3.5ms] -> Segment 1
        // 1. Send Segment 3 (tail of ClientHello: second half of SNI + extensions)
        Self::send_tcp_segment(api, handle, packet_buf, parsed, split2 as u32, part3, addr)?;

        // High-precision hybrid micro-wait calibrated to sweet spot [3300us .. 3500us]
        // Combines thread sleep (saves CPU energy/battery) and cycle spin-loop (sub-microsecond precision)
        Self::hybrid_wait_jitter(3300, 200);

        // 2. Send Segment 2 (middle: Handshake header up to midpoint of SNI)
        Self::send_tcp_segment(api, handle, packet_buf, parsed, split1 as u32, part2, addr)?;

        // High-precision hybrid micro-wait calibrated to sweet spot [3300us .. 3500us]
        Self::hybrid_wait_jitter(3300, 200);

        // 3. Send Segment 1 (head: TLS Record Header 0x16 0x03)
        Self::send_tcp_segment(api, handle, packet_buf, parsed, 0, part1, addr)?;

        Ok(())
    }

    /// Splits an outbound TLS ClientHello packet into 3 IN-ORDER segments
    /// (Segment 1 [Header] -> Segment 2 [SNI front] -> Segment 3 [SNI tail + extensions])
    /// with zero wait delay for maximum throughput and seamless VPN/tunnel encapsulation.
    pub fn fragment_and_send_multisplit_inorder(
        api: &WinDivertApi,
        handle: SafeHandle,
        packet_buf: &[u8],
        parsed: &ParsedPacket,
        sni_split: Option<usize>,
        addr: &mut WinDivertAddress,
    ) -> Result<(), String> {
        let payload = parsed.payload;
        if payload.len() < 10 {
            return Self::send_raw(api, handle, packet_buf, addr);
        }

        // Configure WinDivert 2.2 Address flags correctly for outbound & IP version
        addr.set_outbound(true);
        addr.set_ipv6(parsed.ip_version == 6);
        addr.set_impostor(true);

        // Cut points:
        // split1 = 2: Splits right in the TLS Record header ([0x16, 0x03])
        // split2: Splits right into the midpoint of the domain name to preserve transport stream stability
        let split1 = 2;
        let split2 = if let Some(cut) = sni_split {
            if cut > split1 && cut < payload.len() {
                cut
            } else {
                payload.len() / 2
            }
        } else {
            payload.len() / 2
        };

        if split2 <= split1 || split2 >= payload.len() {
            return Self::fragment_and_send(api, handle, packet_buf, parsed, split1, addr, false);
        }

        let part1 = &payload[..split1];
        let part2 = &payload[split1..split2];
        let part3 = &payload[split2..];

        // Transmission order: In-Order Segment 1 -> Segment 2 -> Segment 3 (0ms delay)
        Self::send_tcp_segment(api, handle, packet_buf, parsed, 0, part1, addr)?;
        Self::send_tcp_segment(api, handle, packet_buf, parsed, split1 as u32, part2, addr)?;
        Self::send_tcp_segment(api, handle, packet_buf, parsed, split2 as u32, part3, addr)?;

        Ok(())
    }

    /// Hybrid micro-second wait combining thread sleep (for CPU power saving) and spin-loop (for sub-millisecond precision).
    #[inline]
    fn hybrid_wait_jitter(base_micros: u64, max_jitter_micros: u64) {
        let jitter = if max_jitter_micros > 0 {
            let nanos = std::time::Instant::now().elapsed().subsec_nanos() as u64;
            nanos % (max_jitter_micros + 1)
        } else {
            0
        };
        let total_micros = base_micros + jitter;

        let start = std::time::Instant::now();
        let target = std::time::Duration::from_micros(total_micros);

        // For waits >= 2000us (2ms), sleep for (total - 800us) to relieve CPU pressure,
        // then spend the remaining ~800us in spin-loop for exact sub-microsecond arrival.
        if total_micros >= 2000 {
            let sleep_millis = (total_micros - 800) / 1000;
            if sleep_millis > 0 {
                std::thread::sleep(std::time::Duration::from_millis(sleep_millis));
            }
        }

        while start.elapsed() < target {
            std::hint::spin_loop();
        }
    }

    /// High-precision micro-second wait using CPU cycle spin-loop.
    /// Avoids Windows OS thread scheduler quantum rounding (15.6ms),
    /// keeping delay precisely bounded to protect stream stability without head-of-line blocking.
    #[allow(dead_code)]
    #[inline]
    fn micro_wait(micros: u64) {
        let start = std::time::Instant::now();
        let target = std::time::Duration::from_micros(micros);
        while start.elapsed() < target {
            std::hint::spin_loop();
        }
    }

    /// Constructs a TCP segment directly into the provided output buffer with zero heap allocation.
    /// Returns the total packet length written.
    pub fn construct_tcp_segment(
        packet_buf: &[u8],
        parsed: &ParsedPacket,
        seq_offset: u32,
        part_payload: &[u8],
        out_buf: &mut [u8],
    ) -> usize {
        let ip_hdr_len = parsed.ip_header_len;
        let orig_headers_len = ip_hdr_len + parsed.tcp_header_len;
        let total_len = orig_headers_len + part_payload.len();
        assert!(out_buf.len() >= total_len, "Destination buffer too small for segment");

        // Copy original IP & TCP headers
        out_buf[..orig_headers_len].copy_from_slice(&packet_buf[..orig_headers_len]);
        // Copy segment payload
        out_buf[orig_headers_len..total_len].copy_from_slice(part_payload);

        // Update Sequence Number: seq = base_seq + seq_offset
        if seq_offset > 0 {
            let seq = parsed.tcp_seq.wrapping_add(seq_offset);
            let seq_bytes = seq.to_be_bytes();
            let tcp_seq_offset = ip_hdr_len + 4;
            out_buf[tcp_seq_offset..tcp_seq_offset + 4].copy_from_slice(&seq_bytes);
        }

        // Update IP Length & recalculate checksums
        Self::update_ip_length(&mut out_buf[..total_len], parsed.ip_version, total_len);
        Self::clear_checksums(&mut out_buf[..total_len], parsed.ip_version, ip_hdr_len);

        total_len
    }

    /// Constructs and transmits a single TCP segment using a stack buffer (zero heap allocation for <= 2048 bytes).
    fn send_tcp_segment(
        api: &WinDivertApi,
        handle: SafeHandle,
        packet_buf: &[u8],
        parsed: &ParsedPacket,
        seq_offset: u32,
        part_payload: &[u8],
        addr: &mut WinDivertAddress,
    ) -> Result<(), String> {
        let ip_hdr_len = parsed.ip_header_len;
        let orig_headers_len = ip_hdr_len + parsed.tcp_header_len;
        let total_len = orig_headers_len + part_payload.len();

        let mut stack_buf = [0u8; 2048];
        let mut heap_buf;
        let pkt: &mut [u8] = if total_len <= stack_buf.len() {
            &mut stack_buf[..total_len]
        } else {
            heap_buf = vec![0u8; total_len];
            &mut heap_buf[..]
        };

        Self::construct_tcp_segment(packet_buf, parsed, seq_offset, part_payload, pkt);

        unsafe {
            (api.calc_checksums)(pkt.as_mut_ptr(), pkt.len() as u32, addr as *mut _, 0);
        }

        Self::send_raw(api, handle, pkt, addr)
    }

    /// Helper to construct a single TCP segment with updated sequence and recalculated checksums.
    pub fn build_tcp_segment(
        packet_buf: &[u8],
        parsed: &ParsedPacket,
        seq_offset: u32,
        part_payload: &[u8],
        addr: &mut WinDivertAddress,
        api: &WinDivertApi,
    ) -> Vec<u8> {
        let ip_hdr_len = parsed.ip_header_len;
        let orig_headers_len = ip_hdr_len + parsed.tcp_header_len;
        let total_len = orig_headers_len + part_payload.len();

        let mut pkt = vec![0u8; total_len];
        Self::construct_tcp_segment(packet_buf, parsed, seq_offset, part_payload, &mut pkt);
        unsafe {
            (api.calc_checksums)(pkt.as_mut_ptr(), pkt.len() as u32, addr as *mut _, 0);
        }

        pkt
    }

    /// Splits an outbound TLS ClientHello packet into 2 segments for transport stabilization.
    pub fn fragment_and_send(
        api: &WinDivertApi,
        handle: SafeHandle,
        packet_buf: &[u8],
        parsed: &ParsedPacket,
        split_pos: usize,
        addr: &mut WinDivertAddress,
        use_disorder: bool,
    ) -> Result<(), String> {
        let payload = parsed.payload;
        if payload.len() <= split_pos || split_pos == 0 {
            return Self::send_raw(api, handle, packet_buf, addr);
        }

        // Configure WinDivert 2.2 Address flags correctly for outbound & IP version
        addr.set_outbound(true);
        addr.set_ipv6(parsed.ip_version == 6);
        addr.set_impostor(true);

        let part1 = &payload[..split_pos];
        let part2 = &payload[split_pos..];

        // Send segments in the chosen order (Disorder or Normal)
        if use_disorder {
            // Out-of-order: Send Segment 2 first, then Segment 1
            Self::send_tcp_segment(api, handle, packet_buf, parsed, split_pos as u32, part2, addr)?;
            Self::hybrid_wait_jitter(3300, 200);
            Self::send_tcp_segment(api, handle, packet_buf, parsed, 0, part1, addr)?;
        } else {
            // Normal order: Send Segment 1, then Segment 2
            Self::send_tcp_segment(api, handle, packet_buf, parsed, 0, part1, addr)?;
            Self::send_tcp_segment(api, handle, packet_buf, parsed, split_pos as u32, part2, addr)?;
        }

        Ok(())
    }

    fn update_ip_length(pkt: &mut [u8], ip_ver: u8, total_len: usize) {
        if ip_ver == 4 {
            let len_bytes = (total_len as u16).to_be_bytes();
            pkt[2] = len_bytes[0];
            pkt[3] = len_bytes[1];
        } else if ip_ver == 6 {
            // IPv6 payload length excludes the 40-byte IPv6 header
            let payload_len = total_len.saturating_sub(40) as u16;
            let len_bytes = payload_len.to_be_bytes();
            pkt[4] = len_bytes[0];
            pkt[5] = len_bytes[1];
        }
    }

    fn clear_checksums(pkt: &mut [u8], ip_ver: u8, ip_hdr_len: usize) {
        if ip_ver == 4 && pkt.len() >= 12 {
            // Clear IPv4 Header Checksum
            pkt[10] = 0;
            pkt[11] = 0;
        }
        if pkt.len() >= ip_hdr_len + 18 {
            // Clear TCP Checksum (offset 16..18 of TCP header)
            pkt[ip_hdr_len + 16] = 0;
            pkt[ip_hdr_len + 17] = 0;
        }
    }

    pub fn send_raw(
        api: &WinDivertApi,
        handle: SafeHandle,
        packet_buf: &[u8],
        addr: &WinDivertAddress,
    ) -> Result<(), String> {
        let mut send_addr = *addr;
        send_addr.set_impostor(true);

        let mut sent_len: u32 = 0;
        let res = unsafe {
            (api.send)(
                handle.as_raw(),
                packet_buf.as_ptr(),
                packet_buf.len() as u32,
                &mut sent_len as *mut _,
                &send_addr as *const _,
            )
        };
        if res == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            Err(format!("WinDivertSend failed with code {}", err))
        } else {
            Ok(())
        }
    }
}
