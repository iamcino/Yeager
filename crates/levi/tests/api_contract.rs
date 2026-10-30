use common::{Config, Scope};
use std::time::Instant;

#[test]
fn test_tls_sni_parsing() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x03, 0x03]);
    pkt.extend_from_slice(&[0xAA; 32]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x02, 0xC0, 0x2F]);
    pkt.extend_from_slice(&[0x01, 0x00]);

    let ext_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);

    let host = b"example.com";
    pkt.extend_from_slice(&[0x00, 0x00]);
    let ext_data_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);
    let sni_data_start = pkt.len();
    pkt.extend_from_slice(&[0x00, (host.len() + 3) as u8]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, host.len() as u8]);
    let host_offset = pkt.len();
    pkt.extend_from_slice(host);

    let sni_data_len = (pkt.len() - sni_data_start) as u16;
    pkt[ext_data_len_offset..ext_data_len_offset + 2].copy_from_slice(&sni_data_len.to_be_bytes());
    let total_ext_len = (pkt.len() - (ext_len_offset + 2)) as u16;
    pkt[ext_len_offset..ext_len_offset + 2].copy_from_slice(&total_ext_len.to_be_bytes());

    let total_handshake_len = (pkt.len() - 9) as u32;
    let hs_len_bytes = total_handshake_len.to_be_bytes();
    pkt[6..9].copy_from_slice(&hs_len_bytes[1..4]);

    let total_record_len = (pkt.len() - 5) as u16;
    pkt[3..5].copy_from_slice(&total_record_len.to_be_bytes());

    assert!(levi::tls::is_client_hello(&pkt));
    let info = levi::tls::parse_client_hello(&pkt).expect("Should parse ClientHello");
    assert_eq!(info.sni, Some("example.com"));
    assert_eq!(info.sni_offset, Some(host_offset));
}

#[test]
fn test_stop_when_not_started() {
    // Calling stop when not started must be safe and never hang or panic
    levi::stop();
    assert!(!levi::is_running());
}

#[test]
fn test_api_contract_lifecycle() {
    let mut cfg = Config::default();
    cfg.scope = Scope::All;

    // Test stop when not running
    levi::stop();
    assert!(!levi::is_running(), "is_running() should be false initially");

    // If running with Admin, test start/stop lifecycle
    let start_res = levi::start(&cfg);
    if start_res.is_ok() {
        assert!(levi::is_running(), "is_running() should be true after successful start");

        // Consecutive start must not crash or hang (it cleanly restarts)
        let second_start = levi::start(&cfg);
        assert!(second_start.is_ok(), "Consecutive start should succeed cleanly");
        assert!(levi::is_running());

        // Stop timing test (< 2 seconds)
        let t0 = Instant::now();
        levi::stop();
        let elapsed = t0.elapsed();
        assert!(!levi::is_running(), "is_running() should be false after stop");
        assert!(elapsed.as_secs() < 2, "stop() took {:?}, expected < 2s", elapsed);

        // Restart after stop
        let restart_res = levi::start(&cfg);
        assert!(restart_res.is_ok(), "Restart after stop should succeed");
        assert!(levi::is_running());

        // Test scope change restart
        cfg.scope = Scope::HostList;
        cfg.hosts = vec!["example.com".into(), "discord.com".into()];
        levi::stop();
        assert!(!levi::is_running());

        let scope_restart = levi::start(&cfg);
        assert!(scope_restart.is_ok(), "Restart with new scope should succeed");
        assert!(levi::is_running());

        levi::stop();
        assert!(!levi::is_running());
    } else {
        let err_msg = start_res.err().unwrap();
        assert!(!err_msg.is_empty(), "Error message must be non-empty");
        assert!(!levi::is_running(), "is_running() must be false if start failed");
    }
}

#[test]
fn test_matches_host_zero_alloc() {
    use levi::matches_host;

    // Exact matches
    assert!(matches_host("example.com", "example.com"));
    assert!(matches_host("EXAMPLE.COM", "example.com"));
    assert!(matches_host("example.com", "EXAMPLE.COM"));

    // Subdomains
    assert!(matches_host("sub.example.com", "example.com"));
    assert!(matches_host("a.b.c.example.com", "example.com"));

    // Suffix collisions that must NOT match
    assert!(!matches_host("notexample.com", "example.com"));
    assert!(!matches_host("evil-example.com", "example.com"));
    assert!(!matches_host("myexample.com", "example.com"));

    // Partial domain
    assert!(!matches_host("example.co", "example.com"));
    assert!(!matches_host("example.com.vn", "example.com"));
}

#[test]
fn test_construct_tcp_segment_zero_alloc_ipv4() {
    use levi::engine::ResilienceEngine;
    use levi::packet::ParsedPacket;

    // Construct a minimal valid IPv4 TCP packet
    let mut raw_pkt = vec![0u8; 40 + 50]; // 20B IPv4 + 20B TCP + 50B Payload
    // IPv4 header (20 bytes)
    raw_pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    raw_pkt[2] = 0x00;
    raw_pkt[3] = 90; // Total length = 90
    raw_pkt[8] = 64; // TTL
    raw_pkt[9] = 6; // Protocol = TCP
    raw_pkt[12..16].copy_from_slice(&[192, 168, 1, 100]); // Src IP
    raw_pkt[16..20].copy_from_slice(&[93, 184, 216, 34]); // Dst IP

    // TCP header (20 bytes, offset 20)
    raw_pkt[20] = 0xC0;
    raw_pkt[21] = 0x01; // Src Port: 49153
    raw_pkt[22] = 0x01;
    raw_pkt[23] = 0xBB; // Dst Port: 443
    let base_seq: u32 = 100_000;
    raw_pkt[24..28].copy_from_slice(&base_seq.to_be_bytes()); // Seq
    raw_pkt[28..32].copy_from_slice(&[0, 0, 0, 1]); // Ack
    raw_pkt[32] = 0x50; // Data offset: 5 (20 bytes)
    raw_pkt[33] = 0x18; // Flags: PSH | ACK

    // Payload (50 bytes)
    for i in 0..50 {
        raw_pkt[40 + i] = (i + 1) as u8;
    }

    let parsed = ParsedPacket::parse(&raw_pkt).expect("Should parse IPv4 packet");
    assert_eq!(parsed.ip_version, 4);
    assert_eq!(parsed.payload.len(), 50);

    // Test zero-alloc segment construction on stack buffer
    let mut stack_buf = [0u8; 2048];
    let part_payload = &parsed.payload[10..30]; // 20 bytes payload
    let seq_offset = 10;

    let seg_len = ResilienceEngine::construct_tcp_segment(
        &raw_pkt,
        &parsed,
        seq_offset,
        part_payload,
        &mut stack_buf,
    );

    assert_eq!(seg_len, 40 + 20); // 40 bytes headers + 20 bytes part payload

    // Verify IPv4 total length updated in packet bytes [2..4]
    let seg_ip_len = u16::from_be_bytes([stack_buf[2], stack_buf[3]]) as usize;
    assert_eq!(seg_ip_len, seg_len);

    // Verify Sequence Number updated by seq_offset
    let seg_seq = u32::from_be_bytes([stack_buf[24], stack_buf[25], stack_buf[26], stack_buf[27]]);
    assert_eq!(seg_seq, base_seq + seq_offset);

    // Verify Payload content in segment
    assert_eq!(&stack_buf[40..seg_len], part_payload);

    // Verify Checksums cleared
    assert_eq!(&stack_buf[10..12], &[0, 0]); // IPv4 Checksum cleared
    assert_eq!(&stack_buf[36..38], &[0, 0]); // TCP Checksum cleared
}

#[test]
fn test_construct_tcp_segment_zero_alloc_ipv6() {
    use levi::engine::ResilienceEngine;
    use levi::packet::ParsedPacket;

    // Construct a minimal valid IPv6 TCP packet (40B IPv6 + 20B TCP + 60B Payload)
    let mut raw_pkt = vec![0u8; 40 + 20 + 60];
    // IPv6 header (40 bytes)
    raw_pkt[0] = 0x60; // Version 6
    let payload_len: u16 = 20 + 60; // TCP header (20) + Payload (60)
    raw_pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
    raw_pkt[6] = 6; // Next header = TCP
    raw_pkt[7] = 64; // Hop limit

    // IPv6 Src: 2001:db8::1, Dst: 2001:db8::2
    raw_pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    raw_pkt[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    // TCP header (20 bytes, offset 40)
    raw_pkt[40] = 0xC0; raw_pkt[41] = 0x01; // Src Port: 49153
    raw_pkt[42] = 0x01; raw_pkt[43] = 0xBB; // Dst Port: 443
    let base_seq: u32 = 500_000;
    raw_pkt[44..48].copy_from_slice(&base_seq.to_be_bytes());
    raw_pkt[48..52].copy_from_slice(&[0, 0, 0, 1]); // Ack
    raw_pkt[52] = 0x50; // Data offset: 5 (20 bytes)
    raw_pkt[53] = 0x18; // Flags: PSH | ACK

    // Payload (60 bytes)
    for i in 0..60 {
        raw_pkt[60 + i] = (i + 10) as u8;
    }

    let parsed = ParsedPacket::parse(&raw_pkt).expect("Should parse IPv6 packet");
    assert_eq!(parsed.ip_version, 6);
    assert_eq!(parsed.payload.len(), 60);

    // Segment construction on stack buffer
    let mut stack_buf = [0u8; 2048];
    let part_payload = &parsed.payload[15..45]; // 30 bytes part payload
    let seq_offset = 15;

    let seg_len = ResilienceEngine::construct_tcp_segment(
        &raw_pkt,
        &parsed,
        seq_offset,
        part_payload,
        &mut stack_buf,
    );

    assert_eq!(seg_len, 40 + 20 + 30); // 90 bytes

    // Verify IPv6 payload length (excludes 40-byte IPv6 header)
    let seg_ipv6_payload_len = u16::from_be_bytes([stack_buf[4], stack_buf[5]]) as usize;
    assert_eq!(seg_ipv6_payload_len, 20 + 30);

    // Verify Sequence Number updated
    let seg_seq = u32::from_be_bytes([stack_buf[44], stack_buf[45], stack_buf[46], stack_buf[47]]);
    assert_eq!(seg_seq, base_seq + seq_offset);

    // Verify Payload content in segment
    assert_eq!(&stack_buf[60..seg_len], part_payload);

    // Verify TCP Checksum cleared
    assert_eq!(&stack_buf[56..58], &[0, 0]);
}

#[test]
fn test_inbound_rst_packet_detection() {
    use levi::packet::{ParsedPacket, TCP_FLAG_RST, TCP_FLAG_ACK};

    // Construct a minimal 40-byte IPv4 TCP RST packet (no payload)
    let mut raw_pkt = vec![0u8; 40];
    raw_pkt[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
    raw_pkt[2] = 0x00; raw_pkt[3] = 40; // Total length = 40
    raw_pkt[8] = 64; // TTL
    raw_pkt[9] = 6;  // Protocol = TCP
    raw_pkt[12..16].copy_from_slice(&[93, 184, 216, 34]); // Src IP (Remote Server)
    raw_pkt[16..20].copy_from_slice(&[192, 168, 1, 100]); // Dst IP (Local Client)

    // TCP Header (20 bytes, offset 20)
    raw_pkt[20] = 0x01; raw_pkt[21] = 0xBB; // Src Port: 443
    raw_pkt[22] = 0xC0; raw_pkt[23] = 0x01; // Dst Port: 49153
    raw_pkt[24..28].copy_from_slice(&[0, 1, 2, 3]); // Seq
    raw_pkt[28..32].copy_from_slice(&[0, 0, 0, 0]); // Ack
    raw_pkt[32] = 0x50; // Data offset: 5 (20 bytes)
    raw_pkt[33] = TCP_FLAG_RST | TCP_FLAG_ACK; // Flags: RST | ACK

    let parsed = ParsedPacket::parse(&raw_pkt).expect("Should parse inbound RST packet");
    assert_eq!(parsed.ip_version, 4);
    assert_eq!(parsed.payload.len(), 0); // RST packet has 0 payload
    assert!((parsed.tcp_flags & TCP_FLAG_RST) != 0, "Must detect TCP RST flag");
}
