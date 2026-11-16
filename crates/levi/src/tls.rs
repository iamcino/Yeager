//! Zero-allocation TLS ClientHello inspector & SNI extractor.

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

pub struct ClientHelloInfo<'a> {
    pub sni: Option<&'a str>,
    pub sni_offset: Option<usize>,
}

pub fn is_client_hello(payload: &[u8]) -> bool {
    if payload.len() < 9 {
        return false;
    }
    // Record layer: Type 0x16 (Handshake), Version 0x03, 0x01..0x03
    if payload[0] != TLS_RECORD_HANDSHAKE || payload[1] != 0x03 {
        return false;
    }
    // Handshake layer: Type 0x01 (ClientHello)
    payload[5] == TLS_HANDSHAKE_CLIENT_HELLO
}

/// Parses SNI from TLS ClientHello payload if present.
pub fn parse_client_hello(payload: &[u8]) -> Option<ClientHelloInfo<'_>> {
    if !is_client_hello(payload) {
        return None;
    }

    // Skip Record Header (5 bytes) + Handshake Header (4 bytes) + Version (2 bytes) + Random (32 bytes) = 43 bytes
    let mut cursor = 43;
    if payload.len() < cursor + 1 {
        return None;
    }

    // Session ID length
    let session_id_len = payload[cursor] as usize;
    cursor += 1 + session_id_len;
    if payload.len() < cursor + 2 {
        return None;
    }

    // Cipher Suites length
    let cipher_suites_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
    cursor += 2 + cipher_suites_len;
    if payload.len() < cursor + 1 {
        return None;
    }

    // Compression Methods length
    let comp_len = payload[cursor] as usize;
    cursor += 1 + comp_len;
    if payload.len() < cursor + 2 {
        return None;
    }

    // Extensions length
    let extensions_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
    cursor += 2;

    let extensions_end = std::cmp::min(cursor + extensions_len, payload.len());

    // Iterate extensions to find Server Name Indication (0x0000)
    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
        let ext_len = u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
        cursor += 4;

        if ext_type == 0x0000 {
            // SNI extension
            // Server Name list length (2 bytes)
            if cursor + 2 <= extensions_end {
                let mut sni_cursor = cursor + 2;
                if sni_cursor + 3 <= extensions_end {
                    let name_type = payload[sni_cursor];
                    let name_len = u16::from_be_bytes([payload[sni_cursor + 1], payload[sni_cursor + 2]]) as usize;
                    sni_cursor += 3;
                    if name_type == 0 && sni_cursor + name_len <= extensions_end {
                        let name_bytes = &payload[sni_cursor..sni_cursor + name_len];
                        let sni_str = std::str::from_utf8(name_bytes).ok();
                        return Some(ClientHelloInfo {
                            sni: sni_str,
                            sni_offset: Some(sni_cursor),
                        });
                    }
                }
            }
        }

        cursor += ext_len;
    }

    Some(ClientHelloInfo {
        sni: None,
        sni_offset: None,
    })
}

/// Rebuilds a single-record TLS ClientHello into two valid TLS Handshake records
/// while preserving the exact total TCP payload length (`out_buf[..payload.len()]`).
///
/// This is possible without introducing a TCP sequence-number delta whenever the
/// ClientHello carries a TLS Padding extension (`0x0015`) of at least 5 bytes,
/// freeing the exact 5 bytes required for the second TLS record header.
///
/// Returns `Some(record2_offset)` on success, or `None` if the ClientHello is not
/// a single complete record, lacks >= 5 bytes of padding, or exceeds `out_buf`.
pub fn try_build_zero_delta_record_split(payload: &[u8], out_buf: &mut [u8]) -> Option<usize> {
    if !is_client_hello(payload) || payload.len() < 48 || out_buf.len() < payload.len() {
        return None;
    }

    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if 5 + rec_len != payload.len() || rec_len < 43 {
        return None;
    }

    let hs_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);
    if 4 + hs_len != rec_len || hs_len < 5 {
        return None;
    }

    let mut cursor = 43;
    if payload.len() < cursor + 1 {
        return None;
    }
    let session_id_len = payload[cursor] as usize;
    cursor += 1 + session_id_len;
    if payload.len() < cursor + 2 {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
    cursor += 2 + cipher_suites_len;
    if payload.len() < cursor + 1 {
        return None;
    }

    let comp_len = payload[cursor] as usize;
    cursor += 1 + comp_len;
    if payload.len() < cursor + 2 {
        return None;
    }

    let extensions_len_off = cursor;
    let extensions_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
    cursor += 2;
    if cursor + extensions_len != payload.len() || extensions_len < 5 {
        return None;
    }

    let mut sni_split_in_payload: Option<usize> = None;
    let mut pad_ext: Option<(usize, usize)> = None;

    while cursor + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
        let ext_len = u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
        let ext_data_off = cursor + 4;
        if ext_data_off + ext_len > payload.len() {
            return None;
        }

        if ext_type == 0x0000 && ext_len >= 5 {
            let name_len =
                u16::from_be_bytes([payload[ext_data_off + 3], payload[ext_data_off + 4]]) as usize;
            let name_start = ext_data_off + 5;
            if name_start + name_len <= ext_data_off + ext_len && name_len > 0 {
                sni_split_in_payload = Some(name_start + (name_len / 2).max(1));
            }
        } else if ext_type == 0x0015 && ext_len >= 5 && pad_ext.is_none() {
            pad_ext = Some((cursor, ext_len));
        }

        cursor = ext_data_off + ext_len;
    }

    if cursor != payload.len() {
        return None;
    }

    let (pad_off, pad_len) = pad_ext?;
    let new_hs_total = rec_len - 5;
    if new_hs_total < 2 || new_hs_total > u16::MAX as usize {
        return None;
    }

    // Build the shrunk Handshake message directly on stack (no heap allocation).
    if new_hs_total > 2048 {
        return None;
    }
    let mut hs_buf = [0u8; 2048];
    let prefix_end = pad_off + 4;
    let prefix_len = prefix_end - 5;
    hs_buf[..prefix_len].copy_from_slice(&payload[5..prefix_end]);
    let suffix_start = prefix_end + 5;
    let suffix_len = payload.len() - suffix_start;
    hs_buf[prefix_len..prefix_len + suffix_len].copy_from_slice(&payload[suffix_start..]);

    // Update Handshake length (-5)
    let new_hs_len = hs_len - 5;
    hs_buf[1] = ((new_hs_len >> 16) & 0xff) as u8;
    hs_buf[2] = ((new_hs_len >> 8) & 0xff) as u8;
    hs_buf[3] = (new_hs_len & 0xff) as u8;

    // Update Extensions total length (-5)
    let new_ext_len = (extensions_len - 5) as u16;
    let ext_len_hs_off = extensions_len_off - 5;
    hs_buf[ext_len_hs_off..ext_len_hs_off + 2].copy_from_slice(&new_ext_len.to_be_bytes());

    // Update Padding extension length (-5)
    let new_pad_len = (pad_len - 5) as u16;
    let pad_len_hs_off = (pad_off + 2) - 5;
    hs_buf[pad_len_hs_off..pad_len_hs_off + 2].copy_from_slice(&new_pad_len.to_be_bytes());

    // Determine split point inside the shrunk Handshake message.
    let mut split_in_hs = match sni_split_in_payload {
        Some(off) if off > pad_off + 4 => off.saturating_sub(10),
        Some(off) => off.saturating_sub(5),
        None => new_hs_total / 2,
    };
    if split_in_hs == 0 || split_in_hs >= new_hs_total {
        split_in_hs = new_hs_total / 2;
    }

    let rec1_len = split_in_hs as u16;
    let rec2_len = (new_hs_total - split_in_hs) as u16;

    // Record 1
    out_buf[0] = TLS_RECORD_HANDSHAKE;
    out_buf[1] = payload[1];
    out_buf[2] = payload[2];
    out_buf[3..5].copy_from_slice(&rec1_len.to_be_bytes());
    out_buf[5..5 + split_in_hs].copy_from_slice(&hs_buf[..split_in_hs]);

    // Record 2
    let rec2_off = 5 + split_in_hs;
    out_buf[rec2_off] = TLS_RECORD_HANDSHAKE;
    out_buf[rec2_off + 1] = payload[1];
    out_buf[rec2_off + 2] = payload[2];
    out_buf[rec2_off + 3..rec2_off + 5].copy_from_slice(&rec2_len.to_be_bytes());
    out_buf[rec2_off + 5..payload.len()].copy_from_slice(&hs_buf[split_in_hs..new_hs_total]);

    Some(rec2_off)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_client_hello(sni: &str, padding_len: Option<usize>) -> Vec<u8> {
        let mut exts = Vec::new();
        // SNI extension (0x0000)
        let sni_bytes = sni.as_bytes();
        let list_len = (3 + sni_bytes.len()) as u16;
        let ext_len = (2 + list_len) as u16;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);

        if let Some(plen) = padding_len {
            exts.extend_from_slice(&0x0015u16.to_be_bytes());
            exts.extend_from_slice(&(plen as u16).to_be_bytes());
            exts.resize(exts.len() + plen, 0u8);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // ClientVersion TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // Random
        body.push(0x00); // SessionID len
        body.extend_from_slice(&2u16.to_be_bytes()); // CipherSuites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // Compression methods len
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let hs_len = body.len();
        let mut hs = Vec::new();
        hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(TLS_RECORD_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn zero_delta_record_split_preserves_length_and_reassembles_valid_hello() {
        let pkt = build_sample_client_hello("app.example.com", Some(64));
        let mut out = vec![0u8; pkt.len()];
        let rec2_off = try_build_zero_delta_record_split(&pkt, &mut out)
            .expect("padded ClientHello must split into two TLS records");

        // Record 1 header
        assert_eq!(out[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(&out[1..3], &[0x03, 0x01]);
        let r1_len = u16::from_be_bytes([out[3], out[4]]) as usize;
        assert_eq!(5 + r1_len, rec2_off);

        // Record 2 header
        assert_eq!(out[rec2_off], TLS_RECORD_HANDSHAKE);
        assert_eq!(&out[rec2_off + 1..rec2_off + 3], &[0x03, 0x01]);
        let r2_len = u16::from_be_bytes([out[rec2_off + 3], out[rec2_off + 4]]) as usize;
        assert_eq!(rec2_off + 5 + r2_len, pkt.len());

        // Reassemble Handshake stream from both records and verify parse_client_hello succeeds
        let mut reassembled = Vec::new();
        reassembled.push(TLS_RECORD_HANDSHAKE);
        reassembled.extend_from_slice(&[0x03, 0x01]);
        reassembled.extend_from_slice(&((r1_len + r2_len) as u16).to_be_bytes());
        reassembled.extend_from_slice(&out[5..rec2_off]);
        reassembled.extend_from_slice(&out[rec2_off + 5..]);

        let info = parse_client_hello(&reassembled).expect("reassembled hello must parse");
        assert_eq!(info.sni, Some("app.example.com"));
        // Record 1 must NOT contain the full SNI string
        assert!(
            !out[5..rec2_off].windows("app.example.com".len()).any(|w| w == b"app.example.com"),
            "Record 1 must split before the end of SNI"
        );
    }

    #[test]
    fn zero_delta_record_split_returns_none_without_sufficient_padding() {
        let no_pad = build_sample_client_hello("app.example.com", None);
        let mut out = vec![0u8; no_pad.len()];
        assert_eq!(try_build_zero_delta_record_split(&no_pad, &mut out), None);

        let small_pad = build_sample_client_hello("app.example.com", Some(4));
        let mut out2 = vec![0u8; small_pad.len()];
        assert_eq!(try_build_zero_delta_record_split(&small_pad, &mut out2), None);
    }
}
