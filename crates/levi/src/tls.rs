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
