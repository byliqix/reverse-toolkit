pub fn apply(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect()
}

pub fn parse_key(s: &str, is_hex: bool) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() { return None; }
    if is_hex {
        let s = s.replace(' ', "").replace("0x", "").replace("0X", "");
        if s.len() % 2 != 0 { return None; }
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
            .collect()
    } else {
        Some(s.as_bytes().to_vec())
    }
}

pub fn format_hex_dump(data: &[u8], limit: usize) -> String {
    let data = if data.len() > limit { &data[..limit] } else { data };
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        use std::fmt::Write;
        write!(out, "{:08X}  ", i * 16).ok();
        for (j, b) in chunk.iter().enumerate() {
            write!(out, "{:02X} ", b).ok();
            if j == 7 { write!(out, " ").ok(); }
        }
        let mut pad = (16 - chunk.len()) * 3;
        if chunk.len() <= 8 { pad += 1; }
        for _ in 0..pad { out.push(' '); }
        out.push(' ');
        for b in chunk {
            if b.is_ascii_graphic() || *b == b' ' { out.push(*b as char); }
            else { out.push('.'); }
        }
        out.push('\n');
    }
    out
}
