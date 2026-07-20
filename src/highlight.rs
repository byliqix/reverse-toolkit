use fltk::enums::{Color, Font};
use fltk::text::StyleTableEntry;

pub fn disasm_style_table() -> Vec<StyleTableEntry> {
    vec![
        StyleTableEntry { color: Color::from_hex(0xDCDCAA), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0x808080), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0x569CD6), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0xD4D4D4), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0x6A9955), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0x6080B0), font: Font::Courier, size: 12 },
    ]
}

pub fn hex_style_table() -> Vec<StyleTableEntry> {
    vec![
        StyleTableEntry { color: Color::from_hex(0xDCDCAA), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0xD4D4D4), font: Font::Courier, size: 12 },
        StyleTableEntry { color: Color::from_hex(0x6A9955), font: Font::Courier, size: 12 },
    ]
}

pub fn style_disasm(text: &str) -> Vec<u8> {
    let mut styles = Vec::with_capacity(text.len());
    for line in text.lines() {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() && b[i] != b':' && b[i] != b' ' { i += 1; }
        if i < b.len() && b[i] == b':' { i += 1; }
        styles.extend(std::iter::repeat(0u8).take(i.min(b.len())));
        if i >= b.len() { styles.push(3); continue; }
        while i < b.len() && b[i] == b' ' { styles.push(3); i += 1; }
        let byte_start = i;
        let mut has_space = false;
        while i < b.len() && !b[i..].starts_with(b"  ") && b[i] != b';' {
            if b[i] == b' ' { has_space = true; }
            i += 1;
        }
        if has_space {
            for j in byte_start..i.min(b.len()) {
                styles.push(if b[j] == b' ' { 3 } else { 5 });
            }
        }
        if i >= b.len() { continue; }
        while i < b.len() && b[i] == b' ' { styles.push(3); i += 1; }
        while i < b.len() && b[i] != b';' { styles.push(2); i += 1; }
        while i < b.len() { styles.push(4); i += 1; }
    }
    while styles.len() < text.len() { styles.push(3); }
    styles.truncate(text.len());
    styles
}

pub fn style_hex(text: &str) -> Vec<u8> {
    let mut styles = Vec::with_capacity(text.len());
    for line in text.lines() {
        let b = line.as_bytes();
        for (j, &ch) in b.iter().enumerate() {
            if j < 9 { styles.push(0); }
            else if ch.is_ascii_graphic() || ch == b'.' {
                let prev = if j > 0 { b[j-1] } else { 0 };
                if prev == b' ' && (j < 3 || b[j-3] == b' ') { styles.push(2); }
                else { styles.push(1); }
            } else { styles.push(1); }
        }
        styles.push(1);
    }
    while styles.len() < text.len() { styles.push(1); }
    styles.truncate(text.len());
    styles
}
