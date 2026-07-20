mod pe;
mod disasm;
mod hash;
mod xor;

use fltk::{app, prelude::*, window::*, group::*, button::*, input::*, output::*,
           text::*, menu::*, frame::*};
use std::cell::RefCell;
use std::fmt::Write;

thread_local! {
    static STATE: RefCell<AppState> = RefCell::new(AppState::new());
}

struct AppCore {
    file_data: Vec<u8>,
    pe: String,
    hex: String,
    str: String,
    disasm: String,
    md5: String,
    sha1: String,
    sha256: String,
    xor_hex: String,
}

impl AppCore {
    fn new() -> Self {
        Self {
            file_data: vec![],
            pe: String::new(),
            hex: String::new(),
            str: "Open a file with File > Open or Ctrl+O".into(),
            disasm: String::new(),
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            xor_hex: String::new(),
        }
    }
}

struct AppState {
    core: AppCore,
    file_label: String,
}

impl AppState {
    fn new() -> Self { Self { core: AppCore::new(), file_label: "No file loaded".into() } }

    fn load(&mut self, path: &str) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                fltk::dialog::alert_default("Failed to read file!");
                return;
            }
        };
        self.core = AppCore::new();
        self.core.file_data = data;

        let name = std::path::Path::new(path)
            .file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        self.file_label = format!("File: {}  |  Size: {} bytes", name, self.core.file_data.len());

        self.analyze_pe();
        self.to_hex();
        self.to_strings();
        self.to_disasm();
        self.to_hashes();
    }

    fn analyze_pe(&mut self) {
        let info = match pe::parse_pe(self.core.file_data.clone()) {
            Some(i) => i,
            None => { self.core.pe = "Not a valid PE file.".into(); return; }
        };
        let s = &mut self.core.pe;
        writeln!(s, "Machine:           {}", info.machine).ok();
        writeln!(s, "PE Type:           {}", info.pe_type).ok();
        writeln!(s, "Sections:          {}", info.num_sections).ok();
        writeln!(s, "Timestamp:         {}", info.timestamp).ok();
        writeln!(s, "Entry Point:       0x{:08X}", info.entry_point).ok();
        writeln!(s, "Image Base:        0x{:X}", info.image_base).ok();
        writeln!(s, "Size of Image:     0x{:X} bytes", info.size_of_image).ok();
        writeln!(s, "Size of Code:      0x{:X} bytes", info.size_of_code).ok();
        writeln!(s, "Subsystem:         {}", info.subsystem).ok();
        writeln!(s, "Characteristics:   {}", info.characteristics).ok();
        writeln!(s, "\n── Sections ({}) ──", info.sections.len()).ok();
        for sec in &info.sections {
            let f = pe::section_chars_desc(sec.characteristics).join("|");
            writeln!(s, "  {:<8}  vsize=0x{:X}  vaddr=0x{:08X}  rsize=0x{:X}  raddr=0x{:08X}  {}",
                sec.name, sec.virtual_size, sec.virtual_address, sec.raw_size, sec.raw_address, f).ok();
        }
        let imports = pe::parse_imports(&info);
        writeln!(s, "\n── Imports ({}) ──", imports.len()).ok();
        for imp in imports.iter().take(100) {
            writeln!(s, "  {}!{}", imp.dll, imp.name).ok();
        }
        let exports = pe::parse_exports(&info);
        writeln!(s, "\n── Exports ({}) ──", exports.len()).ok();
        for exp in exports.iter().take(100) {
            writeln!(s, "  {} @ {}", exp.name, exp.address).ok();
        }
    }

    fn to_hex(&mut self) {
        if self.core.file_data.is_empty() { return; }
        for (i, chunk) in self.core.file_data.chunks(16).enumerate() {
            write!(self.core.hex, "{:08X}  ", i * 16).ok();
            for (j, b) in chunk.iter().enumerate() {
                write!(self.core.hex, "{:02X} ", b).ok();
                if j == 7 { write!(self.core.hex, " ").ok(); }
            }
            let mut pad = (16 - chunk.len()) * 3;
            if chunk.len() <= 8 { pad += 1; }
            for _ in 0..pad { self.core.hex.push(' '); }
            self.core.hex.push(' ');
            for b in chunk {
                if b.is_ascii_graphic() || *b == b' ' { self.core.hex.push(*b as char); }
                else { self.core.hex.push('.'); }
            }
            self.core.hex.push('\n');
        }
    }

    fn to_strings(&mut self) {
        if self.core.file_data.is_empty() { return; }
        let d = &self.core.file_data;
        let mut i = 0;
        while i < d.len() {
            if d[i].is_ascii_graphic() || d[i] == b' ' {
                let s = i;
                while i < d.len() && (d[i].is_ascii_graphic() || d[i] == b' ') { i += 1; }
                if i - s >= 4 {
                    if let Ok(t) = std::str::from_utf8(&d[s..i]) {
                        writeln!(self.core.str, "[ASCII @ 0x{:08X}]  {}", s, t).ok();
                    }
                }
            } else { i += 1; }
        }
        i = 0;
        while i + 1 < d.len() {
            if d[i].is_ascii_graphic() && d[i + 1] == 0 {
                let s = i;
                let mut c = 0;
                while i + 1 < d.len() && d[i].is_ascii_graphic() && d[i + 1] == 0 { i += 2; c += 1; }
                if c >= 4 {
                    let t: String = (s..i).step_by(2).map(|j| d[j] as char).collect();
                    writeln!(self.core.str, "[UTF16 @ 0x{:08X}]  {}", s, t).ok();
                }
            } else { i += 1; }
        }
        if self.core.str.is_empty() { self.core.str = "No strings found.".into(); }
    }

    fn to_disasm(&mut self) {
        let info = match pe::parse_pe(self.core.file_data.clone()) {
            Some(i) => i,
            None => return,
        };
        for sec in &info.sections {
            if sec.characteristics & 0x20000000 != 0 && !sec.data.is_empty() {
                writeln!(self.core.disasm, "; Section: {} (vaddr=0x{:08X})", sec.name, sec.virtual_address).ok();
                let base = info.image_base + sec.virtual_address as u64;
                for instr in &disasm::disassemble(&sec.data, base, 2000) {
                    let h: String = instr.bytes.iter().map(|b| format!("{:02X} ", b)).collect();
                    writeln!(self.core.disasm, "0x{:016X}:  {:<24}  {}", instr.address, h, instr.mnemonic).ok();
                }
                writeln!(self.core.disasm).ok();
            }
        }
        if self.core.disasm.is_empty() { self.core.disasm = "No executable sections found.".into(); }
    }

    fn to_hashes(&mut self) {
        if self.core.file_data.is_empty() { return; }
        let h = hash::compute_hashes(&self.core.file_data);
        self.core.md5 = h.md5;
        self.core.sha1 = h.sha1;
        self.core.sha256 = h.sha256;
    }

    fn apply_xor(&mut self, key: &[u8]) {
        if self.core.file_data.is_empty() { return; }
        let xored = xor::apply(&self.core.file_data, key);
        let key_repr: String = key.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        self.core.xor_hex = format!("; XOR key: [{}]  ({} bytes)\n; File: {} bytes → {} bytes\n\n{}",
            key_repr, key.len(), self.core.file_data.len(), xored.len(),
            xor::format_hex_dump(&xored, 65536));
        if self.core.file_data.len() > 65536 {
            self.core.xor_hex.push_str(&format!("\n[Showing first 65536 of {} bytes]", self.core.file_data.len()));
        }
    }
}

struct Editors {
    pe: TextBuffer,
    hex: TextBuffer,
    str: TextBuffer,
    disasm: TextBuffer,
    md5: Output,
    sha1: Output,
    sha256: Output,
    xor_hex: TextBuffer,
    status: Frame,
}

impl Editors {
    fn refresh() {
        let (pe, hex, str, disasm, md5, sha1, sha256, xor_hex, label) = STATE.with(|s| {
            let st = s.borrow();
            (
                st.core.pe.clone(), st.core.hex.clone(), st.core.str.clone(),
                st.core.disasm.clone(), st.core.md5.clone(), st.core.sha1.clone(),
                st.core.sha256.clone(), st.core.xor_hex.clone(), st.file_label.clone(),
            )
        });
        EDITORS.with(|e| {
            if let Some(ref mut ed) = *e.borrow_mut() {
                ed.pe.set_text(&pe);
                ed.hex.set_text(&hex);
                ed.str.set_text(&str);
                ed.disasm.set_text(&disasm);
                ed.md5.set_value(&md5);
                ed.sha1.set_value(&sha1);
                ed.sha256.set_value(&sha256);
                ed.xor_hex.set_text(&xor_hex);
                ed.status.set_label(&label);
            }
        });
    }
}

thread_local! {
    static EDITORS: RefCell<Option<Editors>> = const { RefCell::new(None) };
}

fn do_open() {
    if let Some(path) = fltk::dialog::file_chooser("Open File", "*", "", true) {
        STATE.with(|s| s.borrow_mut().load(&path));
        Editors::refresh();
    }
}

fn do_rehash() {
    let (md5, sha1, sha256) = STATE.with(|s| {
        let mut st = s.borrow_mut();
        st.to_hashes();
        (st.core.md5.clone(), st.core.sha1.clone(), st.core.sha256.clone())
    });
    EDITORS.with(|e| {
        if let Some(ref mut ed) = *e.borrow_mut() {
            ed.md5.set_value(&md5);
            ed.sha1.set_value(&sha1);
            ed.sha256.set_value(&sha256);
        }
    });
}

fn main() {
    let app = app::App::default().with_scheme(app::Scheme::Plastic);
    app::background(236, 233, 216);
    app::set_background_color(236, 233, 216);

    let mut win = Window::new(100, 100, 1050, 720, "XPTool - Reverse Engineering Tool");
    win.set_frame(fltk::enums::FrameType::BorderBox);
    win.make_resizable(true);

    let mut menu = MenuBar::new(0, 0, 1050, 24, "");
    menu.set_frame(fltk::enums::FrameType::ThinUpBox);
    menu.set_color(fltk::enums::Color::from_hex(0xECE9D8));
    menu.set_label_color(fltk::enums::Color::Black);
    menu.add("&File/Open\t", fltk::enums::Shortcut::Ctrl | 'o', fltk::menu::MenuFlag::Normal, |_| do_open());
    menu.add("&File/Exit\t", fltk::enums::Shortcut::Ctrl | 'q', fltk::menu::MenuFlag::Normal, |_| app::quit());

    let tab_bg = fltk::enums::Color::from_hex(0xECE9D8);

    let mut tabs = Tabs::new(0, 24, 1050, 653, "");
    tabs.set_color(tab_bg);
    tabs.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));

    // PE Tab
    let mut pe_grp = Group::new(2, 48, 1046, 627, "PE Analyzer");
    pe_grp.set_frame(fltk::enums::FrameType::FlatBox);
    pe_grp.set_color(fltk::enums::Color::White);
    let mut pe_buf = TextBuffer::default();
    let mut pe_ed = TextEditor::new(4, 50, 1040, 623, "");
    pe_ed.set_buffer(pe_buf.clone());
    pe_ed.set_text_font(fltk::enums::Font::Courier);
    pe_ed.set_text_size(13);
    pe_ed.set_insert_mode(false);
    pe_ed.set_color(fltk::enums::Color::White);
    pe_ed.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    pe_grp.end();

    // Hex Tab
    let mut hx_grp = Group::new(2, 48, 1046, 627, "Hex Viewer");
    hx_grp.set_frame(fltk::enums::FrameType::FlatBox);
    hx_grp.set_color(fltk::enums::Color::White);
    let hex_buf = TextBuffer::default();
    let mut hx_ed = TextEditor::new(4, 50, 1040, 623, "");
    hx_ed.set_buffer(hex_buf.clone());
    hx_ed.set_text_font(fltk::enums::Font::Courier);
    hx_ed.set_text_size(13);
    hx_ed.set_insert_mode(false);
    hx_ed.set_color(fltk::enums::Color::White);
    hx_ed.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    hx_grp.end();

    // Strings Tab
    let mut st_grp = Group::new(2, 48, 1046, 627, "Strings");
    st_grp.set_frame(fltk::enums::FrameType::FlatBox);
    st_grp.set_color(fltk::enums::Color::White);
    let str_buf = TextBuffer::default();
    let mut st_ed = TextEditor::new(4, 50, 1040, 623, "");
    st_ed.set_buffer(str_buf.clone());
    st_ed.set_text_font(fltk::enums::Font::Courier);
    st_ed.set_text_size(13);
    st_ed.set_insert_mode(false);
    st_ed.set_color(fltk::enums::Color::White);
    st_ed.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    st_grp.end();

    // Disasm Tab
    let mut da_grp = Group::new(2, 48, 1046, 627, "Disassembler");
    da_grp.set_frame(fltk::enums::FrameType::FlatBox);
    da_grp.set_color(fltk::enums::Color::White);
    let disasm_buf = TextBuffer::default();
    let mut da_ed = TextEditor::new(4, 50, 1040, 623, "");
    da_ed.set_buffer(disasm_buf.clone());
    da_ed.set_text_font(fltk::enums::Font::Courier);
    da_ed.set_text_size(13);
    da_ed.set_insert_mode(false);
    da_ed.set_color(fltk::enums::Color::White);
    da_ed.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    da_grp.end();

    // Hash Tab
    let mut ha_grp = Group::new(2, 48, 1046, 627, "Hash Calculator");
    ha_grp.set_frame(fltk::enums::FrameType::FlatBox);
    ha_grp.set_color(fltk::enums::Color::White);
    let mut md5_out = Output::new(100, 70, 420, 26, " MD5:");
    let mut sha1_out = Output::new(100, 100, 420, 26, " SHA1:");
    let mut sha256_out = Output::new(100, 130, 420, 26, " SHA256:");
    md5_out.set_text_font(fltk::enums::Font::Courier);
    md5_out.set_text_size(13);
    sha1_out.set_text_font(fltk::enums::Font::Courier);
    sha1_out.set_text_size(13);
    sha256_out.set_text_font(fltk::enums::Font::Courier);
    sha256_out.set_text_size(13);
    let mut btn = Button::new(540, 70, 150, 26, "Re-calc Hashes");
    btn.set_color(fltk::enums::Color::from_hex(0xECE9D8));
    btn.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    btn.set_callback(|_| do_rehash());
    ha_grp.end();

    // XOR Tab
    let mut xr_grp = Group::new(2, 48, 1046, 627, "XOR Tool");
    xr_grp.set_frame(fltk::enums::FrameType::FlatBox);
    xr_grp.set_color(fltk::enums::Color::White);
    let mut xr_label = Frame::new(10, 56, 60, 22, "Key:");
    xr_label.set_label_size(13);
    let mut xr_input = Input::new(70, 56, 180, 22, "");
    xr_input.set_color(fltk::enums::Color::White);
    xr_input.set_text_size(13);
    let mut xr_hex_rb = RadioRoundButton::new(265, 56, 50, 22, "HEX");
    xr_hex_rb.set_label_size(13);
    let mut xr_asc_rb = RadioRoundButton::new(320, 56, 60, 22, "ASCII");
    xr_asc_rb.set_label_size(13);
    xr_asc_rb.set_value(true);
    let mut xr_btn = Button::new(395, 56, 80, 22, "Apply");
    xr_btn.set_color(fltk::enums::Color::from_hex(0xECE9D8));
    xr_btn.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    let mut xor_buf = TextBuffer::default();
    let mut xr_ed = TextEditor::new(4, 84, 1040, 589, "");
    xr_ed.set_buffer(xor_buf.clone());
    xr_ed.set_text_font(fltk::enums::Font::Courier);
    xr_ed.set_text_size(13);
    xr_ed.set_insert_mode(false);
    xr_ed.set_color(fltk::enums::Color::White);
    xr_ed.set_selection_color(fltk::enums::Color::from_hex(0x316AC5));
    xr_btn.set_callback({
        let inp = xr_input.clone();
        let hex_rb = xr_hex_rb.clone();
        move |_| {
            STATE.with(|s| {
                let is_hex = hex_rb.is_set();
                if let Some(key) = xor::parse_key(&inp.value(), is_hex) {
                    s.borrow_mut().apply_xor(&key);
                } else {
                    fltk::dialog::alert_default("Invalid XOR key!");
                }
            });
            Editors::refresh();
        }
    });
    xr_grp.end();

    tabs.end();

    let mut status = Frame::new(0, 677, 1050, 22, " No file loaded");
    status.set_frame(fltk::enums::FrameType::ThinDownBox);
    status.set_color(fltk::enums::Color::from_hex(0xECE9D8));
    status.set_label_color(fltk::enums::Color::from_hex(0x004080));
    status.set_label_size(11);

    win.end();
    win.show();

    pe_buf.set_text("Open a file with File > Open (Ctrl+O)");
    xor_buf.set_text("Enter a XOR key and click Apply (need to open a file first).\n\nExamples:\n  ASCII key: \"hello\"  (5-byte key: 68 65 6C 6C 6F)\n  HEX key:   \"FF A1\"    (2-byte key: FF A1)\n  HEX key:   \"0xDEAD\"  (2-byte key: DE AD)");

    EDITORS.with(|e| {
        *e.borrow_mut() = Some(Editors {
            pe: pe_buf, hex: hex_buf, str: str_buf, disasm: disasm_buf,
            md5: md5_out, sha1: sha1_out, sha256: sha256_out,
            xor_hex: xor_buf, status,
        });
    });

    app.run().unwrap();
}
