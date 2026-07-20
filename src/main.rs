mod pe;
mod disasm;
mod hash;
mod xor;
mod highlight;

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
    str: TextBuffer,
    disasm: TextBuffer,
    disasm_style: TextBuffer,
    hex: TextBuffer,
    hex_style: TextBuffer,
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
                ed.str.set_text(&str);
                ed.xor_hex.set_text(&xor_hex);
                ed.md5.set_value(&md5);
                ed.sha1.set_value(&sha1);
                ed.sha256.set_value(&sha256);
                ed.status.set_label(&label);
                ed.disasm.set_text(&disasm);
                let ds = highlight::style_disasm(&disasm);
                ed.disasm_style.set_text(std::str::from_utf8(&ds).unwrap_or(""));
                ed.hex.set_text(&hex);
                let hs = highlight::style_hex(&hex);
                ed.hex_style.set_text(std::str::from_utf8(&hs).unwrap_or(""));
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

thread_local! {
    static CONTENT_GROUPS: RefCell<Vec<Group>> = const { RefCell::new(Vec::new()) };
    static SIDEBAR_BTNS: RefCell<Vec<Button>> = const { RefCell::new(Vec::new()) };
}

fn switch_tab(idx: usize) {
    let sb_bg = fltk::enums::Color::from_hex(0x252526);
    let sb_sel = fltk::enums::Color::from_hex(0x094771);
    SIDEBAR_BTNS.with(|b| {
        let mut btns = b.borrow_mut();
        for i in 0..btns.len() {
            if i == idx {
                btns[i].set_color(sb_sel);
                btns[i].set_selection_color(sb_sel);
                btns[i].set_label_color(fltk::enums::Color::from_hex(0xF0F0F0));
                btns[i].set_frame(fltk::enums::FrameType::FlatBox);
            } else {
                btns[i].set_color(sb_bg);
                btns[i].set_selection_color(sb_sel);
                btns[i].set_label_color(fltk::enums::Color::from_hex(0xCCCCCC));
                btns[i].set_frame(fltk::enums::FrameType::FlatBox);
            }
        }
    });
    CONTENT_GROUPS.with(|g| {
        let mut groups = g.borrow_mut();
        for i in 0..groups.len() {
            if i == idx { groups[i].show(); } else { groups[i].hide(); }
        }
    });
}

fn main() {
    let app = app::App::default().with_scheme(app::Scheme::Gtk);
    app::background(30, 30, 30);
    app::set_background_color(30, 30, 30);

    let mut win = Window::new(100, 100, 1150, 740, "XPTool - Reverse Engineering Toolkit");
    win.set_frame(fltk::enums::FrameType::BorderBox);
    win.make_resizable(true);

    let c_bg = fltk::enums::Color::from_hex(0x1E1E1E);
    let c_sb = fltk::enums::Color::from_hex(0x252526);
    let c_pn = fltk::enums::Color::from_hex(0x2D2D2D);
    let c_sel = fltk::enums::Color::from_hex(0x094771);
    let c_txt = fltk::enums::Color::from_hex(0xD4D4D4);
    let c_txtb = fltk::enums::Color::from_hex(0xF0F0F0);
    let c_reg = fltk::enums::Color::from_hex(0x4EC9B0);
    let c_addr = fltk::enums::Color::from_hex(0xDCDCAA);

    let sb_w = 150;
    let rp_w = 220;
    let cx = sb_w + 1;
    let cw = 1150 - sb_w - rp_w - 2;
    let rx = 1150 - rp_w;
    let main_y = 24;
    let main_h = 692;

    // Menu bar
    let mut menu = MenuBar::new(0, 0, 1150, 24, "");
    menu.set_frame(fltk::enums::FrameType::FlatBox);
    menu.set_color(c_sb);
    menu.set_label_color(c_txtb);
    menu.set_selection_color(c_sel);
    menu.add("&File/Open\t", fltk::enums::Shortcut::Ctrl | 'o', fltk::menu::MenuFlag::Normal, |_| do_open());
    menu.add("&File/Exit\t", fltk::enums::Shortcut::Ctrl | 'q', fltk::menu::MenuFlag::Normal, |_| app::quit());

    // Sidebar
    let mut sidebar = Group::new(0, main_y, sb_w, main_h, "");
    sidebar.set_frame(fltk::enums::FrameType::FlatBox);
    sidebar.set_color(c_sb);

    let mut sb_title = Frame::new(0, main_y + 4, sb_w, 24, "  NAVIGATION");
    sb_title.set_label_size(10);
    sb_title.set_label_color(c_sel);
    sb_title.set_frame(fltk::enums::FrameType::FlatBox);
    sb_title.set_color(c_sb);
    sb_title.set_align(fltk::enums::Align::Left | fltk::enums::Align::Inside);

    let mut sep1 = Frame::new(5, main_y + 28, sb_w - 10, 1, "");
    sep1.set_frame(fltk::enums::FrameType::ThinDownBox);

    let btn_pe    = btn(sb_w, &c_sb, &c_sel, main_y + 33, "  PE Analyzer");
    let btn_hex   = btn(sb_w, &c_sb, &c_sel, main_y + 59, "  Hex Viewer");
    let btn_str   = btn(sb_w, &c_sb, &c_sel, main_y + 85, "  Strings");
    let btn_dis   = btn(sb_w, &c_sb, &c_sel, main_y + 111, "  Disassembler");
    let btn_hash  = btn(sb_w, &c_sb, &c_sel, main_y + 137, "  Hash");
    let btn_xor   = btn(sb_w, &c_sb, &c_sel, main_y + 163, "  XOR Tool");

    sidebar.end();

    // Divider
    let mut div1 = Frame::new(sb_w, main_y, 1, main_h, "");
    div1.set_frame(fltk::enums::FrameType::ThinDownBox);
    let mut div2 = Frame::new(rx - 1, main_y, 1, main_h, "");
    div2.set_frame(fltk::enums::FrameType::ThinDownBox);

    // Content area
    let pe_grp = grp(cx, main_y, cw, main_h);
    let mut pe_buf = TextBuffer::default();
    let _pe_ed = ted(cx + 4, main_y + 4, cw - 8, main_h - 8, &pe_buf, &c_bg, &c_sel);
    pe_grp.end();

    let hx_grp = grp(cx, main_y, cw, main_h);
    let hex_buf = TextBuffer::default();
    let hex_style = TextBuffer::default();
    let mut hx_ed = TextEditor::new(cx + 4, main_y + 4, cw - 8, main_h - 8, "");
    hx_ed.set_buffer(hex_buf.clone());
    hx_ed.set_highlight_data(hex_style.clone(), highlight::hex_style_table());
    hx_ed.set_text_font(fltk::enums::Font::Courier);
    hx_ed.set_text_size(12);
    hx_ed.set_insert_mode(false);
    hx_ed.set_color(c_bg);
    hx_ed.set_text_color(c_txt);
    hx_ed.set_selection_color(c_sel);
    hx_grp.end();

    let st_grp = grp(cx, main_y, cw, main_h);
    let str_buf = TextBuffer::default();
    let _st_ed = ted(cx + 4, main_y + 4, cw - 8, main_h - 8, &str_buf, &c_bg, &c_sel);
    st_grp.end();

    let da_grp = grp(cx, main_y, cw, main_h);
    let disasm_buf = TextBuffer::default();
    let disasm_style = TextBuffer::default();
    let mut da_ed = TextEditor::new(cx + 4, main_y + 4, cw - 8, main_h - 8, "");
    da_ed.set_buffer(disasm_buf.clone());
    da_ed.set_highlight_data(disasm_style.clone(), highlight::disasm_style_table());
    da_ed.set_text_font(fltk::enums::Font::Courier);
    da_ed.set_text_size(12);
    da_ed.set_insert_mode(false);
    da_ed.set_color(c_bg);
    da_ed.set_text_color(c_txt);
    da_ed.set_selection_color(c_sel);
    da_grp.end();

    let ha_grp = grp(cx, main_y, cw, main_h);
    let mut md5_out = Output::new(cx + 10, main_y + 40, 260, 24, " MD5:");
    let mut sha1_out = Output::new(cx + 10, main_y + 68, 260, 24, " SHA1:");
    let mut sha256_out = Output::new(cx + 10, main_y + 96, 260, 24, " SHA256:");
    for o in [&mut md5_out, &mut sha1_out, &mut sha256_out] {
        o.set_text_font(fltk::enums::Font::Courier);
        o.set_text_size(12);
        o.set_color(c_pn);
        o.set_text_color(c_addr);
        o.set_selection_color(c_sel);
    }
    let mut hash_btn = Button::new(cx + 280, main_y + 40, 140, 24, "Re-calc");
    hash_btn.set_color(c_pn);
    hash_btn.set_selection_color(c_sel);
    hash_btn.set_label_color(c_txt);
    hash_btn.set_callback(|_| do_rehash());
    ha_grp.end();

    let xr_grp = grp(cx, main_y, cw, main_h);
    let mut xr_lbl = Frame::new(cx + 10, main_y + 38, 40, 22, "Key:");
    xr_lbl.set_label_color(c_txt);
    xr_lbl.set_label_size(12);
    let mut xr_inp = Input::new(cx + 50, main_y + 38, 160, 22, "");
    xr_inp.set_color(c_pn);
    xr_inp.set_text_color(c_txtb);
    xr_inp.set_text_size(12);
    let mut xr_hex = RadioRoundButton::new(cx + 220, main_y + 38, 50, 22, "HEX");
    xr_hex.set_label_color(c_txt);
    xr_hex.set_label_size(12);
    let mut xr_asc = RadioRoundButton::new(cx + 272, main_y + 38, 60, 22, "ASCII");
    xr_asc.set_label_color(c_txt);
    xr_asc.set_label_size(12);
    xr_asc.set_value(true);
    let mut xr_btn = Button::new(cx + 340, main_y + 38, 80, 22, "Apply");
    xr_btn.set_color(c_pn);
    xr_btn.set_selection_color(c_sel);
    xr_btn.set_label_color(c_txt);
    let mut xor_buf = TextBuffer::default();
    let _xr_ed = ted(cx + 4, main_y + 66, cw - 8, main_h - 74, &xor_buf, &c_bg, &c_sel);
    let inp = xr_inp.clone();
    let hex_rb = xr_hex.clone();
    xr_btn.set_callback(move |_| {
        STATE.with(|s| {
            let is_hex = hex_rb.is_set();
            if let Some(key) = xor::parse_key(&inp.value(), is_hex) {
                s.borrow_mut().apply_xor(&key);
            } else {
                fltk::dialog::alert_default("Invalid XOR key!");
            }
        });
        Editors::refresh();
    });
    xr_grp.end();

    // Right info panel (x64dbg style)
    let mut info_panel = Group::new(rx, main_y, rp_w, main_h, "");
    info_panel.set_frame(fltk::enums::FrameType::FlatBox);
    info_panel.set_color(c_bg);

    let mut reg_label = Frame::new(rx + 4, main_y + 4, rp_w - 8, 18, "REGISTERS");
    reg_label.set_label_color(c_sel);
    reg_label.set_label_size(10);
    reg_label.set_frame(fltk::enums::FrameType::FlatBox);
    reg_label.set_color(c_pn);

    let reg_names = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS"];
    let mut reg_vals_out: Vec<Output> = reg_names.iter().enumerate().map(|(i, name)| {
        let y = main_y + 26 + (i as i32) * 20;
        let mut nf = Frame::new(rx + 6, y, 42, 18, *name);
        nf.set_label_color(c_reg);
        nf.set_label_size(11);
        nf.set_align(fltk::enums::Align::Right | fltk::enums::Align::Inside);
        let mut vf = Output::new(rx + 52, y, rp_w - 60, 18, "");
        vf.set_color(c_bg);
        vf.set_text_color(c_addr);
        vf.set_text_size(11);
        vf.set_text_font(fltk::enums::Font::Courier);
        vf
    }).collect();

    let mut stk_label = Frame::new(rx + 4, main_y + 228, rp_w - 8, 18, "STACK");
    stk_label.set_label_color(c_sel);
    stk_label.set_label_size(10);
    stk_label.set_frame(fltk::enums::FrameType::FlatBox);
    stk_label.set_color(c_pn);

    let mut stack_buf = TextBuffer::default();
    let mut stack_ed = TextEditor::new(rx + 2, main_y + 248, rp_w - 4, main_h - 252, "");
    stack_ed.set_buffer(stack_buf.clone());
    stack_ed.set_text_font(fltk::enums::Font::Courier);
    stack_ed.set_text_size(11);
    stack_ed.set_insert_mode(false);
    stack_ed.set_color(c_bg);
    stack_ed.set_text_color(c_addr);
    stack_ed.set_selection_color(c_sel);
    info_panel.end();

    // Status bar
    let mut status = Frame::new(0, 716, 1150, 24, " No file loaded");
    status.set_frame(fltk::enums::FrameType::FlatBox);
    status.set_color(c_sb);
    status.set_label_color(c_txt);
    status.set_label_size(11);

    win.end();
    win.show();

    // Register content groups
    CONTENT_GROUPS.with(|g| {
        let mut v = g.borrow_mut();
        v.push(pe_grp); v.push(hx_grp); v.push(st_grp);
        v.push(da_grp); v.push(ha_grp); v.push(xr_grp);
    });

    // Register sidebar buttons
    let mut btns = [btn_pe, btn_hex, btn_str, btn_dis, btn_hash, btn_xor];
    SIDEBAR_BTNS.with(|b| {
        let mut v = b.borrow_mut();
        for btn in &btns { v.push(btn.clone()); }
    });

    btns[0].set_callback(|_| switch_tab(0));
    btns[1].set_callback(|_| switch_tab(1));
    btns[2].set_callback(|_| switch_tab(2));
    btns[3].set_callback(|_| switch_tab(3));
    btns[4].set_callback(|_| switch_tab(4));
    btns[5].set_callback(|_| switch_tab(5));

    switch_tab(0);

    pe_buf.set_text("Open a file with File > Open (Ctrl+O)");
    xor_buf.set_text("Enter a XOR key and click Apply\n\nExamples:\n  ASCII: \"hello\" (68 65 6C 6C 6F)\n  HEX:   \"FF A1\"  (FF A1)\n  HEX:   \"0xDEAD\" (DE AD)");

    stack_buf.set_text("0019FF88  00 00 00 00\n0019FF8C  00 00 00 00\n0019FF90  00 00 00 00\n0019FF94  00 00 00 00\n0019FF98  00 00 00 00\n0019FF9C  00 00 00 00");

    for (i, _name) in reg_names.iter().enumerate() {
        if i < reg_vals_out.len() {
            reg_vals_out[i].set_value("00000000");
        }
    }

    EDITORS.with(|e| {
        *e.borrow_mut() = Some(Editors {
            pe: pe_buf, str: str_buf, hex: hex_buf, hex_style,
            disasm: disasm_buf, disasm_style,
            md5: md5_out, sha1: sha1_out, sha256: sha256_out,
            xor_hex: xor_buf, status,
        });
    });

    app.run().unwrap();
}

fn btn(sb_w: i32, c_sb: &fltk::enums::Color, c_sel: &fltk::enums::Color, y: i32, label: &str) -> Button {
    let mut b = Button::new(2, y, sb_w - 4, 24, label);
    b.set_color(*c_sb);
    b.set_selection_color(*c_sel);
    b.set_label_color(fltk::enums::Color::from_hex(0xCCCCCC));
    b.set_label_size(11);
    b.set_frame(fltk::enums::FrameType::FlatBox);
    b.set_align(fltk::enums::Align::Left | fltk::enums::Align::Inside);
    b
}

fn grp(x: i32, y: i32, w: i32, h: i32) -> Group {
    let mut g = Group::new(x, y, w, h, "");
    g.set_frame(fltk::enums::FrameType::FlatBox);
    g.set_color(fltk::enums::Color::from_hex(0x1E1E1E));
    g
}

fn ted(x: i32, y: i32, w: i32, h: i32, buf: &TextBuffer, bg: &fltk::enums::Color, sel: &fltk::enums::Color) -> TextEditor {
    let mut e = TextEditor::new(x, y, w, h, "");
    e.set_buffer(buf.clone());
    e.set_text_font(fltk::enums::Font::Courier);
    e.set_text_size(12);
    e.set_insert_mode(false);
    e.set_color(*bg);
    e.set_text_color(fltk::enums::Color::from_hex(0xD4D4D4));
    e.set_selection_color(*sel);
    e
}
