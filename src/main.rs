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
    regs: [String; 10],
    stack: String,
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
            regs: [
                "00000000".into(), "00000000".into(), "00000000".into(),
                "00000000".into(), "00000000".into(), "00000000".into(),
                "00000000".into(), "00000000".into(), "00000000".into(),
                "00000000".into(),
            ],
            stack: String::new(),
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
        self.compute_regs_and_stack();
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

    fn compute_regs_and_stack(&mut self) {
        let info = pe::parse_pe(self.core.file_data.clone());
        let (entry, base, img_size, code_size, num_sec, chars) =
            if let Some(ref i) = info {
                (i.entry_point, i.image_base, i.size_of_image, i.size_of_code,
                 i.num_sections as u32, i.characteristics.clone())
            } else {
                (0u32, 0u64, 0u32, 0u32, 0u32, String::new())
            };
        self.core.regs = [
            format!("{:08X}", entry),
            format!("{:016X}", base),
            format!("{:08X}", img_size),
            format!("{:08X}", code_size),
            format!("{:X}", num_sec),
            format!("{:08X}", entry),
            format!("{:X}", 0x1000),
            format!("{:X}", 0x200),
            format!("{:08X}", entry),
            if chars.is_empty() { "00000000".into() } else { chars },
        ];
        self.core.stack.clear();
        for (i, chunk) in self.core.file_data.chunks(16).enumerate().take(16) {
            use std::fmt::Write;
            write!(self.core.stack, "{:08X}  ", i * 16).ok();
            for (j, b) in chunk.iter().enumerate() {
                write!(self.core.stack, "{:02X} ", b).ok();
                if j == 7 { write!(self.core.stack, " ").ok(); }
            }
            self.core.stack.push('\n');
        }
    }
}

struct Editors {
    disasm: TextBuffer,
    disasm_style: TextBuffer,
    hex: TextBuffer,
    hex_style: TextBuffer,
    regs: Vec<Output>,
    stack: TextBuffer,
    status: Frame,
    title: Frame,
}

impl Editors {
    fn refresh() {
        let (disasm, hex, regs, stack, label) = STATE.with(|s| {
            let st = s.borrow();
            (
                st.core.disasm.clone(), st.core.hex.clone(),
                st.core.regs.clone(), st.core.stack.clone(),
                st.file_label.clone(),
            )
        });
        EDITORS.with(|e| {
            if let Some(ref mut ed) = *e.borrow_mut() {
                ed.disasm.set_text(&disasm);
                let ds = highlight::style_disasm(&disasm);
                ed.disasm_style.set_text(std::str::from_utf8(&ds).unwrap_or(""));
                ed.hex.set_text(&hex);
                let hs = highlight::style_hex(&hex);
                ed.hex_style.set_text(std::str::from_utf8(&hs).unwrap_or(""));
                for (i, v) in regs.iter().enumerate() {
                    if i < ed.regs.len() { ed.regs[i].set_value(v); }
                }
                ed.stack.set_text(&stack);
                ed.status.set_label(&label);
                ed.title.set_label(&format!("  xptool - {}", label));
            }
        });
    }
}

thread_local! {
    static EDITORS: RefCell<Option<Editors>> = const { RefCell::new(None) };
}

thread_local! {
    static TB_BTNS: RefCell<Vec<Button>> = const { RefCell::new(Vec::new()) };
    static VIEW_GROUPS: RefCell<Vec<Group>> = const { RefCell::new(Vec::new()) };
}

fn switch_view(idx: usize) {
    let c_sel   = fltk::enums::Color::from_hex(0x094771);
    let c_header = fltk::enums::Color::from_hex(0x2D2D2D);
    let c_txt   = fltk::enums::Color::from_hex(0xD4D4D4);
    let c_white = fltk::enums::Color::from_hex(0xF0F0F0);
    TB_BTNS.with(|b| {
        for (i, btn) in b.borrow_mut().iter_mut().enumerate() {
            if i == idx {
                btn.set_color(c_sel);
                btn.set_label_color(c_white);
            } else {
                btn.set_color(c_header);
                btn.set_label_color(c_txt);
            }
        }
    });
    VIEW_GROUPS.with(|g| {
        for (i, grp) in g.borrow_mut().iter_mut().enumerate() {
            if i == idx { grp.show(); } else { grp.hide(); }
        }
    });
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
    fltk::dialog::message_title("Hashes");
    fltk::dialog::message_default(&format!("MD5:   {}\nSHA1:  {}\nSHA256: {}", md5, sha1, sha256));
}

fn main() {
    let app = app::App::default().with_scheme(app::Scheme::Gtk);
    app::background(12, 12, 12);
    app::set_background_color(12, 12, 12);

    let W: i32 = 1400;
    let H: i32 = 820;
    let TITLE_H: i32 = 28;
    let MENU_H: i32 = 22;
    let TB_H: i32 = 28;
    let CY: i32 = TITLE_H + MENU_H + TB_H;
    let CH: i32 = H - CY - 24;
    let LW: i32 = 920;
    let RW: i32 = W - LW - 4;
    let TH: i32 = CH / 2;
    let BH: i32 = CH - TH;
    let RX: i32 = LW + 2;

    let c_bg     = fltk::enums::Color::from_hex(0x0C0C0C);
    let c_panel  = fltk::enums::Color::from_hex(0x1A1A1A);
    let c_sel    = fltk::enums::Color::from_hex(0x094771);
    let c_txt    = fltk::enums::Color::from_hex(0xD4D4D4);
    let c_gold   = fltk::enums::Color::from_hex(0xFFD700);
    let c_cyan   = fltk::enums::Color::from_hex(0x00FFFF);
    let c_green  = fltk::enums::Color::from_hex(0x39FF14);
    let c_orange = fltk::enums::Color::from_hex(0xFF8C00);
    let c_red    = fltk::enums::Color::from_hex(0xFF2A2A);
    let c_teal   = fltk::enums::Color::from_hex(0x4EC9B0);
    let c_gray   = fltk::enums::Color::from_hex(0x808080);
    let c_header = fltk::enums::Color::from_hex(0x2D2D2D);

    let mut win = Window::new(50, 50, W, H, "xptool - Reverse Engineering Toolkit");
    win.make_resizable(true);

    // Title Bar
    let mut title_bg = Frame::new(0, 0, W, TITLE_H, "");
    title_bg.set_frame(fltk::enums::FrameType::FlatBox);
    title_bg.set_color(c_bg);
    let mut title_txt = Frame::new(6, 0, W - 200, TITLE_H, "  xptool - No file loaded");
    title_txt.set_label_color(c_cyan);
    title_txt.set_label_size(11);

    // Menu Bar
    let mut menu = MenuBar::new(0, TITLE_H, W, MENU_H, "");
    menu.set_frame(fltk::enums::FrameType::FlatBox);
    menu.set_color(c_header);
    menu.set_label_color(c_txt);
    menu.set_selection_color(c_sel);
    menu.add("&File/Open\t", fltk::enums::Shortcut::Ctrl | 'o', fltk::menu::MenuFlag::Normal, |_| do_open());
    menu.add("&File/Hashes\t", fltk::enums::Shortcut::Ctrl | 'h', fltk::menu::MenuFlag::Normal, |_| do_rehash());
    menu.add("&File/Exit\t", fltk::enums::Shortcut::Ctrl | 'q', fltk::menu::MenuFlag::Normal, |_| app::quit());

    menu.add("&Tools/PE Info\t", fltk::enums::Shortcut::None, fltk::menu::MenuFlag::Normal, |_| {
        let text = STATE.with(|s| s.borrow().core.pe.clone());
        show_text_window("PE Information", &text, 700, 500);
    });
    menu.add("&Tools/Strings\t", fltk::enums::Shortcut::None, fltk::menu::MenuFlag::Normal, |_| {
        let text = STATE.with(|s| s.borrow().core.str.clone());
        show_text_window("Strings", &text, 800, 600);
    });
    menu.add("&Tools/XOR Tool\t", fltk::enums::Shortcut::None, fltk::menu::MenuFlag::Normal, |_| {
        show_xor_window();
    });

    // Toolbar
    let mut tb = Group::new(0, TITLE_H + MENU_H, W, TB_H, "");
    tb.set_frame(fltk::enums::FrameType::FlatBox);
    tb.set_color(c_header);
    let tb_labels = ["CPU", "Graph", "Snowman", "References", "Breakpoints", "Threads",
                     "Handles", "Memory Map", "Symbols", "Call Stack", "SEH", "Notes",
                     "Log", "Script", "Source"];
    let tb_colors = [c_green, c_orange, c_cyan, c_gold, c_red, c_cyan,
                     c_orange, c_gray, c_gold, c_teal, c_red, c_cyan, c_gray, c_orange, c_green];
    let mut tb_btns: Vec<Button> = Vec::new();
    for (i, lbl) in tb_labels.iter().enumerate() {
        let x = 4 + i as i32 * 76;
        let mut b = Button::new(x, 3, 72, TB_H - 6, *lbl);
        b.set_frame(fltk::enums::FrameType::FlatBox);
        b.set_color(c_header);
        b.set_selection_color(c_sel);
        b.set_label_color(tb_colors[i % tb_colors.len()]);
        b.set_label_size(10);
        let idx = i;
        b.set_callback(move |_| switch_view(idx));
        tb_btns.push(b);
    }
    tb.end();
    TB_BTNS.with(|v| *v.borrow_mut() = tb_btns);

    // CPU View (index 0): 4-panel layout
    let mut cpu_grp = Group::new(0, CY, W, CH, "");
    cpu_grp.set_frame(fltk::enums::FrameType::FlatBox);
    cpu_grp.set_color(c_bg);

    // Top-Left: Disassembly
    let mut da_panel = Group::new(0, 0, LW, TH, "");
    da_panel.set_frame(fltk::enums::FrameType::FlatBox);
    da_panel.set_color(c_bg);
    let mut da_head = Frame::new(0, 0, LW, 20, "  DISASSEMBLY");
    da_head.set_frame(fltk::enums::FrameType::FlatBox);
    da_head.set_color(c_panel);
    da_head.set_label_color(c_green);
    da_head.set_label_size(10);
    let mut da_buf = TextBuffer::default();
    let da_sty = TextBuffer::default();
    let mut da_ed = TextEditor::new(0, 20, LW, TH - 20, "");
    da_ed.set_buffer(da_buf.clone());
    da_ed.set_highlight_data(da_sty.clone(), highlight::disasm_style_table());
    da_ed.set_text_font(fltk::enums::Font::Courier);
    da_ed.set_text_size(12);
    da_ed.set_insert_mode(false);
    da_ed.set_color(c_bg);
    da_ed.set_text_color(c_txt);
    da_ed.set_selection_color(c_sel);
    da_ed.set_cursor_color(c_green);
    da_panel.end();

    // Top-Right: Registers
    let mut reg_panel = Group::new(RX, 0, RW, TH, "");
    reg_panel.set_frame(fltk::enums::FrameType::FlatBox);
    reg_panel.set_color(c_bg);
    let mut reg_head = Frame::new(RX, 0, RW, 20, "  REGISTERS");
    reg_head.set_frame(fltk::enums::FrameType::FlatBox);
    reg_head.set_color(c_panel);
    reg_head.set_label_color(c_gold);
    reg_head.set_label_size(10);
    let cpu_names = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS"];
    let mut reg_vals: Vec<Output> = cpu_names.iter().enumerate().map(|(i, name)| {
        let y = 24 + i as i32 * 18;
        let mut nl = Frame::new(RX + 4, y, 40, 16, *name);
        nl.set_label_color(c_teal);
        nl.set_label_size(10);
        nl.set_align(fltk::enums::Align::Right | fltk::enums::Align::Inside);
        let mut ov = Output::new(RX + 48, y, RW - 54, 16, "");
        ov.set_color(c_bg);
        ov.set_text_color(c_gold);
        ov.set_text_size(10);
        ov.set_text_font(fltk::enums::Font::Courier);
        ov
    }).collect();
    let mut x87_head = Frame::new(RX + 4, 24 + 10 * 18 + 4, RW - 8, 14, "x87 REGISTERS");
    x87_head.set_label_color(c_cyan);
    x87_head.set_label_size(9);
    for i in 0..8 {
        let y = 24 + 10 * 18 + 20 + i as i32 * 15;
        let x87_label = format!("x87r{}:", i);
        let mut nl = Frame::new(RX + 4, y, 44, 14, x87_label.as_str());
        nl.set_label_color(c_teal);
        nl.set_label_size(9);
        nl.set_align(fltk::enums::Align::Right | fltk::enums::Align::Inside);
        let mut ov = Output::new(RX + 52, y, RW - 58, 14, "");
        ov.set_color(c_bg);
        ov.set_text_color(c_cyan);
        ov.set_text_size(9);
        ov.set_text_font(fltk::enums::Font::Courier);
        reg_vals.push(ov);
    }
    reg_panel.end();

    // Bottom-Left: Hex Dump
    let mut hex_panel = Group::new(0, TH, LW, BH, "");
    hex_panel.set_frame(fltk::enums::FrameType::FlatBox);
    hex_panel.set_color(c_bg);
    let mut hex_head = Frame::new(0, TH, LW, 20, "  HEX DUMP");
    hex_head.set_frame(fltk::enums::FrameType::FlatBox);
    hex_head.set_color(c_panel);
    hex_head.set_label_color(c_green);
    hex_head.set_label_size(10);
    let mut hex_buf = TextBuffer::default();
    let hex_sty = TextBuffer::default();
    let mut hex_ed = TextEditor::new(0, TH + 20, LW, BH - 20, "");
    hex_ed.set_buffer(hex_buf.clone());
    hex_ed.set_highlight_data(hex_sty.clone(), highlight::hex_style_table());
    hex_ed.set_text_font(fltk::enums::Font::Courier);
    hex_ed.set_text_size(12);
    hex_ed.set_insert_mode(false);
    hex_ed.set_color(c_bg);
    hex_ed.set_text_color(c_txt);
    hex_ed.set_selection_color(c_sel);
    hex_panel.end();

    // Bottom-Right: Stack
    let mut stk_panel = Group::new(RX, TH, RW, BH, "");
    stk_panel.set_frame(fltk::enums::FrameType::FlatBox);
    stk_panel.set_color(c_bg);
    let mut stk_head = Frame::new(RX, TH, RW, 20, "  STACK");
    stk_head.set_frame(fltk::enums::FrameType::FlatBox);
    stk_head.set_color(c_panel);
    stk_head.set_label_color(c_gold);
    stk_head.set_label_size(10);
    let mut stack_buf = TextBuffer::default();
    let mut stk_ed = TextEditor::new(RX + 2, TH + 20, RW - 4, BH - 20, "");
    stk_ed.set_buffer(stack_buf.clone());
    stk_ed.set_text_font(fltk::enums::Font::Courier);
    stk_ed.set_text_size(11);
    stk_ed.set_insert_mode(false);
    stk_ed.set_color(c_bg);
    stk_ed.set_text_color(c_txt);
    stk_ed.set_selection_color(c_sel);
    stk_panel.end();

    cpu_grp.end();

    // Other views (index 1..14)
    let other_names = ["Graph", "Snowman", "References", "Breakpoints", "Threads",
                       "Handles", "Memory Map", "Symbols", "Call Stack", "SEH",
                       "Notes", "Log", "Script", "Source"];
    let mut view_grps: Vec<Group> = Vec::new();
    view_grps.push(cpu_grp);
    for name in &other_names {
        let mut grp = Group::new(0, CY, W, CH, "");
        grp.set_frame(fltk::enums::FrameType::FlatBox);
        grp.set_color(c_bg);
        let mut buf = TextBuffer::default();
        buf.set_text(&format!("{} View\n\nNot yet implemented.", name));
        let mut ed = TextEditor::new(2, 2, W - 4, CH - 4, "");
        ed.set_buffer(buf);
        ed.set_text_font(fltk::enums::Font::Courier);
        ed.set_text_size(12);
        ed.set_insert_mode(false);
        ed.set_color(c_bg);
        ed.set_text_color(c_txt);
        ed.set_selection_color(c_sel);
        grp.end();
        view_grps.push(grp);
    }
    VIEW_GROUPS.with(|v| *v.borrow_mut() = view_grps);

    // Status Bar
    let mut status = Frame::new(0, CY + CH, W, 24, " No file loaded  |  Ready");
    status.set_frame(fltk::enums::FrameType::FlatBox);
    status.set_color(c_header);
    status.set_label_color(c_txt);
    status.set_label_size(10);
    status.set_align(fltk::enums::Align::Left | fltk::enums::Align::Inside);

    win.end();
    win.show();

    da_buf.set_text("Open a file with File > Open (Ctrl+O)");
    hex_buf.set_text("Open a file with File > Open (Ctrl+O)");
    stack_buf.set_text("No file loaded.");
    for ov in &mut reg_vals {
        ov.set_value("00000000");
    }

    EDITORS.with(|e| {
        *e.borrow_mut() = Some(Editors {
            disasm: da_buf, disasm_style: da_sty,
            hex: hex_buf, hex_style: hex_sty,
            regs: reg_vals,
            stack: stack_buf,
            status, title: title_txt,
        });
    });

    switch_view(0);

    app.run().unwrap();
}

fn show_text_window(title: &str, text: &str, w: i32, h: i32) {
    let mut win = Window::default().with_size(w, h).with_label(title);
    win.make_resizable(true);
    win.set_color(fltk::enums::Color::from_hex(0x1E1E1E));
    let mut buf = TextBuffer::default();
    buf.set_text(text);
    let mut ed = TextEditor::new(5, 5, w - 10, h - 10, "");
    ed.set_buffer(buf);
    ed.set_text_font(fltk::enums::Font::Courier);
    ed.set_text_size(12);
    ed.set_insert_mode(false);
    ed.set_color(fltk::enums::Color::from_hex(0x0C0C0C));
    ed.set_text_color(fltk::enums::Color::from_hex(0xD4D4D4));
    win.end();
    win.show();
}

fn show_xor_window() {
    let mut win = Window::default().with_size(750, 550).with_label("XOR Tool");
    win.make_resizable(true);
    win.set_color(fltk::enums::Color::from_hex(0x1E1E1E));

    let c_bg = fltk::enums::Color::from_hex(0x0C0C0C);
    let c_pn = fltk::enums::Color::from_hex(0x2D2D2D);
    let c_sel = fltk::enums::Color::from_hex(0x094771);
    let c_txt = fltk::enums::Color::from_hex(0xD4D4D4);
    let c_txtb = fltk::enums::Color::from_hex(0xF0F0F0);

    let mut key_inp = Input::new(55, 10, 160, 24, "Key:");
    key_inp.set_color(c_pn);
    key_inp.set_text_color(c_txtb);

    let mut hex_rb = RadioRoundButton::new(230, 10, 55, 24, "HEX");
    hex_rb.set_label_color(c_txt);

    let mut asc_rb = RadioRoundButton::new(290, 10, 65, 24, "ASCII");
    asc_rb.set_label_color(c_txt);
    asc_rb.set_value(true);

    let mut apply_btn = Button::new(365, 10, 70, 24, "Apply");
    apply_btn.set_color(c_pn);
    apply_btn.set_selection_color(c_sel);
    apply_btn.set_label_color(c_txt);

    let mut buf = TextBuffer::default();
    buf.set_text("Enter a XOR key and click Apply\n\nExamples:\n  ASCII: \"hello\" (68 65 6C 6C 6F)\n  HEX:   \"FF A1\"  (FF A1)\n  HEX:   \"0xDEAD\" (DE AD)");

    let mut ed = TextEditor::new(5, 40, 740, 505, "");
    ed.set_buffer(buf.clone());
    ed.set_text_font(fltk::enums::Font::Courier);
    ed.set_text_size(12);
    ed.set_insert_mode(false);
    ed.set_color(c_bg);
    ed.set_text_color(c_txt);

    let inp = key_inp.clone();
    let hex = hex_rb.clone();
    apply_btn.set_callback(move |_| {
        STATE.with(|s| {
            let is_hex = hex.is_set();
            if let Some(key) = xor::parse_key(&inp.value(), is_hex) {
                s.borrow_mut().apply_xor(&key);
                let result = s.borrow().core.xor_hex.clone();
                buf.set_text(&result);
            } else {
                fltk::dialog::alert_default("Invalid XOR key!");
            }
        });
    });

    win.end();
    win.show();
}
