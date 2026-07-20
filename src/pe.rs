use std::fmt;

#[derive(Clone)]
pub struct PESection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_address: u32,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

impl fmt::Display for PESection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<8}  VSize:0x{:X}  VAddr:0x{:08X}  RSize:0x{:X}  RAddr:0x{:08X}  {:?}",
            self.name,
            self.virtual_size,
            self.virtual_address,
            self.raw_size,
            self.raw_address,
            section_chars_desc(self.characteristics),
        )
    }
}

pub struct PEInfo {
    pub data: Vec<u8>,
    pub machine: String,
    pub num_sections: u16,
    pub timestamp: String,
    pub pe_type: String,
    pub entry_point: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_code: u32,
    pub subsystem: String,
    pub characteristics: String,
    pub sections: Vec<PESection>,
    pub is_pe32plus: bool,
    pub pe_offset: u32,
}

pub struct ImportEntry {
    pub dll: String,
    pub name: String,
}

pub struct ExportEntry {
    pub name: String,
    pub address: String,
}

pub fn read_u16(data: &[u8], off: u32) -> u16 {
    if (off as usize) + 2 > data.len() { 0 }
    else { u16::from_le_bytes([data[off as usize], data[off as usize + 1]]) }
}

pub fn read_u32(data: &[u8], off: u32) -> u32 {
    if (off as usize) + 4 > data.len() { 0 }
    else { u32::from_le_bytes([data[off as usize], data[off as usize + 1], data[off as usize + 2], data[off as usize + 3]]) }
}

pub fn read_u64(data: &[u8], off: u32) -> u64 {
    if (off as usize) + 8 > data.len() { 0 }
    else { u64::from_le_bytes([data[off as usize], data[off as usize + 1], data[off as usize + 2], data[off as usize + 3], data[off as usize + 4], data[off as usize + 5], data[off as usize + 6], data[off as usize + 7]]) }
}

fn pe_chars_desc(ch: u16) -> String {
    let mut v = Vec::new();
    if ch & 0x0001 != 0 { v.push("RELOCS_STRIPPED"); }
    if ch & 0x0002 != 0 { v.push("EXECUTABLE_IMAGE"); }
    if ch & 0x0004 != 0 { v.push("LINE_NUMS_STRIPPED"); }
    if ch & 0x0008 != 0 { v.push("LOCAL_SYMS_STRIPPED"); }
    if ch & 0x0010 != 0 { v.push("AGGRESSIVE_WS_TRIM"); }
    if ch & 0x0020 != 0 { v.push("LARGE_ADDRESS_AWARE"); }
    if ch & 0x0080 != 0 { v.push("BYTES_REVERSED_LO"); }
    if ch & 0x0100 != 0 { v.push("32BIT_MACHINE"); }
    if ch & 0x0200 != 0 { v.push("DEBUG_STRIPPED"); }
    if ch & 0x0400 != 0 { v.push("REMOVABLE_RUN_FROM_SWAP"); }
    if ch & 0x0800 != 0 { v.push("NET_RUN_FROM_SWAP"); }
    if ch & 0x1000 != 0 { v.push("SYSTEM"); }
    if ch & 0x2000 != 0 { v.push("DLL"); }
    if ch & 0x4000 != 0 { v.push("UP_SYSTEM_ONLY"); }
    if ch & 0x8000 != 0 { v.push("BYTES_REVERSED_HI"); }
    if v.is_empty() { return "None".into(); }
    v.join(" | ")
}

pub fn section_chars_desc(ch: u32) -> Vec<String> {
    let mut v = Vec::new();
    if ch & 0x00000020 != 0 { v.push("CODE".into()); }
    if ch & 0x00000040 != 0 { v.push("INIT_DATA".into()); }
    if ch & 0x00000080 != 0 { v.push("UNINIT_DATA".into()); }
    if ch & 0x02000000 != 0 { v.push("DISCARDABLE".into()); }
    if ch & 0x20000000 != 0 { v.push("EXECUTE".into()); }
    if ch & 0x40000000 != 0 { v.push("READ".into()); }
    if ch & 0x80000000 != 0 { v.push("WRITE".into()); }
    v
}

pub fn parse_pe(data: Vec<u8>) -> Option<PEInfo> {
    if data.len() < 64 || &data[0..2] != b"MZ" { return None; }

    let pe_off = read_u32(&data, 0x3C);
    if pe_off == 0 || (pe_off as usize) + 4 >= data.len() { return None; }
    if &data[pe_off as usize..pe_off as usize + 4] != b"PE\x00\x00" { return None; }

    let machine = read_u16(&data, pe_off + 4);
    let machine_str = match machine {
        0x014c => "I386 (x86)",
        0x8664 => "AMD64 (x64)",
        0x01c4 => "ARM NT",
        0xaa64 => "ARM64",
        0x01c0 => "ARM",
        0x0200 => "IA64",
        _ => "Unknown",
    };

    let num_sec = read_u16(&data, pe_off + 6);
    let ts = read_u32(&data, pe_off + 8);
    let timestamp = if ts == 0 {
        "N/A".into()
    } else {
        let ut = std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts as u64);
        format!("{:?}", ut)
    };

    let chars = read_u16(&data, pe_off + 22);
    let opt_off = pe_off + 24;
    let magic = read_u16(&data, opt_off);

    let (is_pe32plus, epoff, iboff, subsys_off, sec_off) = match magic {
        0x10b => (false, 16u32, 28u32, 68u32, 96u32),
        0x20b => (true, 16u32, 24u32, 72u32, 112u32),
        _ => { return None; }
    };

    let entry = read_u32(&data, opt_off + epoff);
    let image_base = if is_pe32plus { read_u64(&data, opt_off + iboff) } else { read_u32(&data, opt_off + iboff) as u64 };
    let size_img = read_u32(&data, opt_off + 56);
    let size_code = read_u32(&data, opt_off + 20);
    let subsys = read_u16(&data, opt_off + subsys_off);

    let subsys_str = match subsys {
        1 => "NATIVE", 2 => "WINDOWS_GUI", 3 => "WINDOWS_CUI",
        5 => "OS2_CUI", 7 => "POSIX_CUI", 9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION", 11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER", 13 => "EFI_ROM", 14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => "Unknown",
    };

    let pe_type = if is_pe32plus { "PE32+" } else { "PE32" };

    let mut sections = Vec::new();
    for i in 0..num_sec {
        let s_off = (sec_off + (i as u32) * 40) as usize;
        if s_off + 40 > data.len() { break; }

        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&data[s_off..s_off + 8]);
        let name = String::from_utf8_lossy(&name_bytes).trim_end_matches('\0').to_string();

        let vs = read_u32(&data, s_off as u32 + 8);
        let va = read_u32(&data, s_off as u32 + 12);
        let rs = read_u32(&data, s_off as u32 + 16);
        let ra = read_u32(&data, s_off as u32 + 20);
        let ch = read_u32(&data, s_off as u32 + 36);

        let sec_data = if ra > 0 && rs > 0 {
            let end = (ra + rs).min(data.len() as u32);
            data[ra as usize..end as usize].to_vec()
        } else {
            Vec::new()
        };

        sections.push(PESection {
            name, virtual_size: vs, virtual_address: va,
            raw_size: rs, raw_address: ra, characteristics: ch, data: sec_data,
        });
    }

    Some(PEInfo {
        data,
        machine: machine_str.into(),
        num_sections: num_sec,
        timestamp,
        pe_type: pe_type.into(),
        entry_point: entry,
        image_base,
        size_of_image: size_img,
        size_of_code: size_code,
        subsystem: subsys_str.into(),
        characteristics: pe_chars_desc(chars),
        sections,
        is_pe32plus,
        pe_offset: pe_off,
    })
}

fn rva_to_raw(info: &PEInfo, rva: u32) -> Option<u32> {
    for sec in &info.sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size {
            if sec.raw_address == 0 { return None; }
            return Some(rva - sec.virtual_address + sec.raw_address);
        }
    }
    None
}

pub fn parse_imports(info: &PEInfo) -> Vec<ImportEntry> {
    let mut result = Vec::new();

    let dir_off = if info.is_pe32plus { 112 } else { 96 };
    let import_rva = read_u32(&info.data, info.pe_offset + 24 + dir_off);
    if import_rva == 0 { return result; }

    let imp_raw = match rva_to_raw(info, import_rva) {
        Some(r) => r,
        None => return result,
    };

    let mut off = imp_raw as usize;
    loop {
        if off + 20 > info.data.len() { break; }
        let ilt = read_u32(&info.data, off as u32);
        let name_rva = read_u32(&info.data, off as u32 + 4);
        if ilt == 0 && name_rva == 0 { break; }

        let dll_name = if name_rva != 0 {
            let dll_raw = match rva_to_raw(info, name_rva) {
                Some(r) => r as usize,
                None => { off += 20; continue; }
            };
            let end = dll_raw;
            let mut e = end;
            while e < info.data.len() && info.data[e] != 0 { e += 1; }
            String::from_utf8_lossy(&info.data[end..e]).to_string()
        } else { String::new() };

        let mut thunk = ilt;
        if thunk == 0 {
            thunk = read_u32(&info.data, off as u32 + 12);
        }

        while thunk != 0 {
            if thunk & 0x80000000 != 0 {
                result.push(ImportEntry {
                    dll: dll_name.clone(),
                    name: format!("ord({})", thunk & 0xFFFF),
                });
            } else {
                let func_raw = match rva_to_raw(info, thunk) {
                    Some(r) => r as usize + 2,
                    None => { break; }
                };
                let mut e = func_raw;
                while e < info.data.len() && info.data[e] != 0 { e += 1; }
                let func_name = String::from_utf8_lossy(&info.data[func_raw..e]).to_string();
                result.push(ImportEntry { dll: dll_name.clone(), name: func_name });
            }

            off += 20;
            if off + 20 > info.data.len() { break; }
            thunk = read_u32(&info.data, off as u32);
            if thunk == 0 {
                off += 12;
                break;
            }
        }

        off += 20;
    }

    result
}

pub fn parse_exports(info: &PEInfo) -> Vec<ExportEntry> {
    let mut result = Vec::new();
    let dir_off = if info.is_pe32plus { 112 } else { 96 };
    let export_rva = read_u32(&info.data, info.pe_offset + 24 + dir_off + 8);
    if export_rva == 0 { return result; }

    let exp_raw = match rva_to_raw(info, export_rva) {
        Some(r) => r,
        None => return result,
    } as usize;

    let num_names = read_u32(&info.data, exp_raw as u32 + 24);
    let addr_rva = read_u32(&info.data, exp_raw as u32 + 28);
    let name_rva = read_u32(&info.data, exp_raw as u32 + 32);

    let addr_raw = match rva_to_raw(info, addr_rva) {
        Some(r) => r as usize,
        None => return result,
    };
    let name_ptr_raw = match rva_to_raw(info, name_rva) {
        Some(r) => r as usize,
        None => return result,
    };

    for i in 0..num_names.min(10000) {
        let npr = name_ptr_raw + (i as usize) * 4;
        if npr + 4 > info.data.len() { break; }
        let nr = read_u32(&info.data, npr as u32);
        let nraw = match rva_to_raw(info, nr) {
            Some(r) => r as usize,
            None => continue,
        };
        let mut e = nraw;
        while e < info.data.len() && info.data[e] != 0 { e += 1; }
        let name = String::from_utf8_lossy(&info.data[nraw..e]).to_string();

        let func_addr = read_u32(&info.data, (addr_raw + (i as usize) * 4) as u32);
        result.push(ExportEntry {
            name,
            address: format!("0x{:X}", info.image_base + func_addr as u64),
        });
    }

    result
}
