#![allow(dead_code)]

pub struct Instr {
    pub address: u64,
    pub mnemonic: String,
    pub size: usize,
    pub bytes: Vec<u8>,
}

const REG32: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { 0 }
    else { u16::from_le_bytes([data[off], data[off + 1]]) }
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { 0 }
    else { u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) }
}

fn read_i32(data: &[u8], off: usize) -> i32 {
    read_u32(data, off) as i32
}

fn is_prefix(b: u8) -> bool {
    matches!(b, 0x66 | 0x67 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0xF0 | 0xF2 | 0xF3)
}

pub fn disassemble(data: &[u8], base_addr: u64, max_instr: usize) -> Vec<Instr> {
    let mut result = Vec::new();
    let mut offset = 0;
    let mut count = 0;

    while offset < data.len() && count < max_instr {
        let addr = base_addr + offset as u64;
        let start = offset;

        while offset < data.len() && is_prefix(data[offset]) {
            offset += 1;
        }
        if offset >= data.len() { break; }

        let opcode = data[offset];

        match opcode {
            0x0F => {
                offset += 1;
                if offset >= data.len() {
                    push(&mut result, addr, start, offset, "db 0x0F");
                    break;
                }
                let op2 = data[offset];
                offset += 1;

                let name = match op2 {
                    0x80..=0x8F => {
                        let names = ["jo","jno","jb","jnb","jz","jnz","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"];
                        if offset + 1 <= data.len() {
                            let disp = data[offset] as i8 as i32;
                            let target = addr + 3 + disp as u64;
                            offset += 1;
                            format!("{} 0x{:X}", names[(op2 - 0x80) as usize], target)
                        } else {
                            names[(op2 - 0x80) as usize].to_string()
                        }
                    },
                    0x31 => "rdtsc".into(),
                    0xA2 => "cpuid".into(),
                    0x30 => "wrmsr".into(),
                    0x32 => "rdmsr".into(),
                    0x34 => "sysenter".into(),
                    0x35 => "sysexit".into(),
                    0x77 => "emms".into(),
                    0x0B => "ud2".into(),
                    0x08 => "invd".into(),
                    0x09 => "wbinvd".into(),
                    0x06 => "clts".into(),
                    0x40..=0x4F => {
                        let names = ["cmovo","cmovno","cmovb","cmovnb","cmovz","cmovnz","cmovbe","cmova","cmovs","cmovns","cmovp","cmovnp","cmovl","cmovge","cmovle","cmovg"];
                        offset += 2;
                        names[(op2 - 0x40) as usize].into()
                    },
                    0xB6 => { offset += 2; "movzx reg, byte [reg]".into() },
                    0xB7 => { offset += 2; "movzx reg, word [reg]".into() },
                    0xBE => { offset += 2; "movsx reg, byte [reg]".into() },
                    0xBF => { offset += 2; "movsx reg, word [reg]".into() },
                    0xAF => { offset += 2; "imul reg, [reg]".into() },
                    0xA3 => { offset += 2; "bt reg, reg".into() },
                    0xAB => { offset += 2; "bts reg, reg".into() },
                    0xC8..=0xCF => {
                        let names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                        format!("bswap {}", names[(op2 - 0xC8) as usize])
                    },
                    _ => format!("db 0x0F, 0x{:02X}", op2),
                };
                push(&mut result, addr, start, offset, &name);
            },

            0x8B | 0x89 | 0x03 | 0x2B | 0x23 | 0x0B | 0x33 | 0x31 | 0x01 | 0x29 | 0x21 | 0x09 | 0x85 => {
                offset += 1;
                if offset + 1 > data.len() { push(&mut result, addr, start, offset, &format!("db 0x{:02X}", opcode)); continue; }
                let modrm = data[offset];
                offset += 1;
                let mod_bits = (modrm >> 6) & 3;
                let reg = ((modrm >> 3) & 7) as usize;
                let rm = (modrm & 7) as usize;

                let op_name = match opcode {
                    0x8B => "mov", 0x89 => "mov", 0x03 => "add", 0x2B => "sub",
                    0x23 => "and", 0x0B => "or", 0x33 => "xor", 0x31 => "xor",
                    0x01 => "add", 0x29 => "sub", 0x21 => "and", 0x09 => "or",
                    0x85 => "test", _ => "db",
                };

                if opcode == 0x85 {
                    if mod_bits == 3 {
                        push(&mut result, addr, start, offset, &format!("test {}, {}", REG32[reg], REG32[rm]));
                    }
                    continue;
                }

                let rm_str = if mod_bits == 3 {
                    REG32[rm].to_string()
                } else {
                    let base = if rm == 4 {
                        if offset >= data.len() { offset += 1; "sib".into() }
                        else {
                            let sib = data[offset]; offset += 1;
                            REG32[(sib & 7) as usize].to_string()
                        }
                    } else { REG32[rm].to_string() };

                    match mod_bits {
                        0 => {
                            if rm == 5 {
                                let disp = read_u32(data, offset); offset += 4;
                                format!("[0x{:08X}]", disp)
                            } else { format!("[{}]", base) }
                        },
                        1 => {
                            let disp = data[offset] as i8 as i32; offset += 1;
                            if disp >= 0 { format!("[{}+0x{:X}]", base, disp) }
                            else { format!("[{}-0x{:X}]", base, -disp) }
                        },
                        _ => {
                            let disp = read_u32(data, offset); offset += 4;
                            format!("[{}+0x{:08X}]", base, disp)
                        },
                    }
                };

                let mnemonic = if opcode == 0x89 {
                    format!("{} {}, {}", op_name, rm_str, REG32[reg])
                } else {
                    format!("{} {}, {}", op_name, REG32[reg], rm_str)
                };
                push(&mut result, addr, start, offset, &mnemonic);
            },

            0xB8..=0xBF => {
                let idx = (opcode - 0xB8) as usize;
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1);
                    offset += 5;
                    push(&mut result, addr, start, offset, &format!("mov {}, 0x{:08X}", REG32[idx], imm));
                } else { offset += 1; push(&mut result, addr, start, offset, &format!("db 0x{:02X}", opcode)); }
            },

            0xE8 | 0xE9 => {
                if offset + 5 <= data.len() {
                    let disp = read_u32(data, offset + 1) as i32;
                    let target = addr + 5 + disp as u64;
                    let name = if opcode == 0xE8 { "call" } else { "jmp" };
                    offset += 5;
                    push(&mut result, addr, start, offset, &format!("{} 0x{:X}", name, target));
                } else { offset += 1; push(&mut result, addr, start, offset, "db call/jmp"); }
            },

            0xEB => {
                if offset + 2 <= data.len() {
                    let disp = data[offset + 1] as i8 as i64;
                    let target = addr + 2 + disp as u64;
                    offset += 2;
                    push(&mut result, addr, start, offset, &format!("jmp 0x{:X}", target));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xEB"); }
            },

            0x70..=0x7F => {
                let names = ["jo","jno","jb","jnb","jz","jnz","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg"];
                if offset + 2 <= data.len() {
                    let disp = data[offset + 1] as i8 as i64;
                    let target = addr + 2 + disp as u64;
                    offset += 2;
                    push(&mut result, addr, start, offset, &format!("{} 0x{:X}", names[(opcode - 0x70) as usize], target));
                } else { offset += 1; push(&mut result, addr, start, offset, "db jcc"); }
            },

            0xFF => {
                if offset + 2 <= data.len() {
                    let modrm = data[offset + 1];
                    let reg = ((modrm >> 3) & 7) as usize;
                    let ff_ops = ["inc", "dec", "call", "call far", "jmp", "jmp far", "push"];
                    let op = if reg < ff_ops.len() { ff_ops[reg] } else { "op" };
                    offset += 2;
                    push(&mut result, addr, start, offset, &format!("{} [reg]", op));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xFF"); }
            },

            0x68 => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("push 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x68"); }
            },

            0x6A => {
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("push 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x6A"); }
            },

            0x50..=0x57 => {
                let names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                offset += 1;
                push(&mut result, addr, start, offset, &format!("push {}", names[(opcode - 0x50) as usize]));
            },

            0x58..=0x5F => {
                let names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                offset += 1;
                push(&mut result, addr, start, offset, &format!("pop {}", names[(opcode - 0x58) as usize]));
            },

            0x40..=0x47 => {
                let names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                offset += 1;
                push(&mut result, addr, start, offset, &format!("inc {}", names[(opcode - 0x40) as usize]));
            },

            0x48..=0x4F => {
                let names = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"];
                offset += 1;
                push(&mut result, addr, start, offset, &format!("dec {}", names[(opcode - 0x48) as usize]));
            },

            0xA1 => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("mov eax, [0x{:08X}]", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xA1"); }
            },

            0xA3 => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("mov [0x{:08X}], eax", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xA3"); }
            },

            0xCD => {
                if offset + 2 <= data.len() {
                    let num = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("int 0x{:02X}", num));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xCD"); }
            },

            0x80 => {
                if offset + 3 <= data.len() {
                    let imm = data[offset + 2]; offset += 3;
                    push(&mut result, addr, start, offset, &format!("add byte [reg], 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x80"); }
            },

            0x81 => {
                if offset + 6 <= data.len() {
                    let imm = read_u32(data, offset + 2); offset += 6;
                    push(&mut result, addr, start, offset, &format!("add [reg], 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x81"); }
            },

            0x83 => {
                if offset + 3 <= data.len() {
                    let imm = data[offset + 2] as i8; offset += 3;
                    push(&mut result, addr, start, offset, &format!("add [reg], {}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x83"); }
            },

            0xC7 => {
                if offset + 6 <= data.len() {
                    let imm = read_u32(data, offset + 2); offset += 6;
                    push(&mut result, addr, start, offset, &format!("mov [reg], 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xC7"); }
            },

            0xC6 => {
                if offset + 3 <= data.len() {
                    let imm = data[offset + 2]; offset += 3;
                    push(&mut result, addr, start, offset, &format!("mov byte [reg], 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xC6"); }
            },

            0x90 => { offset += 1; push(&mut result, addr, start, offset, "nop"); },
            0xC3 => { offset += 1; push(&mut result, addr, start, offset, "ret"); },
            0xCC => { offset += 1; push(&mut result, addr, start, offset, "int3"); },
            0x9C => { offset += 1; push(&mut result, addr, start, offset, "pushfd"); },
            0x9D => { offset += 1; push(&mut result, addr, start, offset, "popfd"); },
            0xF4 => { offset += 1; push(&mut result, addr, start, offset, "hlt"); },
            0xF8 => { offset += 1; push(&mut result, addr, start, offset, "clc"); },
            0xF9 => { offset += 1; push(&mut result, addr, start, offset, "stc"); },
            0xFC => { offset += 1; push(&mut result, addr, start, offset, "cld"); },
            0xFD => { offset += 1; push(&mut result, addr, start, offset, "std"); },
            0xCF => { offset += 1; push(&mut result, addr, start, offset, "iret"); },

            0xC2 | 0xCA => {
                if offset + 3 <= data.len() {
                    let imm = read_u16(data, offset + 1); offset += 3;
                    let n = if opcode == 0xC2 { "retn" } else { "retf" };
                    push(&mut result, addr, start, offset, &format!("{} 0x{:X}", n, imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db ret"); }
            },

            0xB0..=0xB7 => {
                let names = ["al","cl","dl","bl","ah","ch","dh","bh"];
                let idx = (opcode - 0xB0) as usize;
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("mov {}, 0x{:02X}", names[idx], imm));
                } else { offset += 1; push(&mut result, addr, start, offset, &format!("db 0x{:02X}", opcode)); }
            },

            0xE0..=0xE3 => {
                let names = ["loopne","loope","loop","jcxz"];
                if offset + 2 <= data.len() {
                    let disp = data[offset + 1] as i8 as i64;
                    let target = addr + 2 + disp as u64;
                    offset += 2;
                    push(&mut result, addr, start, offset, &format!("{} 0x{:X}", names[(opcode - 0xE0) as usize], target));
                } else { offset += 1; push(&mut result, addr, start, offset, "db loop"); }
            },

            0x91..=0x97 => {
                let names = ["ecx","edx","ebx","esp","ebp","esi","edi"];
                offset += 1;
                push(&mut result, addr, start, offset, &format!("xchg eax, {}", names[(opcode - 0x91) as usize]));
            },

            0x04 => {
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("add al, 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x04"); }
            },

            0x05 => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("add eax, 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x05"); }
            },

            0x2C => {
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("sub al, 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x2C"); }
            },

            0x2D => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("sub eax, 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x2D"); }
            },

            0x34 => {
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("xor al, 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x34"); }
            },

            0x35 => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("xor eax, 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x35"); }
            },

            0x0C => {
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("or al, 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0x0C"); }
            },

            0xA8 => {
                if offset + 2 <= data.len() {
                    let imm = data[offset + 1]; offset += 2;
                    push(&mut result, addr, start, offset, &format!("test al, 0x{:02X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xA8"); }
            },

            0xA9 => {
                if offset + 5 <= data.len() {
                    let imm = read_u32(data, offset + 1); offset += 5;
                    push(&mut result, addr, start, offset, &format!("test eax, 0x{:08X}", imm));
                } else { offset += 1; push(&mut result, addr, start, offset, "db 0xA9"); }
            },

            0xEC => { offset += 1; push(&mut result, addr, start, offset, "in al, dx"); },
            0xED => { offset += 1; push(&mut result, addr, start, offset, "in eax, dx"); },
            0xEE => { offset += 1; push(&mut result, addr, start, offset, "out dx, al"); },
            0xEF => { offset += 1; push(&mut result, addr, start, offset, "out dx, eax"); },

            0xD0..=0xD3 => { offset += 2; push(&mut result, addr, start, offset, "shift [reg]"); },
            0xD8..=0xDF => { offset += 2; push(&mut result, addr, start, offset, "fpu instruction"); },

            _ => {
                offset += 1;
                push(&mut result, addr, start, offset, &format!("db 0x{:02X}", opcode));
            },
        }

        count += 1;
    }

    result
}

fn push(result: &mut Vec<Instr>, addr: u64, start: usize, end: usize, mnemonic: &str) {
    result.push(Instr {
        address: addr,
        mnemonic: mnemonic.to_string(),
        size: end - start,
        bytes: Vec::new(),
    });
}

pub fn disassemble_section(data: &[u8], base: u64, max_instr: usize) -> String {
    let instrs = disassemble(data, base, max_instr);
    let mut out = String::with_capacity(instrs.len() * 80);
    for instr in instrs {
        let hex_str: String = instr.bytes.iter().map(|b| format!("{:02X} ", b)).collect();
        out.push_str(&format!("0x{:016X}:  {:<24}  {}\n", instr.address, hex_str, instr.mnemonic));
    }
    out
}
