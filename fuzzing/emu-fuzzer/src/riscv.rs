use crate::emu::{Arch, PreArch, VmExit};
use crate::mmu::{Mmu, Perm, VirtAddr};
use crate::mmu::{PERM_READ, PERM_EXEC, DIRTY_BLOCK_SIZE};

use crate::syscall;
use crate::files::FilePool;
use crate::util;
use crate::jitcache::JitCache;

use std::process::Command;
use std::convert::TryFrom;
use std::sync::Arc;

/// 64 bit RISC-V registers
const NUM_REGISTERS: usize = 33;
/// See: Chapter 25; RISC-V Assembly Programmer’s Handbook
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Register {
    Zero = 0,   // Zero
    Ra,         // Return addr
    Sp,         // Stack Pointer
    Gp,         // Global Pointer
    Tp,         // Thread Pointer
    T0,         // Temp / alt. link register
    T1,         // Temp
    T2,
    S0,         // Saved register / frame pointer
    S1,         // Saved register
    A0,         // Function args / return values
    A1,
    A2,         // Functions args
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,         // Saved registers
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,         // Temp
    T4,
    T5,
    T6,
    Pc,         // Program counter
}

impl Register {
    pub fn from_u32(a: u32) -> Option<Self> {
        // pain.
        match a {
             0 => Some(Register::Zero),
             1 => Some(Register::Ra),
             2 => Some(Register::Sp),
             3 => Some(Register::Gp),
             4 => Some(Register::Tp),
             5 => Some(Register::T0),
             6 => Some(Register::T1),
             7 => Some(Register::T2),
             8 => Some(Register::S0),
             9 => Some(Register::S1),
            10 => Some(Register::A0),
            11 => Some(Register::A1),
            12 => Some(Register::A2),
            13 => Some(Register::A3),
            14 => Some(Register::A4),
            15 => Some(Register::A5),
            16 => Some(Register::A6),
            17 => Some(Register::A7),
            18 => Some(Register::S2),
            19 => Some(Register::S3),
            20 => Some(Register::S4),
            21 => Some(Register::S5),
            22 => Some(Register::S6),
            23 => Some(Register::S7),
            24 => Some(Register::S8),
            25 => Some(Register::S9),
            26 => Some(Register::S10),
            27 => Some(Register::S11),
            28 => Some(Register::T3),
            29 => Some(Register::T4),
            30 => Some(Register::T5),
            31 => Some(Register::T6),
            32 => Some(Register::Pc),
             _ => None,
        }
    }
}

pub struct RiscV {
    /// Register state
    registers: [u64; NUM_REGISTERS],
}

impl PreArch for RiscV {
    fn new() -> Box<dyn Arch + Send + Sync> {
        Box::new(RiscV {
            registers: [0u64; NUM_REGISTERS],
        })
    }
}

impl RiscV {

    /// Architecture specific set_register routine, that knows about the Register
    /// enum for this arch.
    fn set_register(&mut self, reg: Register, value: u64) {
        if reg != Register::Zero {
            self.set_register_raw(reg as usize, value).unwrap()
        }
    }

    fn get_register(&self, reg: Register) -> u64 {
        if reg != Register::Zero {
            return self.get_register_raw(reg as usize).unwrap()
        }
        0
    }

    /// Translate RiscV syscall numbers into the proper syscall handler,
    /// and arguments / return values.
    fn handle_syscall(&mut self, mmu: &mut Mmu, file_pool: &mut FilePool) -> Result<(), VmExit> {
        let nr_syscall = self.get_register(Register::A7);

        //DEBUG
        //println!("SYSCALL: {}", nr_syscall);

        let a0 = self.get_register(Register::A0);
        let a1 = self.get_register(Register::A1);
        let a2 = self.get_register(Register::A2);

        return match nr_syscall {
            // close
            57 => {
                let ret = syscall::close(a0 as i64)?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
            // lseek
            62  => {
                let ret = syscall::lseek(file_pool, a0 as i64, a1 as i64, a2 as i32)?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
            // read
            63  => {
                let ret = syscall::read(file_pool, mmu, 
                                        a0 as i64, VirtAddr(a1 as usize), a2 as usize)?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
            // write
            64  => {
                let ret = syscall::write(&mmu, a0 as i64, VirtAddr(a1 as usize), a2)?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
            // fstat
            80  => {
                let ret: i64 = syscall::fstat(mmu, &file_pool,
                                              a0 as i64, VirtAddr(a1 as usize))?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
            // exit
            93  => {syscall::exit(a0 as i64)?; Ok(())},
            // exit_group
            94  => {syscall::exit(a0 as i64)?; Ok(())},
            // brk
            214 => {
                let size = self.get_register(Register::A0) as i64;
                let ret = syscall::brk(mmu, size)?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
            // open
            1024 => {
                // Get the pathname as a c string.
                let path = util::get_c_string(&mmu, VirtAddr(a0 as usize))?;
                let ret = syscall::open(file_pool, &path, a1 as i64)?;
                self.set_register(Register::A0, ret as u64);
                Ok(())
            },
             _ => Err(VmExit::SyscallNotImplemented(nr_syscall)),
        }
    }

    fn generate_jit(&mut self, pc: VirtAddr, num_blocks: usize, mmu: &mut Mmu)
        -> Result<String, VmExit> {
        let mut asm = "[bits 64]\n".to_string();
        let mut pc = pc.0 as u64;

        'next_inst: loop {
            // Fetch the current instruction
            let addr = VirtAddr(pc as usize);
            let inst = mmu_read_perms!(mmu, addr, Perm(PERM_EXEC), u32)?;

            let opcode = inst & 0b1111111;

            // Add a label to this instruction
            asm += &format!("inst_pc_{:#x}:\n", pc);
            //DEBUG
            //print!("Opcode: {:07b} PC: {:x?}\n", opcode, pc);


            // Load VM register into a "real" x86 register
            macro_rules! load_reg  {
                ($other: expr, $reg: expr) => {
                    if $reg == Register::Zero {
                        // If reading from zero, force an XOR XOR instead
                        format!("xor {other}, {other}", other = $other)
                    } else {
                        format!("mov {other}, qword [r13 + {reg}*8]\n", 
                                other = $other, reg = $reg as usize)
                    }
                }
            }

            // Store an x86 register or immediate into a VM register.
            macro_rules! store_reg  {
                ($reg: expr, $other: expr) => {
                    if $reg == Register::Zero {
                        String::new() // Ignore stores into the Zero register.
                    } else {
                        format!("mov qword [r13 + {reg}*8], {other}\n", 
                                other = $other, reg = $reg as usize)
                    }
                }
            }

            match opcode {
                0b0110111 => {
                    // LUI: Load Upper Immediate
                    let inst = Utype::from(inst);
                    asm += &store_reg!(inst.rd, inst.imm as i64 as u64);
                },

                0b0010111 => {
                    // AUIPC: Add upper immediate to PC, store result in reg
                    let inst = Utype::from(inst);
                    let val = (inst.imm as i64 as u64).wrapping_add(pc);
                    asm += &format!(r#"
                        mov rax, {val:#x}
                        {store_rd_from_rax}
                    "#, val = val, store_rd_from_rax = store_reg!(inst.rd, "rax"));
                },

                0b1101111 => {
                    // JAL: Jump and store the link address in reg
                    let inst = Jtype::from(inst);
                    let ret  =  pc.wrapping_add(4);
                    let target = pc.wrapping_add(inst.imm as i64 as u64);

                    // Bounds check the JIT target
                    if (target / 4) >= num_blocks as u64 {
                        return Err(VmExit::JitOob);
                    }

                    // First do the link, then lookup the jump target from the JIT map.
                    asm += &format!(r#"
                        mov rax, {ret}
                        {store_rd_from_rax}

                        mov rax, [r14 + {target}]
                        test rax, rax
                        jz .jit_resolve

                        jmp rax

                        .jit_resolve:
                        mov rax, 1
                        mov rdx, {target_pc}
                        ret
                        
                    "#, ret = ret,
                        target = (target / 4) * 8, target_pc = target,
                        store_rd_from_rax = store_reg!(inst.rd, "rax"));
                    break 'next_inst;
                },

                0b1100111 => {
                    // JALR: Jump and link register
                    let inst = Itype::from(inst);
                    match inst.funct3 {
                        0b000 => {
                            let ret = pc.wrapping_add(4);
                            asm += &format!(r#"
                                mov rax, {ret}
                                {store_rd_from_rax}

                                {load_rax_from_rs1}
                                add rax, {imm}

                                shr rax, 2
                                cmp rax, {num_blocks}
                                jae .jit_resolve

                                mov rax, [r14 + rax*8]
                                test rax, rax
                                jz .jit_resolve

                                jmp rax

                                .jit_resolve:
                                {load_rdx_from_rs1}
                                add rdx, {imm}
                                mov rax, 1
                                ret
                                
                            "#, ret = ret, imm = inst.imm,
                                num_blocks = num_blocks,
                                store_rd_from_rax = store_reg!(inst.rd, "rax"),
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs1 = load_reg!("rdx", inst.rs1));
                            break 'next_inst;
                        },
                        _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n", 
                                     inst.funct3, opcode)},
                    }
                },

                0b1100011 => {
                    // BXX: Branch instructions
                    let inst = Btype::from(inst);

                    // Compute the target address
                    let target = pc.wrapping_add(inst.imm as i64 as u64);

                    // Bounds check the JIT target
                    if (target / 4) >= num_blocks as u64 {
                        return Err(VmExit::JitOob);
                    }

                    // Convert RISCV branch types into corresponding x86 jump instructions
                    // (inverted to skip a bounds check)
                    let jmp_type = match inst.funct3 {
                        // BEQ: Branch if EQual
                        0b000 => "jne",
                        // BNQ: Branch if Not eQual
                        0b001 => "je",
                        // BLT: Branch if less than
                        0b100 => "jge",
                        // BGE: Branch if greater of equal
                        0b101 => "jl",
                        // BLTU: Branch if less than (unsigned version)
                        0b110 => "jae",
                        // BGEU: Branch if greater than or equal (unsigned version)
                        0b111 => "jb",
                        _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n", 
                                     inst.funct3, opcode)},
                    };

                    asm += &format!(r#"
                        {load_rax_from_rs1}
                        {load_rdx_from_rs2}

                        cmp rax, rdx
                        {jmp_type} .fallthrough

                        mov rax, [r14 + {target}]
                        test rax, rax
                        jz .jit_resolve

                        jmp rax

                        .jit_resolve:
                        mov rax, 1
                        mov rdx, {target_pc}
                        ret
 
                        .fallthrough:
                    "#, jmp_type = jmp_type,
                        target = (target / 4) * 8, target_pc = target,
                        load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                        load_rdx_from_rs2 = load_reg!("rdx", inst.rs2));
                },

                0b0000011 => {
                    // LX: Load instructions
                    let inst = Itype::from(inst);

                    let (load_type, load_size, reg, size) = match inst.funct3 {
                        0b000 => ("movsx", "byte",  "rax", 1),    // LB : Load byte
                        0b001 => ("movsx", "word",  "rax", 2),    // LH : Load half word
                        0b010 => ("movsx", "dword", "rax", 4),    // LW : Load word
                        0b011 => ("mov",   "qword", "rax", 8),    // LD : Load double word
                        0b100 => ("movzx", "byte",  "rax", 1),    // LBU: Load byte unsigned.
                        0b101 => ("movzx", "word",  "rax", 2),    // LHU: Load half word unsigned
                        0b110 => ("mov",   "dword", "eax", 4),    // LWU: Load word unsigned
                        _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n", 
                                     inst.funct3, opcode)},
                    };

                    asm += &format!(r#"
                        {load_rax_from_rs1}
                        add rax, {imm}

                        ; Bounds check first
                        cmp rax, {memory_len} - {size}
                        ja .fault

                        ; TODO; Perms check here
                        jmp .do_load

                        .fault:
                        mov rcx, rax
                        mov rdx, {pc}
                        mov rax, 4
                        ret
                        
                        .do_load:
                        {load_type} {reg}, {load_size} [r8 + rax]
                        {store_rax_into_rd}
                    "#, imm = inst.imm,
                        load_type = load_type, load_size = load_size, reg = reg,
                        memory_len = mmu.mem_len(), size = size, pc = pc,
                        load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                        store_rax_into_rd = store_reg!(inst.rd, "rax"));
                },
                0b0100011 => {
                    // SX: Store instructions
                    let inst = Stype::from(inst);

                    // Beyond resolving the right mnemonics, we also need to know the size of the
                    // write so we can do perm tracking and make sure the dirtied bytes are
                    // registerd correctly.
                    let (store_type, store_size, reg, size) = match inst.funct3 {
                        0b000 => ("mov", "byte",  "dl",  1),    // SB : Store byte
                        0b001 => ("mov", "word",  "dx",  2),    // SH : Store half word
                        0b010 => ("mov", "dword", "edx", 4),    // SW : Store word
                        0b011 => ("mov", "qword", "rdx", 8),    // SD : Store double word
                        _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n", 
                                     inst.funct3, opcode)},
                    };

                    // DIRTY_BLOCK_SIZE is required to be a power of 2, wich means we can just
                    // shift an address down by `shamt` to get the block idx.
                    let dirty_block_shamt = DIRTY_BLOCK_SIZE.trailing_zeros();

                    asm += &format!(r#"
                        {load_rax_from_rs1}
                        {load_rdx_from_rs2}

                        ; Bounds check first
                        cmp rax, {memory_len} - {size}
                        ja .fault

                        ; TODO; Perms check here
                        jmp .nofault

                        .fault:
                        mov rcx, rax
                        mov rdx, {pc}
                        mov rax, 5
                        ret

                        .nofault:
                        ; Check if this block is already marked dirty (if not, set it)
                        mov rcx, rax
                        shr rcx, {dirty_block_shamt}
                        bts qword [r11], rcx
                        jc .do_store

                        ; The block wasn't marked dirty yet, add its index to the dirty list.
                        mov qword[r10 + r12*8], rcx
                        inc r12
                        
                        .do_store:
                        {store_type} {store_size} [r8 + rax + {imm}], {reg}
                    "#, imm = inst.imm,
                        dirty_block_shamt = dirty_block_shamt,
                        store_type = store_type, store_size = store_size, reg = reg,
                        memory_len = mmu.mem_len(), size = size, pc = pc,
                        load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                        load_rdx_from_rs2 = load_reg!("rdx", inst.rs2));
                 },

                0b0010011 => {
                    // Register-Immediate operations
                    let inst = Itype::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // ADDI: Add immediate to register
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                add rax, {imm}
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                imm = inst.imm);
                        },
                        0b010 => {
                            // SLTI: Set to one if less than imm
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                xor  edx, edx
                                cmp  rax, {imm}
                                setl dl,
                                {store_rdx_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rdx_into_rd = store_reg!(inst.rd, "rdx"),
                                imm = inst.imm);
                        },
                        0b011 => {
                            // SLTIU: Set to one if less than imm (unsigned)
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                xor  edx, edx
                                cmp  rax, {imm}
                                setb dl,
                                {store_rdx_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rdx_into_rd = store_reg!(inst.rd, "rdx"),
                                imm = inst.imm);
                        },
                        0b100 => {
                            // XORI: Xor RS1 with the immediate
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                xor  rax, {imm}
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                imm = inst.imm);
                        },
                        0b110 => {
                            // ORI: Or RS1 with the immediate
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                or  rax, {imm}
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                imm = inst.imm);
                        },
                        0b111 => {
                            // ANDI: AND RS1 with the immediate
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                and  rax, {imm}
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                imm = inst.imm);
                        },
                        0b001 => {
                            let mode = (inst.imm >> 6) & 0b111111;
                            match mode {
                                0b000000 => {
                                    asm += &format!(r#"
                                        {load_rax_from_rs1}
                                        shl  rax, {shamt}
                                        {store_rax_into_rd}
                                    "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                        store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                        shamt = inst.imm & 0b111111);
                                },
                                _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),
                            }
                        },
                        0b101 => {
                            let mode = (inst.imm >> 6) & 0b111111;
                            let shamt = inst.imm & 0b111111;
                            match mode {
                                0b000000 => {
                                    // SRLI: Shift-right logical immediate
                                    asm += &format!(r#"
                                        {load_rax_from_rs1}
                                        shr  rax, {shamt}
                                        {store_rax_into_rd}
                                    "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                        store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                        shamt = shamt);
                                },
                                0b010000 => {
                                    // SRAI: Shift-right arith immediate
                                    asm += &format!(r#"
                                        {load_rax_from_rs1}
                                        sar  rax, {shamt}
                                        {store_rax_into_rd}
                                    "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                        store_rax_into_rd = store_reg!(inst.rd, "rax"),
                                        shamt = shamt);

                                },
                                _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),

                            }
                        },
                        _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n", 
                                     inst.funct3, opcode)},
                    }
                },

                0b0110011 => {
                    // Register-Register operations
                    let inst = Rtype::from(inst);

                    match (inst.funct7, inst.funct3) {
                        (0b0000000, 0b000) => {
                            // ADD: Adds two registers, stores result in rd
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                add rax, rdx
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0100000, 0b000) => {
                            // SUB: Subtracts two registers, stores result in rd
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                sub rax, rdx
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b001) => {
                            // SLL: Shift-left logical
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rcx_from_rs2}
                                shl rax, cl
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rcx_from_rs2 = load_reg!("rcx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b010) => {
                            // SLT: Set less than
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                xor ecx, ecx
                                cmp rax, rdx
                                setl cl
                                {store_rcx_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rcx_into_rd = store_reg!(inst.rd, "rcx"));
                        },
                        (0b0000000, 0b011) => {
                            // SLT: Set less than (unsigned)
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                xor ecx, ecx
                                cmp rax, rdx
                                setb cl
                                {store_rcx_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rcx_into_rd = store_reg!(inst.rd, "rcx"));
                        },
                        (0b0000000, 0b100) => {
                            // XOR: Xor two registers
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                xor rax, rdx
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b101) => {
                            // SRL: Shift-right locical
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rcx_from_rs2}
                                shr rax, cl
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rcx_from_rs2 = load_reg!("rcx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0100000, 0b101) => {
                            // SRA: Shift-right arith.
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rcx_from_rs2}
                                sar rax, cl
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rcx_from_rs2 = load_reg!("rcx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b110) => {
                            // OR: Or two registers
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                or rax, rdx
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b111) => {
                            // AND: AND two registers
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                and rax, rdx
                                {store_rax_into_rd}
                            "#, load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        _ => {panic!(
                                "Unknown (funct7, funct3): ({:#07b}, {:#03b}) in opcode: {:#09b}\n", 
                                inst.funct7, inst.funct3, opcode)},
                    }
                },
                0b0011011 => {
                    // 64 bit register-immediate.
                    let inst = Itype::from(inst);

                    match inst.funct3 {
                        0b000 => {
                            // ADDIW: Add immediate to register
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                add eax, {imm}
                                movsx rax, eax
                                {store_rax_into_rd}
                                "#,
                                imm = inst.imm,
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));

                        },
                        0b001 => {
                            let mode = (inst.imm >> 5) & 0b1111111;
                            match mode {
                                0b0000000 => {
                                    // SLLIW: Shift-left logical immediate
                                    let shamt = inst.imm & 0b11111;
                                    asm += &format!(r#"
                                        {load_rax_from_rs1}
                                        shl eax, {shamt}
                                        movsx rax, eax
                                        {store_rax_into_rd}
                                        "#,
                                        shamt = shamt,
                                        load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                        store_rax_into_rd = store_reg!(inst.rd, "rax"));
                                },
                                _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),
                            }
                        },
                        0b101 => {
                            let mode = (inst.imm >> 5) & 0b1111111;
                            let shamt = inst.imm & 0b11111;
                            match mode {
                                0b0000000 => {
                                    // SRLIW: Shift-right logical immediate
                                    asm += &format!(r#"
                                        {load_rax_from_rs1}
                                        shr eax, {shamt}
                                        movsx rax, eax
                                        {store_rax_into_rd}
                                        "#,
                                        shamt = shamt,
                                        load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                        store_rax_into_rd = store_reg!(inst.rd, "rax"));
                                },
                                0b0100000 => {
                                    // SRAIW: Shift-right arith immediate
                                    asm += &format!(r#"
                                        {load_rax_from_rs1}
                                        sar eax, {shamt}
                                        movsx rax, eax
                                        {store_rax_into_rd}
                                        "#,
                                        shamt = shamt,
                                        load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                        store_rax_into_rd = store_reg!(inst.rd, "rax"));
                                },
                                _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),
                            };
                        },
                        _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n",
                                     inst.funct3, opcode)},
                    }
                },

                0b0111011 => {
                    // Register-Register operations (64 bit)
                    let inst = Rtype::from(inst);

                    match (inst.funct7, inst.funct3) {
                        (0b0000000, 0b000) => {
                            // ADDW: Adds two registers, stores result in rd
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                add eax, edx
                                movsx rax, eax
                                {store_rax_into_rd}
                                "#,
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0100000, 0b000) => {
                            // SUBW: Subtracts two registers, stores result in rd
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rdx_from_rs2}
                                sub eax, edx
                                movsx rax, eax
                                {store_rax_into_rd}
                                "#,
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rdx_from_rs2 = load_reg!("rdx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b001) => {
                            // SLLW: Shift-left logical
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rcx_from_rs2}
                                shl eax, cl
                                movsx rax, eax
                                {store_rax_into_rd}
                                "#,
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rcx_from_rs2 = load_reg!("rcx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0000000, 0b101) => {
                            // SRLW: Shift-right locical
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rcx_from_rs2}
                                shr eax, cl
                                movsx rax, eax
                                {store_rax_into_rd}
                                "#,
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rcx_from_rs2 = load_reg!("rcx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        },
                        (0b0100000, 0b101) => {
                            // SRAW: Shift-right arith.
                            asm += &format!(r#"
                                {load_rax_from_rs1}
                                {load_rcx_from_rs2}
                                sar eax, cl
                                movsx rax, eax
                                {store_rax_into_rd}
                                "#,
                                load_rax_from_rs1 = load_reg!("rax", inst.rs1),
                                load_rcx_from_rs2 = load_reg!("rcx", inst.rs2),
                                store_rax_into_rd = store_reg!(inst.rd, "rax"));
                        }
                        _ => {panic!(
                                "Unknown (funct7, funct3): ({:#07b}, {:#03b}) in opcode: {:#09b}\n",
                                inst.funct7, inst.funct3, opcode)},
                    }
                },

                0b0001111 => {
                    let inst = Itype::from(inst);
                    match inst.funct3 {
                        0b000 => {
                            //FENCE
                        }
                        _ => unreachable!(),
                    }
                },
                0b1110011 => {
                    if        inst == 0b00000000000000000000000001110011 {
                        // ECALL
                        asm += &format!(r#"
                            mov rax, 2
                            mov rdx, {pc}
                            ret
                        "#, pc = pc.wrapping_add(4));
                    } else if inst == 0b00000000000100000000000001110011 {
                        // EBREAK
                        asm += &format!(r#"
                            mov rax, 3
                            mov rdx, {pc}
                            ret
                        "#, pc = pc);
                    } else {
                        unreachable!();
                    }
                },

                _ => {panic!("Unknown opcode: {:#09b}\n", opcode)},
            }

            // Update the program counter to the next instruction
            pc += 4;
        }
        // Return the assembly we generated.
        Ok(asm)
    }
}

impl Arch for RiscV {

    fn get_register_raw(&self, reg: usize) -> Option<u64> {
        if reg >= NUM_REGISTERS {
            return None;
        }
        Some(self.registers[reg])
    }

    fn set_entry(&mut self, value: u64) {
        self.registers[Register::Pc as usize] = value;
    }

    fn set_stackp(&mut self, value: u64) {
        self.registers[Register::Sp as usize] = value;
    }

    fn set_register_raw(&mut self, reg: usize, value: u64) -> Option<()> {
        if reg >= NUM_REGISTERS {
            return None;
        }

        self.registers[reg] = value;
        Some(())
    }

    fn get_register_state(&self) -> &[u64] {
        &(self.registers)
    }

    fn get_program_counter(&self) -> u64 {
        self.get_register(Register::Pc)
    }

    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()> {
        self.registers = <[u64; NUM_REGISTERS]>::try_from(new_regs.clone()).ok()?;
        Some(())
    }

    fn fork(&self) -> Box<dyn Arch + Send + Sync> {
        Box::new(RiscV {
            registers: <[u64; NUM_REGISTERS]>::try_from(
                           self.get_register_state().clone()).unwrap(),
        })
    }

    fn tick(&mut self, mmu: &mut Mmu, file_pool: &mut FilePool) -> Result<(), VmExit> {
        // Fetch the current PC.
        let pc = self.get_register(Register::Pc);
        // Fetch the current instruction
        let addr = VirtAddr(pc as usize);
        let inst = mmu_read_perms!(mmu, addr, Perm(PERM_EXEC), u32)?;

        let opcode = inst & 0b1111111;
        //DEBUG
        //print!("Opcode: {:07b} PC: {:x?}\n", opcode, pc);

        match opcode {
            0b0110111 => {
                // LUI: Load Upper Immediate
                let inst = Utype::from(inst);
                self.set_register(inst.rd, inst.imm as i64 as u64);
            },

            0b0010111 => {
                // AUIPC: Add upper immediate to PC, store result in reg
                let inst = Utype::from(inst);
                self.set_register(inst.rd, (inst.imm as i64 as u64).wrapping_add(pc));
            },

            0b1101111 => {
                // JAL: Jump and store the link address in reg
                let inst = Jtype::from(inst);
                // Save the return address in reg
                self.set_register(inst.rd, pc.wrapping_add(4));
                // Jump by adding to the PC reg
                self.set_register(Register::Pc, pc.wrapping_add(inst.imm as i64 as u64));
                return Ok(());
            },

            0b1100111 => {
                // JALR: Jump and link register
                let inst = Itype::from(inst);
                match inst.funct3 {
                    0b000 => {
                        let target = self.get_register(inst.rs1)
                            .wrapping_add(inst.imm as i64 as u64);
                        // Save the return addr
                        self.set_register(inst.rd, pc.wrapping_add(4));
                        // Jump to target
                        self.set_register(Register::Pc, target);
                        return Ok(());
                    },
                    _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n",
                                 inst.funct3, opcode)},
                }
            },

            0b1100011 => {
                // BXX: Branch instructions
                let inst = Btype::from(inst);

                let rs1 = self.get_register(inst.rs1);
                let rs2 = self.get_register(inst.rs2);

                match inst.funct3 {
                    0b000 => {
                        // BEQ: Branch if EQual
                        if rs1 == rs2 {
                            self.set_register(Register::Pc,
                                              pc.wrapping_add(inst.imm as i64 as u64));
                            return Ok(());
                        }
                    },
                    0b001 => {
                        // BNQ: Branch if Not eQual
                        if rs1 != rs2 {
                            self.set_register(Register::Pc,
                                              pc.wrapping_add(inst.imm as i64 as u64));
                            return Ok(());
                        }
                    },
                    0b100 => {
                        // BLT: Branch if less than
                        if (rs1 as i64) < (rs2 as i64) {
                            self.set_register(Register::Pc,
                                              pc.wrapping_add(inst.imm as i64 as u64));
                            return Ok(());
                        }
                    },
                    0b101 => {
                        // BGE: Branch if greater of equal
                        if rs1 as i64 >= rs2 as i64 {
                            self.set_register(Register::Pc,
                                              pc.wrapping_add(inst.imm as i64 as u64));
                            return Ok(());
                        }
                    },
                    0b110 => {
                        // BLTU: Branch if less than (unsigned version)
                        if (rs1 as u64) < (rs2 as u64) {
                            self.set_register(Register::Pc,
                                              pc.wrapping_add(inst.imm as i64 as u64));
                            return Ok(());
                        }
                    },
                    0b111 => {
                        // BGEU: Branch if greater than or equal (unsigned version)
                        if (rs1 as u64) >= (rs2 as u64) {
                            self.set_register(Register::Pc,
                                              pc.wrapping_add(inst.imm as i64 as u64));
                            return Ok(());
                        }
                    },
                    _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n", 
                                 inst.funct3, opcode)},
                }
            },

            0b0000011 => {
                // LX: Load instructions
                let inst = Itype::from(inst);

                // Compute the address
                let addr = VirtAddr(self.get_register(inst.rs1)
                                    .wrapping_add(inst.imm as i64 as u64) as usize);

                match inst.funct3 {
                    0b000 => {
                        // LB: Load byte
                        let val = mmu_read!(mmu, addr, i8)?;
                        self.set_register(inst.rd, val as i64 as u64);
                    },
                    0b001 => {
                        // LH: Load half word
                        let val = mmu_read!(mmu, addr, i16)?;
                        self.set_register(inst.rd, val as i64 as u64);
                    },
                    0b010 => {
                        // LW: Load word
                        let val = mmu_read!(mmu, addr, i32)?;
                        self.set_register(inst.rd, val as i64 as u64);
                    },
                    0b100 => {
                        // LBU: Load byte unsigned.
                        let val = mmu_read!(mmu, addr, u8)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    0b101 => {
                        // LHU: Load half word unsigned
                        let val = mmu_read!(mmu, addr, u16)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    0b110 => {
                        // LWU: Load word unsigned
                        let val = mmu_read!(mmu, addr, u32)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    0b011 => {
                        // LD: Load double word
                        let val = mmu_read!(mmu, addr, i64)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n",
                                 inst.funct3, opcode)},
                }
            },
            0b0100011 => {
                // SX: Store instructions
                let inst = Stype::from(inst);

                // Compute the address
                let addr = VirtAddr(self.get_register(inst.rs1)
                                    .wrapping_add(inst.imm as i64 as u64) as usize);
                match inst.funct3 {
                    0b000 => {
                        // SB: Store byte
                        let val = self.get_register(inst.rs2) as u8;
                        mmu_write!(mmu, addr, val)?;
                    },
                    0b001 => {
                        // SH: Store half word
                        let val = self.get_register(inst.rs2) as u16;
                        mmu_write!(mmu, addr, val)?;
                    },
                    0b010 => {
                        // SW: Store word
                        let val = self.get_register(inst.rs2) as u32;
                        mmu_write!(mmu, addr, val)?;
                    },
                    0b011 => {
                        // SD: Store double word
                        let val = self.get_register(inst.rs2) as u64;
                        mmu_write!(mmu, addr, val)?;
                    },
                    _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n",
                                 inst.funct3, opcode)},
                }
            },

            0b0010011 => {
                // Register-Immediate operations
                let inst = Itype::from(inst);
                let rs1 = self.get_register(inst.rs1);
                let imm = inst.imm as i64 as u64;

                match inst.funct3 {
                    0b000 => {
                        // ADDI: Add immediate to register
                        self.set_register(inst.rd, rs1.wrapping_add(imm));
                    },
                    0b010 => {
                        // SLTI: Set to one if less than imm
                        if (rs1 as i64) < (imm as i64) {
                            self.set_register(inst.rd, 1);
                        } else {
                            self.set_register(inst.rd, 0);
                        }
                    },
                    0b011 => {
                        // SLTIU: Set to one if less than imm (unsigned)
                        if (rs1 as u64) < (imm as u64) {
                            self.set_register(inst.rd, 1);
                        } else {
                            self.set_register(inst.rd, 0);
                        }
                    },
                    0b100 => {
                        // XORI: Xor RS1 with the immediate
                        self.set_register(inst.rd, rs1 ^ imm);
                    },
                    0b110 => {
                        // ORI: Or RS1 with the immediate
                        self.set_register(inst.rd, rs1 | imm);
                    },
                    0b111 => {
                        // ANDI: AND RS1 with the immediate
                        self.set_register(inst.rd, rs1 & imm);
                    },
                    0b001 => {
                        let mode = (inst.imm >> 6) & 0b111111;
                        match mode {
                            0b000000 => {
                                // SLLI: Shift-left logical immediate
                                let shamt = inst.imm & 0b111111;
                                self.set_register(inst.rd, rs1 << shamt);
                            },
                            _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),
                        }
                    },
                    0b101 => {
                        let mode = (inst.imm >> 6) & 0b111111;
                        let shamt = inst.imm & 0b111111;
                        match mode {
                            0b000000 => {
                                // SRLI: Shift-right logical immediate
                                self.set_register(inst.rd, rs1 >> shamt);
                            },
                            0b010000 => {
                                // SRAI: Shift-right arith immediate
                                self.set_register(inst.rd, ((rs1 as i64) >> shamt) as u64);
                            },
                            _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),

                        }
                    },
                    _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n",
                                 inst.funct3, opcode)},
                }
            },

            0b0110011 => {
                // Register-Register operations
                let inst = Rtype::from(inst);

                let rs1 = self.get_register(inst.rs1);
                let rs2 = self.get_register(inst.rs2);

                match (inst.funct7, inst.funct3) {
                    (0b0000000, 0b000) => {
                        // ADD: Adds two registers, stores result in rd
                        self.set_register(inst.rd, rs1.wrapping_add(rs2));
                    },
                    (0b0100000, 0b000) => {
                        // SUB: Subtracts two registers, stores result in rd
                        self.set_register(inst.rd, rs1.wrapping_sub(rs2));
                    },
                    (0b0000000, 0b001) => {
                        // SLL: Shift-left logical
                        let shamt = rs2 & 0b11111;
                        self.set_register(inst.rd, rs1 << shamt);
                    },
                    (0b0000000, 0b010) => {
                        // SLT: Set less than
                        if (rs1 as i64) < (rs2 as i64) {
                            self.set_register(inst.rd, 1);
                        } else {
                            self.set_register(inst.rd, 0);
                        }
                    },
                    (0b0000000, 0b011) => {
                        // SLT: Set less than (unsigned)
                        if (rs1 as u64) < (rs2 as u64) {
                            self.set_register(inst.rd, 1);
                        } else {
                            self.set_register(inst.rd, 0);
                        }
                    },
                    (0b0000000, 0b100) => {
                        // XOR: Xor two registers
                        self.set_register(inst.rd, rs1 ^ rs2);
                    },
                    (0b0000000, 0b101) => {
                        // SRL: Shift-right locical
                        let shamt = rs2 & 0b11111;
                        self.set_register(inst.rd, rs1 >> shamt);
                    },
                    (0b0100000, 0b101) => {
                        // SRA: Shift-right arith.
                        let shamt = rs2 & 0b11111;
                        self.set_register(inst.rd, ((rs1 as i64) >> shamt) as u64);
                    },
                    (0b0000000, 0b110) => {
                        // OR: Or two registers
                        self.set_register(inst.rd, rs1 | rs2);
                    },
                    (0b0000000, 0b111) => {
                        // AND: AND two registers
                        self.set_register(inst.rd, rs1 & rs2);
                    },
                    _ => {panic!(
                            "Unknown (funct7, funct3): ({:#07b}, {:#03b}) in opcode: {:#09b}\n",
                            inst.funct7, inst.funct3, opcode)},
                }
            },
            0b0011011 => {
                // 64 bit register-immediate.
                let inst = Itype::from(inst);
                let rs1 = self.get_register(inst.rs1) as i32;
                let imm = inst.imm;

                match inst.funct3 {
                    0b000 => {
                        // ADDIW: Add immediate to register
                        self.set_register(inst.rd, rs1.wrapping_add(imm) as i32 as i64 as u64);
                    },
                    0b001 => {
                        let mode = (inst.imm >> 5) & 0b1111111;
                        match mode {
                            0b0000000 => {
                                // SLLI: Shift-left logical immediate
                                let shamt = inst.imm & 0b11111;
                                self.set_register(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                            },
                            _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),
                        }
                    },
                    0b101 => {
                        let mode = (inst.imm >> 5) & 0b1111111;
                        let shamt = inst.imm & 0b11111;
                        match mode {
                            0b0000000 => {
                                // SRLIW: Shift-right logical immediate
                                self.set_register(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                            },
                            0b0100000 => {
                                // SRAIW: Shift-right arith immediate
                                self.set_register(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                            },
                            _ => panic!("Unknown shift mode in opcode {:#09b}\n", opcode),
                        };
                    },
                    _ => {panic!("Unknown funct3: {:#03b} in opcode: {:#09b}\n",
                                 inst.funct3, opcode)},
                }
            },

            0b0111011 => {
                // Register-Register operations (64 bit)
                let inst = Rtype::from(inst);

                let rs1 = self.get_register(inst.rs1) as u32;
                let rs2 = self.get_register(inst.rs2) as u32;

                match (inst.funct7, inst.funct3) {
                    (0b0000000, 0b000) => {
                        // ADDW: Adds two registers, stores result in rd
                        self.set_register(inst.rd, rs1.wrapping_add(rs2) as i32 as i64 as u64);
                    },
                    (0b0100000, 0b000) => {
                        // SUBW: Subtracts two registers, stores result in rd
                        self.set_register(inst.rd, rs1.wrapping_sub(rs2) as i32 as i64 as u64);
                    },
                    (0b0000000, 0b001) => {
                        // SLLW: Shift-left logical
                        let shamt = rs2 & 0b11111;
                        self.set_register(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                    },
                    (0b0000000, 0b101) => {
                        // SRLW: Shift-right locical
                        let shamt = rs2 & 0b11111;
                        self.set_register(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                    },
                    (0b0100000, 0b101) => {
                        // SRAW: Shift-right arith.
                        let shamt = rs2 & 0b11111;
                        self.set_register(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                    }
                    _ => {panic!(
                            "Unknown (funct7, funct3): ({:#07b}, {:#03b}) in opcode: {:#09b}\n",
                            inst.funct7, inst.funct3, opcode)},
                }
            },

            0b0001111 => {
                let inst = Itype::from(inst);
                match inst.funct3 {
                    0b000 => {
                        //FENCE
                    }
                    _ => unreachable!(),
                }
            },
            0b1110011 => {
                if        inst == 0b00000000000000000000000001110011 {
                    // ECALL
                    self.handle_syscall(mmu, file_pool)?;
                } else if inst == 0b00000000000100000000000001110011 {
                    // EBREAK
                } else {
                    unreachable!();
                }
            },

            _ => {panic!("Unknown opcode: {:#09b}\n", opcode)},
        }

        // Update the program counter to the next instruction
        self.set_register(Register::Pc, pc.wrapping_add(4));
        Ok(())
    }


    // TODO; Non of this is particularly Arch-specific, so it can be moved to emu / jitcache
    fn run_jit(&mut self, mmu: &mut Mmu, file_pool: &mut FilePool,
               jit_cache: &Arc<JitCache>) -> Result<(), VmExit> {

        // use a temp directory to assemble in.
        let tmpdir = std::env::temp_dir().join("fuzzy");
        std::fs::create_dir_all(&tmpdir).expect("Failed to create tmp dir for JIT cache");
        let thread_id = std::thread::current().id().as_u64();

        loop {
            let pc       = self.get_register(Register::Pc);
            let jit_addr = jit_cache.lookup(VirtAddr(pc as usize));

            // Get the addresses we need to run the JIT:
            let (mem, perms, dirty, dirty_bitmap) = mmu.jit_addresses();
            let translation_table = jit_cache.translation_table();

            let jit_addr = match jit_addr {
                None => {
                    // Go through each instruction in the block to emit some x86_64 assembly
                    let asm = self.generate_jit(VirtAddr(pc as usize),
                                                jit_cache.num_blocks(), mmu)?;

                    let asmfn = tmpdir.join(&format!("tmp-{}.asm", thread_id));
                    let binfn = tmpdir.join(&format!("tmp-{}.bin", thread_id));
                    std::fs::write(&asmfn, &asm).expect("Failed to drop ASM to disk");
                    let nasm_res = Command::new("nasm")
                        .args(&["-f", "bin", "-o", binfn.to_str().unwrap(),
                                asmfn.to_str().unwrap()])
                        .status()
                        .expect("Failed to run `nasm`, is it in your PATH?");

                    // Read the binary that nasm just generated for us.
                    let tmp = std::fs::read(binfn).expect("Failed to read NASM output.");

                    // Add the fresh JIT code to the mapping.
                    jit_cache.add_mapping(VirtAddr(pc as usize), &tmp)
                },
                Some(jit_addr) => jit_addr,
            };

            let mut num_dirty_inuse = mmu.dirty_len();
            let exit_code    : u64;
            let reentry      : u64;
            let guest_address: u64;

            unsafe {

                // Hop into the JIT
                asm!(r#"
                   call {entry}
                "#,
                entry = in(reg) jit_addr,
                in("r8")  mem,
                in("r9")  perms,
                in("r10") dirty,
                in("r11") dirty_bitmap,
                inout("r12") num_dirty_inuse,
                in("r13") self.registers.as_ptr(),
                in("r14") translation_table,
                // Let rust known what we potentially clobbered.
                out("rax") exit_code,
                out("rdx") reentry,
                out("rcx") guest_address, // Contains the offending address for read/write faults
                );

                // Update the length of the dirty list, since we potentially added some items
                // to its backing store.
                mmu.set_dirty_len(num_dirty_inuse);
            }

            // DEBUG
            //println!("JIT exited with {:#x}, reentry: {:#x}", exit_code, reentry);
            match exit_code {
                1 => {
                    // Branch decode request, update PC and re-JIT
                    self.set_register(Register::Pc, reentry)
                },
                2 => {
                    // JIT encountered a syscall. Handle it and reenter.
                    // (We need to set PC first, so a syscall can potentially set PC as well,
                    //  like `sigreturn` for example.)
                    self.set_register(Register::Pc, reentry);
                    self.handle_syscall(mmu, file_pool)?;
                },
                4 => {
                    // JIT encountered a read fault, let the fuzzer known we crashed.
                   // TODO; 
                   // - We don't currently pass the read size. Assuming 1 for now
                   // - The crash_handler will request pc to dedupe crashes, which will be
                   //   slightly off, due to lazy updating.
                   //   Setting it here is a bit hacky
                   self.set_register(Register::Pc, reentry);
                   return Err(VmExit::ReadFault(VirtAddr(guest_address as usize), 1))
                },
                5 => {
                    // JIT encountered a write fault, let the fuzzer known we crashed.
                   // TODO; 
                   // - We don't currently pass the read size. Assuming 1 for now
                   // - The crash_handler will request pc to dedupe crashes, which will be
                   //   slightly off, due to lazy updating.
                   //   Setting it here is a bit hacky
                   self.set_register(Register::Pc, reentry);
                   return Err(VmExit::ReadFault(VirtAddr(guest_address as usize), 1))
                },
                x => unimplemented!("JIT Exit code not handled: {}.", x),
            }
        }
       // Err(VmExit::Exit(-1))
    }
}


struct Utype {
    imm: i32,
    rd: Register,
}

impl From<u32> for Utype {
    // Convert the instruction into an immediate / register combo
    fn from(inst: u32) -> Self {
        Utype {
            imm: (inst & !0xfff) as i32,
            rd: Register::from_u32((inst >> 7) & 0b11111).unwrap(),
        }
    }
}

struct Jtype {
    imm: i32,
    rd: Register,
}

impl From<u32> for Jtype {
    // Convert the instruction into an immediate / register combo
    fn from(inst: u32) -> Self {

        let imm20   = (inst >> 31) & 0b1;
        let imm101  = (inst >> 21) & 0b1111111111;
        let imm11   = (inst >> 20) & 0b1;
        let imm1912 = (inst >> 12) & 0b11111111;

        let imm = (imm20 << 20)| (imm1912 << 12) | (imm11 << 11) | (imm101 << 1);
        // Sign-extent by shifting up/down
        let imm = ((imm as i32) << 11) >> 11;


        Jtype {
            imm: imm,
            rd: Register::from_u32((inst >> 7) & 0b11111).unwrap(),
        }
    }
}


struct Itype {
    imm   : i32,
    rs1   : Register,
    funct3: u32,
    rd    : Register,
}

impl From<u32> for Itype {
    // Convert the instruction into an immediate / register combo
    fn from(inst: u32) -> Self {
        Itype {
            imm   : (inst as i32) >> 20,
            rs1   : Register::from_u32((inst >> 15) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
            rd    : Register::from_u32((inst >> 7) & 0b11111).unwrap(),
        }
    }
}

struct Btype {
    imm   : i32,
    rs1   : Register,
    rs2   : Register,
    funct3: u32,
}

impl From<u32> for Btype {
    // Convert the instruction into an immediate / register combo
    fn from(inst: u32) -> Self {

        let imm12  = (inst >> 31) & 0b1;
        let imm105 = (inst >> 25) & 0b111111;
        let imm41  = (inst >> 8)  & 0b1111;
        let imm11  = (inst >> 7)  & 0b1;

        let imm = (imm12 << 12) | (imm11 << 11) | (imm105 << 5) | (imm41 << 1);
        let imm = ((imm as i32) << 19) >> 19;

        Btype {
            imm   : imm,
            rs1   : Register::from_u32((inst >> 15) & 0b11111).unwrap(),
            rs2   : Register::from_u32((inst >> 20) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
        }
    }
}

struct Stype {
    imm   : i32,
    rs1   : Register,
    rs2   : Register,
    funct3: u32,
}

impl From<u32> for Stype {

    fn from(inst: u32) -> Self {
        let imm115 = (inst >> 25) & 0b1111111;
        let imm40  = (inst >> 7)  & 0b11111;

        let imm = (imm115 << 5) | imm40;
        let imm = ((imm as i32) << 20) >> 20;

        Stype {
            imm   : imm,
            rs1   : Register::from_u32((inst >> 15) & 0b11111).unwrap(),
            rs2   : Register::from_u32((inst >> 20) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
        }
    }
}

struct Rtype {
    rs1   : Register,
    rs2   : Register,
    rd    : Register,
    funct3: u32,
    funct7: u32,
}

impl From<u32> for Rtype {

    fn from(inst: u32) -> Self {

        Rtype {
            rs1   : Register::from_u32((inst >> 15) & 0b11111).unwrap(),
            rs2   : Register::from_u32((inst >> 20) & 0b11111).unwrap(),
            rd    : Register::from_u32((inst >> 7) & 0b11111).unwrap(),
            funct3: (inst >> 12) & 0b111,
            funct7: (inst >> 25) & 0b1111111,
        }
    }
}


