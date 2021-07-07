#[allow(dead_code)]

use crate::emu::{Arch, PreArch, VmExit};
use crate::mmu::{Mmu, Perm, VirtAddr};
use crate::mmu::{PERM_READ, PERM_EXEC};

use crate::syscall;

use std::convert::TryFrom;

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

    /// Memory obj
    memory: Mmu,
}

impl PreArch for RiscV {
    fn new(mmu: Mmu) -> Box<Self> {
        Box::new(RiscV {
            registers: [0u64; NUM_REGISTERS],
            memory: mmu,
        })
    }

    fn fork(old_arch: &dyn Arch) -> Box<Self> {
        Box::new(RiscV {
            registers: <[u64; NUM_REGISTERS]>::try_from(
                           old_arch.get_register_state().clone()).unwrap(),
            memory: old_arch.fork_memory(),
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

    fn get_register(&mut self, reg: Register) -> u64 {
        if reg != Register::Zero {
            return self.get_register_raw(reg as usize).unwrap()
        }
        0
    }

    /// Translate RiscV syscall numbers into the proper syscall handler,
    /// and arguments / return values.
    fn handle_syscall(&mut self) -> Result<i64, VmExit> {
        let nr_syscall = self.get_register(Register::A7);

        let a0 = self.get_register(Register::A0);
        let a1 = self.get_register(Register::A1);
        let a2 = self.get_register(Register::A2);

        return match nr_syscall {
            64  => {
                syscall::write(&self.memory, a0 as i64, VirtAddr(a1 as usize), a2)
            },
            93  => syscall::sys_exit(a0),
            94  => syscall::sys_exit(a0),
            214 => {
                let increment = self.get_register(Register::A0) as i64;
                syscall::sbrk(&mut self.memory, increment)
            },
             _ => Err(VmExit::SyscallNotImplemented(nr_syscall)),
        }
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

    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()> {
        self.registers = <[u64; NUM_REGISTERS]>::try_from(new_regs.clone()).ok()?;
        Some(())
    }

    fn fork_memory(&self) -> Mmu {
        self.memory.fork()
    }

    fn tick(&mut self) -> Result<(), VmExit> {
        // Fetch the current PC.
        let pc = self.get_register(Register::Pc);
        // Fetch the current instruction
        let addr = VirtAddr(pc as usize);
        let inst = mmu_read_perms!(self.memory, addr, Perm(PERM_EXEC), u32)?;

        let opcode = inst & 0b1111111;
        //DEBUG
      //  print!("Opcode: {:07b} PC: {:x?}\n", opcode, pc);

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
                        let val = mmu_read!(self.memory, addr, i8)?;
                        self.set_register(inst.rd, val as i64 as u64);
                    },
                    0b001 => {
                        // LH: Load half word
                        let val = mmu_read!(self.memory, addr, i16)?;
                        self.set_register(inst.rd, val as i64 as u64);
                    },
                    0b010 => {
                        // LW: Load word
                        let val = mmu_read!(self.memory, addr, i32)?;
                        self.set_register(inst.rd, val as i64 as u64);
                    },
                    0b100 => {
                        // LBU: Load byte unsigned.
                        let val = mmu_read!(self.memory, addr, u8)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    0b101 => {
                        // LHU: Load half word unsigned
                        let val = mmu_read!(self.memory, addr, u16)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    0b110 => {
                        // LWU: Load word unsigned
                        let val = mmu_read!(self.memory, addr, u32)?;
                        self.set_register(inst.rd, val as u64);
                    },
                    0b011 => {
                        // LD: Load double word
                        let val = mmu_read!(self.memory, addr, i64)?;
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
                        mmu_write!(self.memory, addr, val)?;
                    },
                    0b001 => {
                        // SH: Store half word
                        let val = self.get_register(inst.rs2) as u16;
                        mmu_write!(self.memory, addr, val)?;
                    },
                    0b010 => {
                        // SW: Store word
                        let val = self.get_register(inst.rs2) as u32;
                        mmu_write!(self.memory, addr, val)?;
                    },
                    0b011 => {
                        // SD: Store double word
                        let val = self.get_register(inst.rs2) as u64;
                        mmu_write!(self.memory, addr, val)?;
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
                    (0b0100000, 0b100) => {
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
                    self.handle_syscall()?;
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


