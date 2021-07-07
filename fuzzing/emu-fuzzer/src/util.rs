use crate::emu::VmExit;
use crate::mmu::{Mmu, Perm, VirtAddr};
use crate::mmu::{PERM_WRITE, PERM_READ, PERM_EXEC};

/// Load an elf, return the entry point on success.
pub fn load_elf(binary_path: &str, mmu: &mut Mmu) -> Option<u64> {
    // Read the input file from disk
    let contents = std::fs::read(binary_path).ok()?;

    let binary = goblin::elf::Elf::parse(&contents).ok()?;
    let entry = binary.entry;
    for ph in binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                let virtaddr    = VirtAddr(ph.p_vaddr as usize);
                let mem_size    = ph.p_memsz  as usize;
                let file_size   = ph.p_filesz as usize;
                let file_offset = ph.p_offset as usize;
                mmu.set_permissions(virtaddr, mem_size, Perm(PERM_WRITE))?;

                // Write the file contents to memory
                mmu.write_from(virtaddr, 
                    &contents[file_offset..file_offset.checked_add(file_size)?]).ok()?;

                // Pad with zeros
                if mem_size > file_size {
                    let padding = vec![0u8; mem_size - file_size];
                    mmu.write_from( VirtAddr(virtaddr.0.checked_add(file_size)?), &padding).ok()?;
                }

                let mut permissions = Perm(0);
                // Translate Goblin perms to our custom Perms
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 
                    {permissions.0 |= PERM_EXEC};
                if ph.p_flags & goblin::elf::program_header::PF_W != 0
                    {permissions.0 |= PERM_WRITE};
                if ph.p_flags & goblin::elf::program_header::PF_R != 0
                    {permissions.0 |= PERM_READ};

                // Set the permissions as specified in the Section struct.
                mmu.set_permissions(virtaddr, mem_size, permissions)?;

                // Update the allocator beyond any sections we load, to ensure this memory can't
                // be allocated again.
                mmu.cur_alloc = VirtAddr(std::cmp::max(
                        mmu.cur_alloc.0, 
                        (virtaddr.0 + mem_size + 0xf) & !0xf
                ));
            },
            _ => ()
        }
    }

    Some(entry)
}


/// Helper function to retrieve a null-terminated string from an MMU.
/// Returns an actual Rust String.
///
/// Not particularly efficient, but this should be rare, and it's good enough
/// to test with.
pub fn get_c_string(mmu: &Mmu, addr: VirtAddr) -> Result<String, VmExit> {
    let mut ret: Vec<u8> = Vec::new();
    for i in addr.0.. {
        let c = mmu_read!(mmu, VirtAddr(i), u8)?;
        if c == 0u8 {
            break;
        }
        ret.push(c);
    }
    Ok(String::from_utf8(ret).unwrap())
}

/// Helper function to get the length of a null-terminated string in memory.
pub fn c_strlen(mmu: &Mmu, addr: VirtAddr) -> Result<usize, VmExit> {
    for i in addr.0.. {
        if 0u8 == mmu_read!(mmu, VirtAddr(i), u8)? {
            return Ok(i - addr.0)
        }
    }
    unreachable!()
}
