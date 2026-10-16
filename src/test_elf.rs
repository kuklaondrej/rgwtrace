//! Hand-built ELF images for tests that need an object file but no compiler.

/// A minimal little-endian ELF64 relocatable image holding `sections`
/// (`(name, sh_type, sh_flags, contents)`), plus the `.shstrtab` it needs. Enough for
/// `object` to parse and hand back section data -- no symbols, no DWARF.
pub(crate) fn tiny_elf(sections: &[(&str, u32, u64, Vec<u8>)]) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::new();
    for (name, _, _, _) in sections {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let mut body = Vec::new();
    let mut placed = Vec::new();
    for (_, _, _, contents) in sections {
        placed.push((64 + body.len() as u64, contents.len() as u64));
        body.extend_from_slice(contents);
    }
    let shstrtab_offset = 64 + body.len() as u64;
    body.extend_from_slice(&shstrtab);
    while body.len() % 8 != 0 {
        body.push(0);
    }
    let shoff = 64 + body.len() as u64;
    let shnum = sections.len() as u16 + 2;

    let mut elf = Vec::new();
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    elf.extend_from_slice(&1u16.to_le_bytes()); // ET_REL
    elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&shoff.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&shnum.to_le_bytes());
    elf.extend_from_slice(&(shnum - 1).to_le_bytes()); // e_shstrndx
    elf.extend_from_slice(&body);

    let mut header = |name: u32, kind: u32, flags: u64, offset: u64, size: u64| {
        elf.extend_from_slice(&name.to_le_bytes());
        elf.extend_from_slice(&kind.to_le_bytes());
        elf.extend_from_slice(&flags.to_le_bytes());
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        elf.extend_from_slice(&offset.to_le_bytes());
        elf.extend_from_slice(&size.to_le_bytes());
        elf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
        elf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        elf.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
    };
    header(0, 0, 0, 0, 0);
    for ((name_offset, (_, kind, flags, _)), (offset, size)) in
        name_offsets.iter().zip(sections).zip(&placed)
    {
        header(*name_offset, *kind, *flags, *offset, *size);
    }
    header(shstrtab_name, 3, 0, shstrtab_offset, shstrtab.len() as u64); // SHT_STRTAB
    elf
}
