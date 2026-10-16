//! Hand-assembled ELF64 little-endian images for unit tests.
//!
//! Address validation and debuginfo matching depend on exact program-header and
//! symbol-table shapes (non-PIE `p_vaddr != p_offset`, a symbol that is not where
//! an address points, a debug file with a different build ID). A compiler cannot
//! be asked for those shapes portably, and `object`'s writer is not enabled, so
//! the images are built byte by byte here.

pub const PF_X: u32 = 1;
pub const PF_R: u32 = 4;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
const STB_GLOBAL: u8 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOTE: u32 = 7;
const PT_LOAD: u32 = 1;
const EHDR_SIZE: u64 = 64;
const PHDR_SIZE: u64 = 56;
const SHDR_SIZE: u64 = 64;

pub struct Segment {
    pub flags: u32,
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
}

pub struct Section {
    pub name: &'static str,
    pub sh_type: u32,
    pub data: Vec<u8>,
}

pub struct Symbol {
    pub name: &'static str,
    pub value: u64,
    pub st_type: u8,
}

#[derive(Default)]
pub struct TestElf {
    pub e_type: u16,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

impl TestElf {
    /// A PIE (`ET_DYN`) image: GNU ld lays its text out with `p_vaddr == p_offset`.
    pub fn pie(text_offset: u64, text_size: u64) -> Self {
        Self {
            e_type: ET_DYN,
            segments: vec![
                Segment {
                    flags: PF_R,
                    vaddr: 0,
                    offset: 0,
                    filesz: text_offset,
                },
                Segment {
                    flags: PF_R | PF_X,
                    vaddr: text_offset,
                    offset: text_offset,
                    filesz: text_size,
                },
            ],
            ..Self::default()
        }
    }

    /// A classic non-PIE (`ET_EXEC`) image linked at 0x400000: every vaddr is the
    /// file offset plus the base, so passing the vaddr as a uprobe offset is wrong.
    pub fn non_pie(text_offset: u64, text_size: u64) -> Self {
        Self {
            e_type: ET_EXEC,
            segments: vec![
                Segment {
                    flags: PF_R,
                    vaddr: 0x40_0000,
                    offset: 0,
                    filesz: text_offset,
                },
                Segment {
                    flags: PF_R | PF_X,
                    vaddr: 0x40_0000 + text_offset,
                    offset: text_offset,
                    filesz: text_size,
                },
            ],
            ..Self::default()
        }
    }

    pub fn function(mut self, name: &'static str, value: u64) -> Self {
        self.symbols.push(Symbol {
            name,
            value,
            st_type: STT_FUNC,
        });
        self
    }

    pub fn section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let phoff = EHDR_SIZE;
        let mut out = vec![0u8; (phoff + PHDR_SIZE * self.segments.len() as u64) as usize];
        let content_end = self
            .segments
            .iter()
            .map(|segment| segment.offset + segment.filesz)
            .max()
            .unwrap_or(0);
        if (out.len() as u64) < content_end {
            out.resize(content_end as usize, 0xcc);
        }

        // Section index 1 is `.text`, covering the first executable segment, so
        // every symbol has a real defining section (object rejects SHN_ABS ones).
        let text = self
            .segments
            .iter()
            .find(|segment| segment.flags & PF_X != 0);
        let mut shstrtab = vec![0u8];
        let mut headers: Vec<[u64; 10]> = vec![[0; 10]];
        let mut push_name = |name: &str| {
            let index = shstrtab.len() as u64;
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
            index
        };
        let text_name = push_name(".text");
        headers.push([
            text_name,
            SHT_PROGBITS as u64,
            6, // SHF_ALLOC | SHF_EXECINSTR
            text.map_or(0, |segment| segment.vaddr),
            text.map_or(0, |segment| segment.offset),
            text.map_or(0, |segment| segment.filesz),
            0,
            0,
            16,
            0,
        ]);

        let append = |out: &mut Vec<u8>, data: &[u8]| {
            while !out.len().is_multiple_of(8) {
                out.push(0);
            }
            let offset = out.len() as u64;
            out.extend_from_slice(data);
            offset
        };

        for section in &self.sections {
            let name = push_name(section.name);
            let offset = append(&mut out, &section.data);
            headers.push([
                name,
                section.sh_type as u64,
                0,
                0,
                offset,
                section.data.len() as u64,
                0,
                0,
                if section.sh_type == SHT_NOTE { 4 } else { 1 },
                0,
            ]);
        }

        if !self.symbols.is_empty() {
            let mut strtab = vec![0u8];
            let mut symtab = vec![0u8; 24];
            for symbol in &self.symbols {
                let name = strtab.len() as u32;
                strtab.extend_from_slice(symbol.name.as_bytes());
                strtab.push(0);
                symtab.extend_from_slice(&name.to_le_bytes());
                symtab.push((STB_GLOBAL << 4) | symbol.st_type);
                symtab.push(0);
                symtab.extend_from_slice(&1u16.to_le_bytes());
                symtab.extend_from_slice(&symbol.value.to_le_bytes());
                symtab.extend_from_slice(&16u64.to_le_bytes());
            }
            let strtab_index = headers.len() as u64 + 1;
            let symtab_name = push_name(".symtab");
            let symtab_offset = append(&mut out, &symtab);
            headers.push([
                symtab_name,
                SHT_SYMTAB as u64,
                0,
                0,
                symtab_offset,
                symtab.len() as u64,
                strtab_index,
                1,
                8,
                24,
            ]);
            let strtab_name = push_name(".strtab");
            let strtab_offset = append(&mut out, &strtab);
            headers.push([
                strtab_name,
                SHT_STRTAB as u64,
                0,
                0,
                strtab_offset,
                strtab.len() as u64,
                0,
                0,
                1,
                0,
            ]);
        }

        let shstrtab_name = push_name(".shstrtab");
        let shstrtab_index = headers.len() as u16;
        let shstrtab_offset = append(&mut out, &shstrtab);
        headers.push([
            shstrtab_name,
            SHT_STRTAB as u64,
            0,
            0,
            shstrtab_offset,
            shstrtab.len() as u64,
            0,
            0,
            1,
            0,
        ]);

        let shoff = append(&mut out, &[]);
        for header in &headers {
            out.extend_from_slice(&(header[0] as u32).to_le_bytes());
            out.extend_from_slice(&(header[1] as u32).to_le_bytes());
            for value in &header[2..6] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            out.extend_from_slice(&(header[6] as u32).to_le_bytes());
            out.extend_from_slice(&(header[7] as u32).to_le_bytes());
            out.extend_from_slice(&header[8].to_le_bytes());
            out.extend_from_slice(&header[9].to_le_bytes());
        }

        let mut ehdr = Vec::with_capacity(EHDR_SIZE as usize);
        ehdr.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        ehdr.extend_from_slice(&[0; 8]);
        ehdr.extend_from_slice(&self.e_type.to_le_bytes());
        ehdr.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        ehdr.extend_from_slice(&1u32.to_le_bytes());
        ehdr.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        ehdr.extend_from_slice(&phoff.to_le_bytes());
        ehdr.extend_from_slice(&shoff.to_le_bytes());
        ehdr.extend_from_slice(&0u32.to_le_bytes());
        ehdr.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        ehdr.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        ehdr.extend_from_slice(&(self.segments.len() as u16).to_le_bytes());
        ehdr.extend_from_slice(&(SHDR_SIZE as u16).to_le_bytes());
        ehdr.extend_from_slice(&(headers.len() as u16).to_le_bytes());
        ehdr.extend_from_slice(&shstrtab_index.to_le_bytes());
        out[..EHDR_SIZE as usize].copy_from_slice(&ehdr);

        for (index, segment) in self.segments.iter().enumerate() {
            let at = (phoff + PHDR_SIZE * index as u64) as usize;
            let mut phdr = Vec::with_capacity(PHDR_SIZE as usize);
            phdr.extend_from_slice(&PT_LOAD.to_le_bytes());
            phdr.extend_from_slice(&segment.flags.to_le_bytes());
            phdr.extend_from_slice(&segment.offset.to_le_bytes());
            phdr.extend_from_slice(&segment.vaddr.to_le_bytes());
            phdr.extend_from_slice(&segment.vaddr.to_le_bytes());
            phdr.extend_from_slice(&segment.filesz.to_le_bytes());
            phdr.extend_from_slice(&segment.filesz.to_le_bytes());
            phdr.extend_from_slice(&0x1000u64.to_le_bytes());
            out[at..at + PHDR_SIZE as usize].copy_from_slice(&phdr);
        }
        out
    }
}

/// `.note.gnu.build-id` carrying `id`.
pub fn build_id_note(id: &[u8]) -> Section {
    let mut data = Vec::new();
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&(id.len() as u32).to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
    data.extend_from_slice(b"GNU\0");
    data.extend_from_slice(id);
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    Section {
        name: ".note.gnu.build-id",
        sh_type: SHT_NOTE,
        data,
    }
}

/// `.gnu_debuglink` naming `filename` with the given CRC.
pub fn debuglink(filename: &str, crc: u32) -> Section {
    let mut data = filename.as_bytes().to_vec();
    data.push(0);
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    data.extend_from_slice(&crc.to_le_bytes());
    Section {
        name: ".gnu_debuglink",
        sh_type: SHT_PROGBITS,
        data,
    }
}

/// A fresh, empty temp directory for one test.
pub fn temp_dir(name: &str) -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!(
        "rgwtrace-test-elf-{name}-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Hand-built ELF images for tests that need an object file but no compiler.
///
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
