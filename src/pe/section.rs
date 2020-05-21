use scroll::{IOread, IOwrite, Pread, Pwrite, SizeWith};

use crate::error;

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct ImportDirectory {
    pub import_lookup_table_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub import_address_table_rva : u32
}

impl ImportDirectory {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ImportDirectoryTable {
    pub imports: Vec<ImportDirectory>
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for ImportDirectoryTable {
    type Error = crate::error::Error;
    fn try_from_ctx(bytes: &'a [u8],  _: scroll::Endian) -> error::Result<(Self, usize)> {
        let mut imports:Vec<ImportDirectory> = Vec::new();
        let offset:&mut usize = &mut 0;
        loop {
            let section: ImportDirectory = ImportDirectory::parse(bytes, offset)?;
            if section.import_lookup_table_rva == 0 &&
                section.time_date_stamp == 0 &&
                section.forwarder_chain == 0 &&
                section.name == 0 &&
                section.import_address_table_rva == 0 {
                break;
            }
            imports.push(section);
        }
        Ok((ImportDirectoryTable { imports }, *offset))
    }
}