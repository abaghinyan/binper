use std::str;

use scroll::{IOread, IOwrite, Pread, Pwrite, SizeWith};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::error;
use crate::pe::index;
/// DOS header present in all PE binaries
pub const DOS_HEADER_SIGNATURE: u16 = 0x5A4D;
pub const DOS_HEADER_FILE_ADD_OF_RELOC_TABLE: u16 = 0x0040;

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct Dos {
    pub signature: u16, /// MS DOS header signature: 5a4d (MZ)
    pub last_size: u16,
    pub pages_in_file: u16,
    pub relocations: u16,
    pub header_size_in_paragraph: u16,
    pub min_extra_paragraph_needed: u16,
    pub max_extra_paragraph_needed: u16,
    pub ss: u16,
    pub sp: u16,
    pub checksum: u16,
    pub ip: u16,
    pub cs: u16,
    pub file_add_of_reloc_table: u16,
    pub overlay_number: u16,
    pub reserved_1: [u16; 4],
    pub oem_identifier: u16,
    pub oem_information: u16,
    pub reserved_2: [u16; 10],
    pub pe_header_offset: u32
}

impl Serialize for Dos {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("Dos", 19)?;
        state.serialize_field("signature", str::from_utf8(&self.signature.to_le_bytes()).expect("Invalid UTF-8"))?;
        state.serialize_field("last_size", &self.last_size)?;
        state.serialize_field("pages_in_file", &format!("0x{:x}", &self.pages_in_file))?;
        state.serialize_field("relocations", &format!("0x{:x}", &self.relocations))?;
        state.serialize_field("header_size_in_paragraph", &format!("0x{:x}", &self.header_size_in_paragraph))?;
        state.serialize_field("min_extra_paragraph_needed", &format!("0x{:x}", &self.min_extra_paragraph_needed))?;
        state.serialize_field("max_extra_paragraph_needed", &format!("0x{:x}", &self.max_extra_paragraph_needed))?;
        state.serialize_field("ss", &format!("0x{:x}", &self.ss))?;
        state.serialize_field("sp", &format!("0x{:x}", &self.sp))?;
        state.serialize_field("checksum", &format!("0x{:x}", &self.checksum))?;
        state.serialize_field("ip", &format!("0x{:x}", &self.ip))?;
        state.serialize_field("cs", &format!("0x{:x}", &self.cs))?;
        state.serialize_field("file_add_of_reloc_table", &format!("0x{:x}", &self.file_add_of_reloc_table))?;
        state.serialize_field("overlay_number", &format!("0x{:x}", &self.overlay_number))?;
        state.serialize_field("reserved_1", &self.reserved_1)?;
        state.serialize_field("oem_identifier", &format!("0x{:x}", &self.oem_identifier))?;
        state.serialize_field("oem_information", &format!("0x{:x}", &self.oem_information))?;
        state.serialize_field("reserved_2", &self.reserved_2)?;
        state.serialize_field("pe_header_offset", &format!("0x{:x}", &self.pe_header_offset))?;
        state.end()
    }
}

impl Dos {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

/// PE header present in all PE binaries
pub const PE_HEADER_SIGNATURE: u32 = 0x00004550;

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct PE {
    pub signature: u32,
}

impl Serialize for PE {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("PE", 1)?;
        let signature_raw = String::from_utf8(self.signature.to_le_bytes().to_vec()).expect("Invalid UTF-8");
        state.serialize_field("signature", signature_raw.trim_matches(char::from(0)))?;
        state.end()
    }
}

impl PE {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct COFF {
    pub machine: u16,
    pub number_of_section: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl Serialize for COFF {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("COFF", 7)?;
        state.serialize_field("machine", index::MACHINE.get(&self.machine).unwrap())?;
        state.serialize_field("number_of_section", &self.number_of_section)?;
        let time_date_stamp_naive = NaiveDateTime::from_timestamp(self.time_date_stamp as i64,0);
        let time_date_stamp_utc: DateTime<Utc> = DateTime::from_utc(time_date_stamp_naive, Utc);
        state.serialize_field("time_date_stamp", &time_date_stamp_utc.format("%Y-%m-%d %H:%M:%S").to_string())?;
        state.serialize_field("pointer_to_symbol_table", &format!("0x{:x}", &self.pointer_to_symbol_table))?;
        state.serialize_field("number_of_symbols", &self.number_of_symbols)?;
        state.serialize_field("size_of_optional_header", &self.size_of_optional_header)?;
        state.serialize_field("characteristics", &format!("0x{:b}", &self.characteristics))?;
        state.end()
    }
}

impl COFF {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct StandardFields {
    pub signature: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
}

impl Serialize for StandardFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("StandardFields", 8)?;
        state.serialize_field("signature", index::PEFORMAT.get(&self.signature).unwrap())?;
        state.serialize_field("major_linker_version", &self.major_linker_version)?;
        state.serialize_field("minor_linker_version", &self.minor_linker_version)?;
        state.serialize_field("size_of_code", &self.size_of_code)?;
        state.serialize_field("size_of_code", &self.size_of_initialized_data)?;
        state.serialize_field("size_of_code", &self.size_of_uninitialized_data)?;
        state.serialize_field("address_of_entry_point", &format!("0x{:x}", &self.address_of_entry_point))?;
        state.serialize_field("base_of_code", &format!("0x{:x}", &self.base_of_code))?;
        state.end()
    }
}


impl StandardFields {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct SpecificFields32 {
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith)]
pub struct SpecificFields64 {
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}



#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct SpecificFields {
    pub base_of_data: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

impl Serialize for SpecificFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("SpecificFields", 22)?;
        state.serialize_field("base_of_data", &format!("0x{:x}", &self.base_of_data))?;
        state.serialize_field("image_base", &format!("0x{:x}", &self.image_base))?;
        state.serialize_field("section_alignment", &format!("0x{:x}", &self.section_alignment))?;
        state.serialize_field("file_alignment", &format!("0x{:x}", &self.file_alignment))?;
        state.serialize_field("major_os_version", &self.major_os_version)?;
        state.serialize_field("minor_os_version", &self.minor_os_version)?;
        state.serialize_field("major_image_version", &self.major_image_version)?;
        state.serialize_field("minor_image_version", &self.minor_image_version)?;
        state.serialize_field("major_subsystem_version", &self.major_os_version)?;
        state.serialize_field("minor_subsystem_version", &self.minor_subsystem_version)?;
        state.serialize_field("reserved", &format!("0x{:x}", &self.reserved))?;
        state.serialize_field("size_of_image", &self.size_of_image)?;
        state.serialize_field("size_of_headers", &self.size_of_headers)?;
        state.serialize_field("checksum", &format!("0x{:x}", &self.checksum))?;
        state.serialize_field("subsystem", index::SUBSYSTEM.get(&self.subsystem).unwrap())?;
        state.serialize_field("dll_characteristics", &format!("0x{:b}", &self.dll_characteristics))?;
        state.serialize_field("size_of_stack_reserve", &self.size_of_stack_reserve)?;
        state.serialize_field("size_of_stack_commit", &self.size_of_stack_commit)?;
        state.serialize_field("size_of_heap_reserve", &self.size_of_heap_reserve)?;
        state.serialize_field("size_of_heap_commit", &self.size_of_heap_commit)?;
        state.serialize_field("loader_flags", &self.loader_flags)?;
        state.serialize_field("number_of_rva_and_sizes", &self.number_of_rva_and_sizes)?;
        state.end()
    }
}
impl From<SpecificFields32> for SpecificFields {
    fn from(specific_fields_32: SpecificFields32) -> Self {
        SpecificFields {
            base_of_data: u32::from(specific_fields_32.base_of_data),
            image_base: u64::from(specific_fields_32.image_base),
            section_alignment: u32::from(specific_fields_32.section_alignment),
            file_alignment: u32::from(specific_fields_32.file_alignment),
            major_os_version: u16::from(specific_fields_32.major_os_version),
            minor_os_version: u16::from(specific_fields_32.minor_os_version),
            major_image_version: u16::from(specific_fields_32.major_image_version),
            minor_image_version: u16::from(specific_fields_32.minor_image_version),
            major_subsystem_version: u16::from(specific_fields_32.major_subsystem_version),
            minor_subsystem_version: u16::from(specific_fields_32.minor_subsystem_version),
            reserved: u32::from(specific_fields_32.reserved),
            size_of_image: u32::from(specific_fields_32.size_of_image),
            size_of_headers: u32::from(specific_fields_32.size_of_headers),
            checksum: u32::from(specific_fields_32.checksum),
            subsystem: u16::from(specific_fields_32.subsystem),
            dll_characteristics: u16::from(specific_fields_32.dll_characteristics),
            size_of_stack_reserve: u64::from(specific_fields_32.size_of_stack_reserve),
            size_of_stack_commit: u64::from(specific_fields_32.size_of_stack_commit),
            size_of_heap_reserve: u64::from(specific_fields_32.size_of_heap_reserve),
            size_of_heap_commit: u64::from(specific_fields_32.size_of_heap_commit),
            loader_flags: u32::from(specific_fields_32.loader_flags),
            number_of_rva_and_sizes: u32::from(specific_fields_32.number_of_rva_and_sizes),
        }
    }
}

impl From<SpecificFields64> for SpecificFields {
    fn from(specific_fields_64: SpecificFields64) -> Self {
        SpecificFields {
            base_of_data: 0,
            image_base: u64::from(specific_fields_64.image_base),
            section_alignment: u32::from(specific_fields_64.section_alignment),
            file_alignment: u32::from(specific_fields_64.file_alignment),
            major_os_version: u16::from(specific_fields_64.major_os_version),
            minor_os_version: u16::from(specific_fields_64.minor_os_version),
            major_image_version: u16::from(specific_fields_64.major_image_version),
            minor_image_version: u16::from(specific_fields_64.minor_image_version),
            major_subsystem_version: u16::from(specific_fields_64.major_subsystem_version),
            minor_subsystem_version: u16::from(specific_fields_64.minor_subsystem_version),
            reserved: u32::from(specific_fields_64.reserved),
            size_of_image: u32::from(specific_fields_64.size_of_image),
            size_of_headers: u32::from(specific_fields_64.size_of_headers),
            checksum: u32::from(specific_fields_64.checksum),
            subsystem: u16::from(specific_fields_64.subsystem),
            dll_characteristics: u16::from(specific_fields_64.dll_characteristics),
            size_of_stack_reserve: u64::from(specific_fields_64.size_of_stack_reserve),
            size_of_stack_commit: u64::from(specific_fields_64.size_of_stack_commit),
            size_of_heap_reserve: u64::from(specific_fields_64.size_of_heap_reserve),
            size_of_heap_commit: u64::from(specific_fields_64.size_of_heap_commit),
            loader_flags: u32::from(specific_fields_64.loader_flags),
            number_of_rva_and_sizes: u32::from(specific_fields_64.number_of_rva_and_sizes),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32
}

impl Serialize for DataDirectory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("DataDirectory", 2)?;
        state.serialize_field("virtual_address", &format!("0x{:x}", &self.virtual_address))?;
        state.serialize_field("size", &self.size)?;
        state.end()
    }
}

impl DataDirectory {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

pub const MAX_NUMBER_OF_RVA: usize = 16;

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct DataDirectories {
    pub items: Vec<DataDirectory>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, (usize, scroll::Endian)> for DataDirectories {
    type Error = crate::error::Error;
    fn try_from_ctx(bytes: &'a [u8], (nb_rva, _):(usize, scroll::Endian)) -> error::Result<(Self, usize)> {
        let mut items:Vec<DataDirectory> = Vec::new();
        let offset:&mut usize = &mut 0;
        for _ in 0..nb_rva {
            let data_directory: DataDirectory = DataDirectory::parse(bytes, offset)?;
            items.push(data_directory);
        }
        Ok((DataDirectories { items }, *offset))
    }
}

pub const OPTIONAL_HEADER_SIGNATURE_32: u16 = 0x10b;
pub const OPTIONAL_HEADER_SIGNATURE_64: u16 = 0x20b;

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Optional {
    pub standard_fields: StandardFields,
    pub specific_fields: SpecificFields,
    pub data_directories: DataDirectories,
}

impl Optional {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let standard_fields: StandardFields = StandardFields::parse(&bytes, offset)?;
        let specific_fields:SpecificFields = match standard_fields.signature {
            OPTIONAL_HEADER_SIGNATURE_32 => {
                let specific_fields = bytes.gread_with::<SpecificFields32>(offset, scroll::LE)?.into();
                specific_fields
            }
            OPTIONAL_HEADER_SIGNATURE_64 => {
                let specific_fields = bytes.gread_with::<SpecificFields64>(offset, scroll::LE)?.into();
                specific_fields
            }
            _ => return Err(error::Error::BadSignature(u64::from(standard_fields.signature))),
        };
        let data_directories:DataDirectories = bytes.pread_with::<DataDirectories>(*offset, (specific_fields.number_of_rva_and_sizes as usize, scroll::LE))?;
        Ok(Optional {
            standard_fields,
            specific_fields,
            data_directories
        })
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, IOread, IOwrite, SizeWith, Deserialize)]
pub struct Section {
    pub name: u64,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl Serialize for Section {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("Section", 10)?;
        let name_raw = String::from_utf8(self.name.to_le_bytes().to_vec()).expect("Invalid UTF-8");
        state.serialize_field("name", name_raw.trim_matches(char::from(0)))?;
        state.serialize_field("virtual_size", &self.virtual_size)?;
        state.serialize_field("virtual_address", &format!("0x{:x}", &self.virtual_address))?;
        state.serialize_field("size_of_raw_data", &self.size_of_raw_data)?;
        state.serialize_field("pointer_to_raw_data", &format!("0x{:x}", &self.pointer_to_raw_data))?;
        state.serialize_field("pointer_to_relocations", &format!("0x{:x}", &self.pointer_to_relocations))?;
        state.serialize_field("pointer_to_linenumbers", &format!("0x{:x}", &self.pointer_to_linenumbers))?;
        state.serialize_field("number_of_relocations", &self.number_of_relocations)?;
        state.serialize_field("number_of_linenumbers", &self.number_of_linenumbers)?;
        state.serialize_field("characteristics", &format!("{:b}",&self.characteristics))?;
        state.end()
    }
}

impl Section {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        Ok(bytes.gread_with(offset, scroll::LE)?)
    }
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Sections {
    pub items: Vec<Section>
}

impl<'a> scroll::ctx::TryFromCtx<'a, (usize, scroll::Endian)> for Sections {
    type Error = crate::error::Error;
    fn try_from_ctx(bytes: &'a [u8], (nb_sections, _):(usize, scroll::Endian)) -> error::Result<(Self, usize)> {
        let mut items:Vec<Section> = Vec::new();
        let offset:&mut usize = &mut 0;
        for _ in 0..nb_sections {
            let section: Section = Section::parse(bytes, offset)?;
            items.push(section);
        }
        Ok((Sections { items }, *offset))
    }
}

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct Headers {
    pub dos: Dos,
    pub pe: PE,
    pub coff: COFF,
    pub optional: Optional,
    pub sections: Sections,
    pub _offset: usize
}

impl Headers {
    pub fn parse(bytes: &[u8]) -> error::Result<Self> {
        let mut offset_start:usize = 0;
        let dos: Dos = Dos::parse(&bytes,&mut offset_start)?;
        let mut offset:usize = dos.pe_header_offset.clone() as usize;
        let pe:PE = PE::parse(&bytes,&mut offset)?;
        let coff:COFF = COFF::parse(&bytes, &mut offset)?;
        let optional:Optional = Optional::parse(&bytes, &mut offset)?;
        let section_offset: usize = offset + optional.specific_fields.number_of_rva_and_sizes as usize * 8;
        let sections:Sections = bytes.pread_with::<Sections>(section_offset, (coff.number_of_section as usize, scroll::LE))?;
        let _offset = offset + optional.specific_fields.number_of_rva_and_sizes.clone() as usize * 8;
        Ok(Headers {
            dos,
            pe,
            coff,
            optional,
            sections,
            _offset
        })
    }
    pub fn get_import_section (self) -> Option<Section> {
        let image_directory_entry_import:DataDirectory = *self.optional.data_directories.items.get(1)?;
        for section in self.sections.items {
            if section.virtual_address <= image_directory_entry_import.virtual_address &&
                image_directory_entry_import.virtual_address <= section.virtual_address + section.virtual_size {
                return Some(section)
            }
        }
        None
    }
    pub fn get_imports_offset(self) -> Option<usize> {
        let image_directory_entry_import:DataDirectory = self.optional.data_directories.items[1];
        match self.get_import_section() {
            None => return None,
            Some(import_section) => {
                return Some((import_section.pointer_to_raw_data + image_directory_entry_import.virtual_address - import_section.virtual_address) as usize)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Headers, PE_HEADER_SIGNATURE, DOS_HEADER_SIGNATURE, DOS_HEADER_FILE_ADD_OF_RELOC_TABLE, OPTIONAL_HEADER_SIGNATURE_64};

    const PE: [u8; 1008] = [
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
        0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x0F, 0x00, 0x8E, 0xA0, 0xC6, 0x5E, 0x00, 0x6C, 0x00, 0x00,
        0x9D, 0x04, 0x00, 0x00, 0xF0, 0x00, 0x27, 0x00, 0x0B, 0x02, 0x02, 0x1E, 0x00, 0x1E, 0x00, 0x00,
        0x00, 0x38, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0xE0, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x30, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x62, 0x98, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x6C, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x00, 0x00, 0x70, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x81, 0x00, 0x00, 0x98, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,
        0xC8, 0x1C, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x50, 0x60,
        0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x50, 0xC0, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xD0, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x60, 0x40,
        0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x70, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40, 0x2E, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0xF4, 0x01, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40,
        0x2E, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x80, 0x09, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x60, 0xC0, 0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
        0x6C, 0x07, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0xC0,
        0x2E, 0x43, 0x52, 0x54, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0xC0, 0x2E, 0x74, 0x6C, 0x73, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0xC0,
        0x2F, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x50, 0x42, 0x2F, 0x31, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x27, 0x22, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,
        0x2F, 0x33, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD2, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42, 0x2F, 0x34, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE3, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,
        0x2F, 0x35, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x42, 0x2F, 0x37, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x9B, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x6A, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x10, 0x42,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn header() {
        let header = Headers::parse(&&PE[..]).unwrap();
        assert!(header.dos.signature == DOS_HEADER_SIGNATURE);
        assert!(header.dos.file_add_of_reloc_table == DOS_HEADER_FILE_ADD_OF_RELOC_TABLE);
        assert!(header.pe.signature == PE_HEADER_SIGNATURE);
        assert!(header.optional.standard_fields.signature == OPTIONAL_HEADER_SIGNATURE_64);
    }
}