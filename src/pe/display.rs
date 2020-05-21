use std::fmt;
use std::str;

use crate::pe::index;
use crate::pe::header::DataDirectories;
use crate::pe::pe::PE;
use crate::pe::header::Sections;
use crate::pe::section::ImportDirectoryTable;

impl fmt::Display for DataDirectories {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = String::new();
        for (index, data_directory) in (&self.items).iter().enumerate() {
            result.push_str(&*format!("\t DataDirectory [{}]: {{ \n\
                                              \t\tVirtual Address : 0x{:x}, \n\
                                              \t\tSize : {}\n\
                                       \t}}\n",
                                      index::DATADIRECTORIES.get(&index).unwrap(),
                                      data_directory.virtual_address,
                                      data_directory.size)
            );
        }
        write!(f, "{}", result)

    }
}

impl fmt::Display for Sections {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = String::new();
        for section in &self.items {
            result.push_str(&*format!("\t Section : {{ \n \
                                              \t\tName : {},                      \n\
                                              \t\tVirtual size: 0x{:x}            \n\
                                              \t\tVirtual address: 0x{:x}         \n\
                                              \t\tSize of raw data: 0x{:x}        \n\
                                              \t\tPointer to raw data: 0x{:x}     \n\
                                              \t\tPointer to relocations: 0x{:x}  \n\
                                              \t\tPointer to linenumbers: 0x{:x}  \n\
                                              \t\tNumber of relocations: {}       \n\
                                              \t\tNumber of linenumbers: {}       \n\
                                              \t\tCharacteristics: {:b}           \n\
                                              \t}} \n",
                                      str::from_utf8(&section.name.to_le_bytes()).unwrap(),
                                      section.virtual_size,
                                      section.virtual_address,
                                      section.size_of_raw_data,
                                      section.pointer_to_raw_data,
                                      section.pointer_to_relocations,
                                      section.pointer_to_linenumbers,
                                      section.number_of_relocations,
                                      section.number_of_linenumbers,
                                      section.characteristics,
                                      )
            );
        }
        write!(f, "{}", result)

    }
}

impl fmt::Display for ImportDirectoryTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = String::new();
        for import in &self.imports {
            result.push_str(&*format!("\t ImportDirectoryTable : {{ \n \
                                              \t\tImport lookup table RVA: 0x{:x}   \n\
                                              \t\tTime date stamp: {:x}             \n\
                                              \t\tForwarder Chain: 0x{:x}           \n\
                                              \t\tName: 0x{:x}                      \n\
                                              \t\tImport address table RVA: 0x{:x}  \n\
                                              \t}} \n",
                                      import.import_lookup_table_rva,
                                      import.time_date_stamp,
                                      import.forwarder_chain,
                                      import.name,
                                      import.import_address_table_rva,
            )
            );
        }
        write!(f, "{}", result)

    }
}

impl fmt::Display for PE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "DOS signature : {}                    \n\
                PE signature : {}                     \n\
                COFF machine : {}                     \n\
                COFF number_of_section : 0x{:x}       \n\
                COFF size_of_optional_header : 0x{:x} \n\
                COFF characteristics : {:b}           \n\
                Optional signature : {}               \n\
                Major linker version : {}             \n\
                Minor linker version : {}             \n\
                Size of code : 0x{:x}                 \n\
                Base of code: 0x{:x}                  \n\
                Base of data: 0x{:x}                  \n\
                File alignment: {}                    \n\
                Number Of Rva And Sizes: {}           \n\
                Data directories: \n {}               \n\
                Sections: \n {}                       \n\
                Imports: \n {}                        \n
                ",
               str::from_utf8(&self.headers.dos.signature.to_le_bytes()).unwrap(),
               str::from_utf8(&self.headers.pe.signature.to_le_bytes()).unwrap(),
               index::MACHINE.get(&self.headers.coff.machine).unwrap(),
               &self.headers.coff.number_of_section,
               &self.headers.coff.size_of_optional_header,
               &self.headers.coff.characteristics,
               index::PEFORMAT.get(&self.headers.optional.standard_fields.signature).unwrap(),
               &self.headers.optional.standard_fields.major_linker_version,
               &self.headers.optional.standard_fields.minor_linker_version,
               &self.headers.optional.standard_fields.size_of_code,
               &self.headers.optional.standard_fields.base_of_code,
               &self.headers.optional.specific_fields.base_of_data,
               &self.headers.optional.specific_fields.file_alignment,
               &self.headers.optional.specific_fields.number_of_rva_and_sizes,
               &self.headers.optional.data_directories,
               &self.headers.sections,
               &self.import_directory_table
        )
    }
}