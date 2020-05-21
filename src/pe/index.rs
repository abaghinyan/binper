use std::collections::HashMap;

// Source : https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files

lazy_static!{
/** Machine
    Value 	Description
    0x14c 	Intel 386
    0x8664 	x64
    0x162 	MIPS R3000
    0x168 	MIPS R10000
    0x169 	MIPS little endian WCI v2
    0x183 	old Alpha AXP
    0x184 	Alpha AXP
    0x1a2 	Hitachi SH3
    0x1a3 	Hitachi SH3 DSP
    0x1a6 	Hitachi SH4
    0x1a8 	Hitachi SH5
    0x1c0 	ARM little endian
    0x1c2 	Thumb
    0x1c4 	ARMv7
    0x1d3 	Matsushita AM33
    0x1f0 	PowerPC little endian
    0x1f1 	PowerPC with floating point support
    0x200 	Intel IA64
    0x266 	MIPS16
    0x268 	Motorola 68000 series
    0x284 	Alpha AXP 64-bit
    0x366 	MIPS with FPU
    0x466 	MIPS16 with FPU
    0xebc 	EFI Byte Code
    0x8664 	AMD AMD64
    0x9041 	Mitsubishi M32R little endian
    0xaa64 	ARM64 little endian
    0xc0ee 	clr pure MSIL
    */
    pub static ref MACHINE: HashMap<u16, &'static str> = vec![
        (0x14c, "Intel 386"),
        (0x8664, "x64"),
        (0x162, "MIPS R3000"),
        (0x168, "MIPS R10000"),
        (0x169 , "MIPS little endian WCI v2"),
        (0x183, "old Alpha AXP"),
        (0x184, "Alpha AXP"),
        (0x1a2, "Hitachi SH3"),
        (0x1a3, "Hitachi SH3 DSP"),
        (0x1a6, "Hitachi SH4"),
        (0x1a8, "Hitachi SH5"),
        (0x1c0, "ARM little endian"),
        (0x1c2, "Thumb"),
        (0x1c4, "ARMv7"),
        (0x1d3, "Matsushita AM33"),
        (0x1f0, "PowerPC little endian"),
        (0x1f1, "PowerPC with floating point support"),
        (0x200, "Intel IA64"),
        (0x266, "MIPS16"),
        (0x268, "Motorola 68000 series"),
        (0x284, "Alpha AXP 64-bit"),
        (0x366, "MIPS with FPU"),
        (0x466, "MIPS16 with FPU"),
        (0xebc, "EFI Byte Code"),
        (0x8664, "AMD AMD64"),
        (0x9041, "Mitsubishi M32R little endian"),
        (0xaa64, "ARM64 little endian"),
        (0xc0ee, "clr pure MSIL"),
    ].into_iter().collect();
}

lazy_static! {
/** Characteristics
    Constant Name 	                    Bit Position / Mask 	Description
    IMAGE_FILE_RELOCS_STRIPPED 	        1 / 0x0001 	            Relocation information was stripped from file
    IMAGE_FILE_EXECUTABLE_IMAGE 	    2 / 0x0002 	            The file is executable
    IMAGE_FILE_LINE_NUMS_STRIPPED 	    3 / 0x0004 	            COFF line numbers were stripped from file
    IMAGE_FILE_LOCAL_SYMS_STRIPPED 	    4 / 0x0008 	            COFF symbol table entries were stripped from file
    IMAGE_FILE_AGGRESIVE_WS_TRIM 	    5 / 0x0010 	            Aggressively trim the working set(obsolete)
    IMAGE_FILE_LARGE_ADDRESS_AWARE 	    6 / 0x0020 	            The application can handle addresses greater than 2 GB
    IMAGE_FILE_BYTES_REVERSED_LO 	    8 / 0x0080 	            The bytes of the word are reversed(obsolete)
    IMAGE_FILE_32BIT_MACHINE 	        9 / 0x0100 	            The computer supports 32-bit words
    IMAGE_FILE_DEBUG_STRIPPED 	        10 / 0x0200 	        Debugging information was removed and stored separately in another file
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 	11 / 0x0400 	        If the image is on removable media, copy it to and run it from the swap file
    IMAGE_FILE_NET_RUN_FROM_SWAP 	    12 / 0x0800 	        If the image is on the network, copy it to and run it from the swap file
    IMAGE_FILE_SYSTEM 	                13 / 0x1000 	        The image is a system file
    IMAGE_FILE_DLL 	                    14 / 0x2000 	        The image is a DLL file
    IMAGE_FILE_UP_SYSTEM_ONLY 	        15 / 0x4000 	        The image should only be ran on a single processor computer
    IMAGE_FILE_BYTES_REVERSED_HI 	    16 / 0x8000 	        The bytes of the word are reversed(obsolete)
    */
    pub static ref CHARACTERISTIC: HashMap<u16, &'static str> = vec![
        (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
        (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
        (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
        (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
        (0x0010, "IMAGE_FILE_AGGRESIVE_WS_TRIM"),
        (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
        (0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"),
        (0x0100, "IMAGE_FILE_32BIT_MACHINE"),
        (0x0200, "IMAGE_FILE_DEBUG_STRIPPED"),
        (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
        (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
        (0x1000, "IMAGE_FILE_SYSTEM"),
        (0x2000, "IMAGE_FILE_DLL"),
        (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
        (0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"),
    ].into_iter().collect();
}

lazy_static! {
/** Subsystem
    Constant Name 	                            Value   Description
    IMAGE_SUBSYSTEM_UNKNOWN                     0 	    Unknown subsystem
    IMAGE_SUBSYSTEM_NATIVE 	                    1 	    No subsystem required (device drivers and native system processes)
    IMAGE_SUBSYSTEM_WINDOWS_GUI 	            2 	    Windows graphical user interface (GUI) subsystem
    IMAGE_SUBSYSTEM_WINDOWS_CUI 	            3 	    Windows character-mode user interface (CUI) subsystem
    IMAGE_SUBSYSTEM_OS2_CUI 	                5 	    OS/2 CUI subsystem
    IMAGE_SUBSYSTEM_POSIX_CUI 	                7 	    POSIX CUI subsystem
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 	            9 	    Windows CE system
    IMAGE_SUBSYSTEM_EFI_APPLICATION 	        10 	    Extensible Firmware Interface (EFI) application
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 	11 	    EFI driver with boot services
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 	        12 	    EFI driver with run-time services
    IMAGE_SUBSYSTEM_EFI_ROM 	                13 	    EFI ROM image
    IMAGE_SUBSYSTEM_XBOX 	                    14 	    Xbox system
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 	16 	    Boot application
*/
    pub static ref SUBSYSTEM: HashMap<u16, &'static str> = vec![
        (0, "IMAGE_SUBSYSTEM_UNKNOWN"),
        (1, "IMAGE_SUBSYSTEM_NATIVE"),
        (2, "IMAGE_SUBSYSTEM_WINDOWS_GUI"),
        (3, "IMAGE_SUBSYSTEM_WINDOWS_CUI"),
        (5, "IMAGE_SUBSYSTEM_OS2_CUI"),
        (7, "IMAGE_SUBSYSTEM_POSIX_CUI"),
        (9, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"),
        (10, "IMAGE_SUBSYSTEM_EFI_APPLICATION"),
        (11, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"),
        (12, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"),
        (13, "IMAGE_SUBSYSTEM_EFI_ROM"),
        (14, "IMAGE_SUBSYSTEM_XBOX"),
        (16, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"),
    ].into_iter().collect();
}

lazy_static! {
/** DLLCharacteristics
    Constant Name 	                                Value 	Description
    No constant name 	                            0x0001 	Reserved
    No constant name 	                            0x0002 	Reserved
    No constant name 	                            0x0004 	Reserved
    No constant name 	                            0x0008 	Reserved
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 	        0x0040 	The DLL can be relocated at load time
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 	    0x0080 	Code integrity checks are forced
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT 	            0x0100 	The image is compatible with data execution prevention (DEP)
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 	        0x0200 	The image is isolation aware, but should not be isolated
    IMAGE_DLLCHARACTERISTICS_NO_SEH 	            0x0400 	The image does not use structured exception handling (SEH). No handlers can be called in this image
    IMAGE_DLLCHARACTERISTICS_NO_BIND 	            0x0800 	Do not bind the image
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER 	        0x1000 	The image must be executed within an App container
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 	        0x2000 	A WDM driver
    No constant name 	                            0x4000 	Reserved
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 	0x8000 	The image is terminal server aware
*/
    pub static ref DLLCHARACTERISTIC: HashMap<u16, &'static str> = vec![
        (0x0001, "No constant name"),
        (0x0002, "No constant name"),
        (0x0004, "No constant name"),
        (0x0008, "No constant name"),
        (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
        (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
        (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
        (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"),
        (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"),
        (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"),
        (0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"),
        (0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"),
        (0x4000, "No constant name"),
        (0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"),
    ].into_iter().collect();
}

lazy_static! {
/** PE format
    Signature       PE format
    0x10b           PE32
    0x20b           PE32+
*/
    pub static ref PEFORMAT: HashMap<u16, &'static str> = vec![
        (0x10b, "PE32 (32 bit)"),
        (0x20b, "PE32+ (64 bit)")
    ].into_iter().collect();
}

lazy_static! {
/** Data Directories
    Constant Name 	                        Value 	Description 	                                    Offset PE(32 bit) 	Offset PE32+(64 bit)
    IMAGE_DIRECTORY_ENTRY_EXPORT 	        0 	    Export Directory 	                                96 	                112
    IMAGE_DIRECTORY_ENTRY_IMPORT 	        1 	    Import Directory 	                                104              	120
    IMAGE_DIRECTORY_ENTRY_RESOURCE      	2 	    Resource Directory 	                                112 	            128
    IMAGE_DIRECTORY_ENTRY_EXCEPTION 	    3 	    Exception Directory 	                            120 	            136
    IMAGE_DIRECTORY_ENTRY_SECURITY      	4       Security Directory 	                                128 	            144
    IMAGE_DIRECTORY_ENTRY_BASERELOC 	    5 	    Base Relocation Table 	                            136 	            152
    IMAGE_DIRECTORY_ENTRY_DEBUG 	        6 	    Debug Directory 	                                144 	            160
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 	    7 	    Architecture specific data                      	152 	            168
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR 	    8 	    Global pointer register relative virtual address 	160 	            176
    IMAGE_DIRECTORY_ENTRY_TLS 	            9   	Thread Local Storage directory 	                    168 	            184
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG     	10  	Load Configuration directory 	                    176 	            192
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 	    11  	Bound Import directory 	                            184 	            200
    IMAGE_DIRECTORY_ENTRY_IAT           	12  	Import Address Table 	                            192 	            208
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  	13  	Delay Import table                              	200             	216
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 	14  	COM descriptor table 	                            208             	224
    No constant name 	                    15  	Reserved 	                                        216             	232
*/
    pub static ref DATADIRECTORIES: HashMap<usize, &'static str> = vec![
        (0, "IMAGE_DIRECTORY_ENTRY_EXPORT"),
        (1, "IMAGE_DIRECTORY_ENTRY_IMPORT"),
        (2, "IMAGE_DIRECTORY_ENTRY_RESOURCE"),
        (3, "IMAGE_DIRECTORY_ENTRY_EXCEPTION"),
        (4, "IMAGE_DIRECTORY_ENTRY_SECURITY"),
        (5, "IMAGE_DIRECTORY_ENTRY_BASERELOC"),
        (6, "IMAGE_DIRECTORY_ENTRY_DEBUG"),
        (7, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"),
        (8, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"),
        (9, "IMAGE_DIRECTORY_ENTRY_TLS"),
        (10, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"),
        (11, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"),
        (12, "IMAGE_DIRECTORY_ENTRY_IAT"),
        (13, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"),
        (14, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"),
        (15, "No constant name"),
    ].into_iter().collect();
}

lazy_static! {
/** Section characteristics
    Constant Name 	                    Value 	    Description
    No Constant Name 	                0x00000000 	Reserved
    No Constant Name 	                0x00000001 	Reserved
    No Constant Name 	                0x00000002 	Reserved
    No Constant Name 	                0x00000004 	Reserved
    IMAGE_SCN_TYPE_NO_PAD 	            0x00000008 	The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES
    No Constant Name 	                0x00000010 	Reserved
    IMAGE_SCN_CNT_CODE 	                0x00000020 	The section contains executable code
    IMAGE_SCN_CNT_INITIALIZED_DATA  	0x00000040 	The section contains initialized data
    IMAGE_SCN_CNT_UNINITIALIZED_DATA 	0x00000080 	The section contains uninitialized data
    IMAGE_SCN_LNK_OTHER 	            0x00000100 	Reserved
    IMAGE_SCN_LNK_INFO              	0x00000200 	The section contains comments or other information. This is valid only for object files
    No Constant Name 	                0x00000400 	Reserved
    IMAGE_SCN_LNK_REMOVE               	0x00000800 	The section will not become part of the image. This is valid only for object files
    IMAGE_SCN_LNK_COMDAT            	0x00001000 	The section contains COMDAT data. This is valid only for object files
    No Constant Name 	                0x00002000 	Reserved
    IMAGE_SCN_NO_DEFER_SPEC_EXC     	0x00004000 	Reset speculative exceptions handling bits in the TLB entries for this section
    IMAGE_SCN_GPREL 	                0x00008000 	The section contains data referenced through the global pointer
    No Constant Name                	0x00010000 	Reserved
    IMAGE_SCN_MEM_PURGEABLE         	0x00020000 	Reserved
    IMAGE_SCN_MEM_LOCKED 	            0x00040000 	Reserved
    IMAGE_SCN_MEM_PRELOAD           	0x00080000 	Reserved
    IMAGE_SCN_ALIGN_1BYTES           	0x00100000 	Align data on a 1-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_2BYTES          	0x00200000 	Align data on a 2-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_4BYTES          	0x00300000 	Align data on a 4-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_8BYTES 	            0x00400000 	Align data on a 8-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_16BYTES 	        0x00500000 	Align data on a 16-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_32BYTES 	        0x00600000 	Align data on a 32-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_64BYTES         	0x00700000 	Align data on a 64-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_128BYTES        	0x00800000 	Align data on a 128-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_256BYTES        	0x00900000 	Align data on a 256-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_512BYTES        	0x00A00000 	Align data on a 512-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_1024BYTES       	0x00B00000 	Align data on a 1024-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_2048BYTES 	        0x00C00000 	Align data on a 2048-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_4096BYTES       	0x00D00000 	Align data on a 4096-byte boundary. This is valid only for object files
    IMAGE_SCN_ALIGN_8192BYTES       	0x00E00000 	Align data on a 8192-byte boundary. This is valid only for object files
    IMAGE_SCN_LNK_NRELOC_OVFL       	0x01000000 	The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section
    IMAGE_SCN_MEM_DISCARDABLE       	0x02000000 	The section can be discarded as needed
    IMAGE_SCN_MEM_NOT_CACHED        	0x04000000 	The section cannot be cached
    IMAGE_SCN_MEM_NOT_PAGED 	        0x08000000 	The section cannot be paged
    IMAGE_SCN_MEM_SHARED 	            0x10000000 	The section can be shared in memory
    IMAGE_SCN_MEM_EXECUTE           	0x20000000 	The section can be executed as code
    IMAGE_SCN_MEM_READ 	                0x40000000 	The section can be read
    IMAGE_SCN_MEM_WRITE             	0x80000000 	The section can be written to
*/
    pub static ref SECTIONCHARACTERISTIC: HashMap<u32, &'static str> = vec![
        (0x00000000, "No Constant Name"),
        (0x00000001, "No Constant Name"),
        (0x00000002, "No Constant Name"),
        (0x00000004, "No Constant Name"),
        (0x00000008, "IMAGE_SCN_TYPE_NO_PAD"),
        (0x00000010, "No Constant Name"),
        (0x00000020, "IMAGE_SCN_CNT_CODE"),
        (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
        (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
        (0x00000100, "IMAGE_SCN_LNK_OTHER"),
        (0x00000200, "IMAGE_SCN_LNK_INFO"),
        (0x00000400, "No Constant Name"),
        (0x00000800, "IMAGE_SCN_LNK_REMOVE"),
        (0x00001000, "IMAGE_SCN_LNK_COMDAT"),
        (0x00002000, "No Constant Name"),
        (0x00004000, "IMAGE_SCN_NO_DEFER_SPEC_EXC"),
        (0x00008000, "IMAGE_SCN_GPREL"),
        (0x00010000, "No Constant Name"),
        (0x00020000, "IMAGE_SCN_MEM_PURGEABLE"),
        (0x00040000, "IMAGE_SCN_MEM_LOCKED"),
        (0x00080000, "IMAGE_SCN_MEM_PRELOAD"),
        (0x00100000, "IMAGE_SCN_ALIGN_1BYTES"),
        (0x00200000, "IMAGE_SCN_ALIGN_2BYTES"),
        (0x00300000, "IMAGE_SCN_ALIGN_4BYTES"),
        (0x00400000, "IMAGE_SCN_ALIGN_8BYTES"),
        (0x00500000, "IMAGE_SCN_ALIGN_16BYTES"),
        (0x00600000, "IMAGE_SCN_ALIGN_32BYTES"),
        (0x00700000, "IMAGE_SCN_ALIGN_64BYTES"),
        (0x00800000, "IMAGE_SCN_ALIGN_128BYTES"),
        (0x00900000, "IMAGE_SCN_ALIGN_256BYTES"),
        (0x00A00000, "IMAGE_SCN_ALIGN_512BYTES"),
        (0x00B00000, "IMAGE_SCN_ALIGN_1024BYTES"),
        (0x00C00000, "IMAGE_SCN_ALIGN_2048BYTES"),
        (0x00D00000, "IMAGE_SCN_ALIGN_4096BYTES"),
        (0x00E00000, "IMAGE_SCN_ALIGN_8192BYTES"),
        (0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"),
        (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"),
        (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"),
        (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"),
        (0x10000000, "IMAGE_SCN_MEM_SHARED"),
        (0x20000000, "IMAGE_SCN_MEM_EXECUTE"),
        (0x40000000, "IMAGE_SCN_MEM_READ"),
        (0x80000000, "IMAGE_SCN_MEM_WRITE"),
    ].into_iter().collect();
}
