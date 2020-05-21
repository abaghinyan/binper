use std::fs::File;
use std::io::Read;

use lib::pe::pe::PE;

fn main() -> lib::error::Result<()> {
    // 32 bit
    let mut f = File::open("samples/pe.exe")?;

    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    let pe:PE = PE::new(&data)?;
    println!("{}", pe);
    Ok(())
}
