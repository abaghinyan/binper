use std::fs::File;
use std::io::Read;

use binper::pe::pe::PE;

fn main() -> binper::error::Result<()> {
    // 32 bit
    let mut f = File::open("samples/pe.exe")?;

    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    let pe:PE = PE::new(&data)?;
    println!("{}", pe);
    Ok(())
}