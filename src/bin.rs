use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use structopt::StructOpt;

use binper::pe::pe::PE;

#[derive(StructOpt)]
struct Cli {
    #[structopt(parse(from_os_str))]
    file_path: PathBuf
}

fn main() -> binper::error::Result<()> {
    let args = Cli::from_args();
    let mut f = File::open(args.file_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    match PE::new(&data) {
        Ok(pe) => println!("{}", pe),
        Err(_e) => eprintln!("Error: problem to parse this file\nMaybe it's not a PE file")
    }

    Ok(())
}
