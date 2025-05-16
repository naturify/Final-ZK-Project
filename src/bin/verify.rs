use std::{error::Error, fs, path::PathBuf};

use clap::Parser;
use group_core::Journal;
use group_methods::GROUP_ID;
use risc0_zkvm::Receipt;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Input file path to fetch the receipt.
    #[clap(short = 'r', long, value_parser, default_value = "./receipt.bin", value_hint = clap::ValueHint::FilePath)]
    receipt: PathBuf,
    /// Input file path to parse the signature
    #[clap(short = 'k', long, value_parser, default_value = "./keys.bin", value_hint = clap::ValueHint::FilePath)]
    key_file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Load and verify the receipt file.
    let receipt: Receipt = bincode::deserialize(&fs::read(&args.receipt)?)?;
    receipt.verify(GROUP_ID)?;

    let journal: Journal = receipt.journal.decode()?;

    let ext_manager_key: Vec<u8> = bincode::deserialize(&fs::read(&args.key_file)?)?;

    assert_eq!(journal.manager_key, ext_manager_key, "Manager key in the journal does not match the external signature");


    //TODO: Initialize your signature with what is read from signature.bin
    // with something like "= bincode::deserialize(&fs::read(&args.key_file)?)?;"

    //************************************YOUR CODE STARTS HERE************************************

    // TODO: Check the consistency of whatever signature received in Journal is the same as in the signature.bin

    //*************************************YOUR CODE ENDS HERE*************************************

    println!("Successfully verified the proof of signature",);
    Ok(())
}
