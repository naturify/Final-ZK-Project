use std::{error::Error, fs, path::PathBuf};

use clap::Parser;
use group_core::PrivateInput;
use group_methods::GROUP_ELF;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Output file path to save the receipt.
    #[clap(short = 'r', long, value_parser, default_value = "./receipt.bin", value_hint = clap::ValueHint::FilePath)]
    receipt: PathBuf,
    /// Output file path to write the ciphertext
    #[clap(short = 'k', long, value_parser, default_value = "./keys.bin", value_hint = clap::ValueHint::FilePath)]
    key_file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

   

    // Give the private input to the guest.
    let input = PrivateInput {
       

    };

    // Make the ExecutorEnv
    let env = ExecutorEnv::builder().write(&input)?.build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(env, GROUP_ELF).unwrap().receipt;

    // Save the receipt & signature to disk so it can be sent to the verifier.
    fs::write(&args.receipt, bincode::serialize(&receipt).unwrap())?;
    fs::write(
        &args.key_file,
        bincode::serialize(&[ser_manager_key]).unwrap(),
    )?;
    println!("Success! Saved the receipt & signature");

    Ok(())
}
