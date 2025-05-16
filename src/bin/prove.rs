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

    let manager_key = SigningKey::random(&mut OsRng);
    let ser_manager_key = (&*VerifyingKey::from(&manager_key).to_sec1_bytes())
        .into_iter()
        .map(|&x| x)
        .collect::<Vec<u8>>();

    //************************************YOUR CODE STARTS HERE************************************
    // keys should be created like:  let key1 = SigningKey::random(&mut OsRng);

    // TODO: Generate the manager and group of keys (and their signatures), the message, and a single signature.

    //*************************************YOUR CODE ENDS HERE*************************************
    let key1 = SigningKey::random(&mut OsRng);
    let key2 = SigningKey::random(&mut OsRng);
    let key3 = SigningKey::random(&mut OsRng);
    let key4 = SigningKey::random(&mut OsRng);
    let key5 = SigningKey::random(&mut OsRng);

    let message = b"Your account balance is 30";
    let signature: Signature = key2.sign(message);
    let ser_sig = signature
    .to_bytes()
    .as_slice()
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let ser_key1 = (&*VerifyingKey::from(&key1).to_sec1_bytes())
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let manager_signed_key_1: Signature = manager_key.sign(&ser_key1);

    let ser_manager_signed_key_1 = manager_signed_key_1
    .to_bytes()
    .as_slice()
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let ser_key2 = (&*VerifyingKey::from(&key2).to_sec1_bytes())
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let manager_signed_key_2: Signature = manager_key.sign(&ser_key2);

    let ser_manager_signed_key_2 = manager_signed_key_2
    .to_bytes()
    .as_slice()
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let ser_key3 = (&*VerifyingKey::from(&key3).to_sec1_bytes())
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let manager_signed_key_3: Signature = manager_key.sign(&ser_key3);

    let ser_manager_signed_key_3 = manager_signed_key_3
    .to_bytes()
    .as_slice()
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    
    let ser_key4 = (&*VerifyingKey::from(&key4).to_sec1_bytes())
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let manager_signed_key_4: Signature = manager_key.sign(&ser_key4);

    let ser_manager_signed_key_4 = manager_signed_key_4
    .to_bytes()
    .as_slice()
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let ser_key5 = (&*VerifyingKey::from(&key5).to_sec1_bytes())
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();

    let manager_signed_key_5: Signature = manager_key.sign(&ser_key5);

    let ser_manager_signed_key_5 = manager_signed_key_5
    .to_bytes()
    .as_slice()
    .into_iter()
    .map(|&x| x)
    .collect::<Vec<u8>>();


    
    let input = PrivateInput {
        msg: message.to_vec(),
        msg_sig: ser_sig.clone(),
        index: 1,
        group_keys: [ser_key1.clone(), ser_key2.clone(), ser_key3.clone(), ser_key4.clone(), ser_key5.clone()],
        sig_of_group_keys: [ser_manager_signed_key_1.clone(), 
        ser_manager_signed_key_2.clone(), 
        ser_manager_signed_key_3.clone(), 
        ser_manager_signed_key_4.clone(), 
        ser_manager_signed_key_5.clone()],
        manager_key: ser_manager_key.clone()
        //************************************YOUR CODE STARTS HERE************************************

        // TODO: Define the private values you need to prove your signature indeed verifies under one of those keys.

        //*************************************YOUR CODE ENDS HERE*************************************
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
