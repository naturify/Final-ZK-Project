use group_core::{Journal, PrivateInput};
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use risc0_zkvm::guest::env;

fn main() {
    let input: PrivateInput = env::read();


    let journal = Journal {
     
    };
    env::commit(&journal);
}
