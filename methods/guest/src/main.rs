use group_core::{Journal, PrivateInput};
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use risc0_zkvm::guest::env;

fn main() {
    let input: PrivateInput = env::read();

    let manager_key = VerifyingKey::from_sec1_bytes(&input.manager_key).unwrap();

    for (i, group_key_bytes) in input.group_keys.iter().enumerate() {
            let manager_signed = Signature::from_slice(&input.sig_of_group_keys[i]).unwrap();

            assert!(
                manager_key.verify(group_key_bytes, &manager_signed).is_ok(),
                "Manager signature on group key {} failed verification",
                i
            );
    }

    let correct_key_bytes = &input.group_keys[input.index];
    let correct_verifying_key = VerifyingKey::from_sec1_bytes(correct_key_bytes).unwrap();
    

    let msg_signature = Signature::from_slice(&input.msg_sig).unwrap();
        assert!(
            correct_verifying_key.verify(&input.msg.clone(), &msg_signature).is_ok(),
            "Message signature verification failed using the key at index {}",
            input.index
        );
    //************************************YOUR CODE STARTS HERE************************************

    // TODO: Add code to verify all the signatures on the 5 group keys and the msg signature indeed verifies for one of the group keys

    //*************************************YOUR CODE ENDS HERE*************************************

    let journal = Journal {
        manager_key: input.manager_key.clone()
        //************************************YOUR CODE STARTS HERE************************************

        // TODO: Add values that will be part of public verification

        //*************************************YOUR CODE ENDS HERE*************************************
    };
    env::commit(&journal);
}
