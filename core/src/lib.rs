use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer};
use rand::Rng;
use rand::rngs::OsRng;

// Helper function to generate a random u128
fn rng() -> impl Rng {
    OsRng
}

#[derive(Debug, Clone, Serialize)] // Added Serialize, Clone is for easier state snapshotting
struct UserIdentity {
    is_banned: bool,
    tickets: Vec<u128>,
    current_internal_nonce: u128, // Object's own internal nonce, part of its state
}

fn calculate_commitment<T: Serialize>(
    object_to_commit: &T, // The object whose state is being committed
    external_commitment_randomness: u128, // The randomness (nonce) for this specific commitment
) -> Result<[u8; 32], String> {
    // Returns a Result to handle potential serialization errors
    // Serialize the object data using bincode
    let serialized_object_data =
        serde_json::to_vec(object_to_commit).map_err(|e| format!("Serialization error: {}", e))?;

    // Initialize the hasher
    let mut hasher = Sha256::new();
    // Update hasher with the serialized object data
    hasher.update(&serialized_object_data);
    // Update hasher with the external commitment randomness
    hasher.update(&external_commitment_randomness.to_le_bytes());

    // Finalize the hash
    let result = hasher.finalize();
    Ok(<[u8; 32]>::try_from(result.as_slice()).expect("SHA-256 output should be 32 bytes"))
}




impl UserIdentity {
    // Constructor to create a new UserIdentity with an initial internal nonce
    fn new(initial_internal_nonce: u128) -> Self {
        UserIdentity {
            is_banned: false,
            tickets: Vec::new(),
            current_internal_nonce: initial_internal_nonce,
        }
    }

    // Method for the user to randomerate a new ticket number for an action
    fn randomerate_ticket(&mut self) -> u128 {
        let new_ticket: u128 = rng().gen();
        self.tickets.push(new_ticket);
        new_ticket
    }

    // Method to check if the user's identity is not currently banned
    fn check_not_banned(&self) -> bool {
        !self.is_banned
    }

    // Method to scan the callbackLedger for the user's tickets.
    // If a ticket is found on the ledger, it implies the action associated with that ticket
    // has been linked back to the user, leading to a ban.
    fn scan_callback_ledger<V>(&mut self, callback_ledger: &HashMap<u128, V>) {
        if self.tickets.is_empty() {
            return;
        }
        for ticket in &self.tickets {
            if callback_ledger.contains_key(ticket) { // note this logic is ban specific, to support multiple kinds of callbacks and/or ones that act differently, you need to change it
                self.ban_identity();
                return; // Stop scanning further for this user once one ticket is found
            }
        }
    }

    // Method to mark the user's identity as banned
    fn ban_identity(&mut self) {
        self.is_banned = true;
    }

    // Method to unban a user's identity
    fn unban_identity(&mut self) {
        self.is_banned = false;
    }

    // Implements the authenticated update logic based on the provided pseudocode
    pub fn process_authenticated_object_update<V>(
        &mut self,
        _committed_object_hash_from_server: [u8; 32],
        _signature_from_server: &Signature,            // Placeholder
        _old_external_commitment_randomness: u128, // Randomness used for the server's commitment
        _new_external_commitment_randomness: u128, // New randomness for the new commitment
        _callback_ledger: &HashMap<u128, V>,
        _vk_server: &SigningKey, // Placeholder for server's verification key
    ) -> Result<(u128, [u8; 32], u128), String> {
        // Returns (new_ticket, new_commitment_hash, old_object_internal_nonce)

        todo!();
    }
}









/// Private input values to used to prove the signature verifies for one of the verification keys



fn register_user(
    user: &UserIdentity,
    _server_vk: &VerifyingKey,        // known ahead of time or fetched out-of-band
    server_sk: &SigningKey,           // only on the *server* side!
) -> (u128, [u8;32], Signature) {
    // 1) client picks external randomness
    let ext_rand: u128 = rng().gen();
    // 2) client computes its commitment
    let commit = calculate_commitment(user, ext_rand)
        .expect("serialize+hash must succeed");
    // 3) server signs it (in reality over the network)
    let sig = server_sk.sign(&commit);
    // 4) server sends you back sig (and you already have vk)
    (ext_rand, commit, sig)
}
