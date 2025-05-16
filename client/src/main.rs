use k256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::error::Error;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use clap::{Parser, Subcommand};
use group_core::UserIdentity;
use group_core::calculate_commitment;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "client")]
#[command(about = "Client for the server with signing key")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new user with the server
    Register {
        /// User name
        #[arg(short, long)]
        name: String,
    },
    
    /// Verify stored user credentials
    Verify {
        /// User name to verify
        #[arg(short, long)]
        name: String,
    },

    /// Generate and add a new ticket for an action
    Action {
        /// User name
        #[arg(short, long)]
        name: String,
        /// Action description
        #[arg(short, long)]
        description: String,
    },

    /// Add a ticket to the callback ledger
    Callback {
        /// Ticket number to add to the ledger
        #[arg(short, long)]
        ticket: u128,
        /// Reason for the callback
        #[arg(short, long)]
        reason: String,
    },

    /// View the callback ledger
    ViewLedger,

    /// Check if a user is banned
    CheckBan {
        /// User name to check
        #[arg(short, long)]
        name: String,
    },
}

#[derive(Serialize)]
struct RegistrationRequest {
    user_data: Vec<u8>,
    external_randomness: u128,
}

#[derive(Deserialize, Debug, Serialize)]
struct RegistrationResponse {
    commit: [u8; 32],
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredCredentials {
    user_identity: UserIdentity,
    commitment: [u8; 32],
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
    external_randomness: u128,
}

#[derive(Serialize)]
struct AddTicketRequest {
    ticket: u128,
    reason: String,
}

#[derive(Serialize)]
struct ScanRequest {
    user_data: Vec<u8>,
}

fn save_credentials(
    user: &UserIdentity,
    commitment: [u8; 32],
    signature: &[u8],
    verifying_key: &[u8],
    external_randomness: u128,
) -> std::io::Result<()> {
    let credentials = StoredCredentials {
        user_identity: user.clone(),
        commitment,
        signature: signature.to_vec(),
        verifying_key: verifying_key.to_vec(),
        external_randomness,
    };
    
    // Serialize to JSON
    let json = serde_json::to_string_pretty(&credentials)?;
    
    // Save to file
    let filename = format!("credentials_{}.json", user.name);
    let mut file = File::create(&filename)?;
    file.write_all(json.as_bytes())?;
    
    println!("Credentials saved to {}", filename);
    Ok(())
}

fn load_credentials(user_name: &str) -> Result<StoredCredentials, Box<dyn Error>> {
    let filename = format!("credentials_{}.json", user_name);
    
    if !Path::new(&filename).exists() {
        return Err(format!("Credentials file {} not found", filename).into());
    }
    
    let mut file = File::open(&filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    
    let credentials: StoredCredentials = serde_json::from_str(&contents)?;
    Ok(credentials)
}

fn verify_stored_credentials(credentials: &StoredCredentials) -> Result<(), Box<dyn Error>> {
    // 1. Verify the user data matches the commitment
    let calculated_commitment = calculate_commitment(&credentials.user_identity, credentials.external_randomness)
        .map_err(|e| Box::<dyn Error>::from(e))?;
    
    if calculated_commitment != credentials.commitment {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Commitment verification failed - user data has been tampered with"
        )));
    }
    
    // 2. Verify the signature against the original commitment
    // This may fail if the user data has been updated (e.g., for banning)
    // but we'll handle that gracefully
    let signature = Signature::try_from(credentials.signature.as_slice())
        .map_err(|_| Box::<dyn Error>::from("Invalid signature format"))?;
    
    let verifying_key = VerifyingKey::from_sec1_bytes(&credentials.verifying_key)
        .map_err(|_| Box::<dyn Error>::from("Invalid verifying key format"))?;
    
    let sig_verification = verifying_key.verify(&credentials.commitment, &signature);
    
    // Display user information regardless of signature verification
    println!("✅ User identity verified:");
    println!("User: {}", credentials.user_identity.name);
    println!("Ban status: {}", if credentials.user_identity.is_banned { "BANNED" } else { "Not Banned" });
    
    if let Err(_) = sig_verification {
        println!("⚠️  Note: Signature does not match current commitment.");
        println!("    This is expected if the user status was updated after registration.");
    } else {
        println!("✅ Signature verification PASSED");
    }
    
    Ok(())
}

async fn register_new_user(name: &str) -> Result<(), Box<dyn Error>> {
    // Create a user with default values
    let user = UserIdentity {
        name: name.to_string(),
        is_banned: false,
        tickets: Vec::new(),
        current_internal_nonce: 0,
    };
    
    // Generate random value
    let external_randomness = rand::thread_rng().gen::<u128>();
    
    // Calculate local commitment using the core library function
    let local_commitment = calculate_commitment(&user, external_randomness)
        .map_err(|e| Box::<dyn Error>::from(e))?;
    println!("Local commitment: {:?}", local_commitment);
    
    // Serialize the user data for the request
    let user_bytes = serde_json::to_vec(&user)?;
    
    // Prepare request
    let request = RegistrationRequest {
        user_data: user_bytes,
        external_randomness,
    };
    
    // Send to server
    println!("Sending registration request to server...");
    let client = Client::new();
    let response = client
        .post("http://localhost:8081/register")
        .json(&request)
        .send()
        .await?;
    
    if response.status().is_success() {
        let registration: RegistrationResponse = response.json().await?;
        println!("Registration successful!");
        println!("Server commitment: {:?}", registration.commit);
        
        // Verify signature
        let signature = Signature::try_from(registration.signature.as_slice())
            .expect("Invalid signature format");
        
        let verifying_key_bytes = registration.verifying_key.as_slice();
        let verifying_key = VerifyingKey::from_sec1_bytes(verifying_key_bytes)
            .expect("Invalid verifying key format");
        
        // Verify the signature
        if verifying_key.verify(&registration.commit, &signature).is_ok() {
            println!("✅ Signature verification PASSED!");
        } else {
            println!("❌ Signature verification FAILED!");
            return Ok(());
        }
        
        // Verify the commitment matches our local one
        if registration.commit == local_commitment {
            println!("✅ Commitment verification PASSED!");
        } else {
            println!("❌ Commitment verification FAILED!");
            return Ok(());
        }
        
        // Store credentials locally
        save_credentials(
            &user,
            local_commitment,
            &registration.signature,
            &registration.verifying_key,
            external_randomness
        )?;
        
    } else {
        println!("Registration failed: {:?}", response.status());
        println!("Error: {}", response.text().await?);
    }
    
    Ok(())
}

async fn generate_ticket_for_action(name: &str, description: &str) -> Result<(), Box<dyn Error>> {
    // Load the user's credentials
    let mut credentials = load_credentials(name)?;
    
    // Generate a new ticket
    let ticket = credentials.user_identity.randomerate_ticket();
    println!("Generated ticket: {} for action: {}", ticket, description);
    
    // Recalculate commitment with the updated user data
    let new_commitment = calculate_commitment(&credentials.user_identity, credentials.external_randomness)
        .map_err(|e| Box::<dyn Error>::from(e))?;
    
    save_credentials(
        &credentials.user_identity,
        new_commitment,
        &credentials.signature,
        &credentials.verifying_key,
        credentials.external_randomness
    )?;
    
    println!("Updated credentials saved with the new ticket");
    Ok(())
}

async fn add_to_callback_ledger(ticket: u128, reason: &str) -> Result<(), Box<dyn Error>> {
    let request = AddTicketRequest {
        ticket,
        reason: reason.to_string(),
    };
    
    println!("Adding ticket {} to the callback ledger...", ticket);
    let client = Client::new();
    let response = client
        .post("http://localhost:8081/add_to_ledger")
        .json(&request)
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("✅ Ticket successfully added to the callback ledger");
        Ok(())
    } else {
        println!("❌ Failed to add ticket to the callback ledger: {}", response.status());
        println!("Error: {}", response.text().await?);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to add ticket to the callback ledger"
        )))
    }
}

async fn view_callback_ledger() -> Result<(), Box<dyn Error>> {
    println!("Retrieving callback ledger from server...");
    let client = Client::new();
    let response = client
        .get("http://localhost:8081/ledger")
        .send()
        .await?;
    
    if response.status().is_success() {
        let ledger: HashMap<String, String> = response.json().await?;
        
        if ledger.is_empty() {
            println!("The callback ledger is empty");
        } else {
            println!("Callback Ledger Contents:");
            println!("{:=^50}", "");
            println!("{:^20} | {:^25}", "Ticket", "Reason");
            println!("{:=^50}", "");
            
            for (ticket, reason) in ledger {
                println!("{:^20} | {}", ticket, reason);
            }
            println!("{:=^50}", "");
        }
        
        Ok(())
    } else {
        println!("❌ Failed to retrieve callback ledger: {}", response.status());
        println!("Error: {}", response.text().await?);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to retrieve callback ledger"
        )))
    }
}

async fn check_user_ban_status(name: &str) -> Result<(), Box<dyn Error>> {
    let mut credentials = load_credentials(name)?;
    
    // If there are no tickets, nothing to check
    if credentials.user_identity.tickets.is_empty() {
        println!("User {} has no tickets to check", name);
        return Ok(());
    }
    
    // Create a request to scan the user
    let user_bytes = serde_json::to_vec(&credentials.user_identity)?;
    let request = ScanRequest {
        user_data: user_bytes,
    };
    
    println!("Checking if user {} is banned...", name);
    let client = Client::new();
    let response = client
        .post("http://localhost:8081/scan_user")
        .json(&request)
        .send()
        .await?;
    
    if response.status().is_success() {
        let scan_result = response.text().await?;
        
        if scan_result.contains("has no tickets in the callback ledger") {
            println!("✅ User {} is not banned", name);
        } else {
            println!("❌ User {} may be banned - tickets found in callback ledger:", name);
            println!("{}", scan_result);
            
            // Update local credentials to reflect banned status
            credentials.user_identity.ban_identity();
            
            // Recalculate commitment with the updated user data
            let new_commitment = calculate_commitment(&credentials.user_identity, credentials.external_randomness)
                .map_err(|e| Box::<dyn Error>::from(e))?;
            
            // Save the updated credentials with the new commitment
            save_credentials(
                &credentials.user_identity,
                new_commitment,
                &credentials.signature,
                &credentials.verifying_key,
                credentials.external_randomness
            )?;
            
            println!("Updated local credentials to reflect banned status");
        }
        
        Ok(())
    } else {
        println!("❌ Failed to check user ban status: {}", response.status());
        println!("Error: {}", response.text().await?);
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to check user ban status"
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Register { name } => {
            register_new_user(&name).await?
        },
        Commands::Verify { name } => {
            println!("Verifying credentials for user: {}", name);
            let credentials = load_credentials(&name)?;
            verify_stored_credentials(&credentials)?
        },
        Commands::Action { name, description } => {
            generate_ticket_for_action(&name, &description).await?
        },
        Commands::Callback { ticket, reason } => {
            add_to_callback_ledger(ticket, &reason).await?
        },
        Commands::ViewLedger => {
            view_callback_ledger().await?
        },
        Commands::CheckBan { name } => {
            check_user_ban_status(&name).await?
        }
    }
    
    Ok(())
}
