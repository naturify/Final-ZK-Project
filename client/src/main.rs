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
    Register,
    
    /// Verify stored user credentials
    Verify {
        /// User ID to verify
        #[arg(short, long)]
        user_id: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserData {
    name: String,
    id: u64,
    access_level: u8,
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
    user_data: UserData,
    commitment: [u8; 32],
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
    external_randomness: u128,
}

fn calculate_commitment(user_data: &[u8], external_randomness: u128) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(user_data);
    hasher.update(&external_randomness.to_le_bytes());
    
    let result = hasher.finalize();
    <[u8; 32]>::try_from(result.as_slice()).expect("SHA-256 output should be 32 bytes")
}

fn save_credentials(
    user: &UserData,
    commitment: [u8; 32],
    signature: &[u8],
    verifying_key: &[u8],
    external_randomness: u128,
) -> std::io::Result<()> {
    let credentials = StoredCredentials {
        user_data: user.clone(),
        commitment,
        signature: signature.to_vec(),
        verifying_key: verifying_key.to_vec(),
        external_randomness,
    };
    
    // Serialize to JSON
    let json = serde_json::to_string_pretty(&credentials)?;
    
    // Save to file
    let filename = format!("credentials_{}.json", user.id);
    let mut file = File::create(&filename)?;
    file.write_all(json.as_bytes())?;
    
    println!("Credentials saved to {}", filename);
    Ok(())
}

fn load_credentials(user_id: u64) -> Result<StoredCredentials, Box<dyn Error>> {
    let filename = format!("credentials_{}.json", user_id);
    
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
    let user_bytes = serde_json::to_vec(&credentials.user_data)?;
    let calculated_commitment = calculate_commitment(&user_bytes, credentials.external_randomness);
    
    if calculated_commitment != credentials.commitment {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Commitment verification failed - user data has been tampered with"
        )));
    }
    
    // 2. Verify the signature
    let signature = Signature::try_from(credentials.signature.as_slice())
        .map_err(|_| Box::<dyn Error>::from("Invalid signature format"))?;
    
    let verifying_key = VerifyingKey::from_sec1_bytes(&credentials.verifying_key)
        .map_err(|_| Box::<dyn Error>::from("Invalid verifying key format"))?;
    
    verifying_key.verify(&credentials.commitment, &signature)
        .map_err(|_| Box::<dyn Error>::from("Signature verification failed - signature is not valid"))?;
    
    println!("✅ All verifications passed! The credentials are valid.");
    println!("User: {} (ID: {})", credentials.user_data.name, credentials.user_data.id);
    println!("Access level: {}", credentials.user_data.access_level);
    
    Ok(())
}

async fn register_new_user() -> Result<(), Box<dyn Error>> {
    // Create a user
    let user = UserData {
        name: "Alice".to_string(),
        id: 12345,
        access_level: 2,
    };
    
    // Serialize the user data
    let user_bytes = serde_json::to_vec(&user)?;
    
    // Generate random value
    let external_randomness = rand::thread_rng().gen::<u128>();
    
    // Calculate local commitment
    let local_commitment = calculate_commitment(&user_bytes, external_randomness);
    println!("Local commitment: {:?}", local_commitment);
    
    // Prepare request
    let request = RegistrationRequest {
        user_data: user_bytes,
        external_randomness,
    };
    
    // Send to server
    println!("Sending registration request to server...");
    let client = Client::new();
    let response = client
        .post("http://localhost:8080/register")
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Register => {
            register_new_user().await?;
        },
        Commands::Verify { user_id } => {
            println!("Verifying credentials for user ID: {}", user_id);
            let credentials = load_credentials(user_id)?;
            verify_stored_credentials(&credentials)?;
        }
    }
    
    Ok(())
}
