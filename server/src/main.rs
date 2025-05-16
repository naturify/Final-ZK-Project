use actix_web::{web, App, HttpServer, HttpResponse, post, middleware::Logger};
use k256::ecdsa::{SigningKey, VerifyingKey, signature::Signer, Signature};
use log::info;
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use std::{io::Write, fs::File};
use sha2::{Sha256, Digest};

struct AppState {
    signing_key: Mutex<SigningKey>,
    verifying_key: Mutex<VerifyingKey>,
}

#[derive(Deserialize)]
struct RegistrationRequest {
    user_data: Vec<u8>,
    external_randomness: u128,
}

#[derive(Serialize)]
struct RegistrationResponse {
    commit: [u8; 32],
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
}

fn calculate_commitment(
    user_data: &[u8],
    external_commitment_randomness: u128,
) -> [u8; 32] {
    // Initialize the hasher
    let mut hasher = Sha256::new();
    // Update hasher with the user data
    hasher.update(user_data);
    // Update hasher with the external commitment randomness
    hasher.update(&external_commitment_randomness.to_le_bytes());

    // Finalize the hash
    let result = hasher.finalize();
    <[u8; 32]>::try_from(result.as_slice()).expect("SHA-256 output should be 32 bytes")
}

#[post("/register")]
async fn register(
    data: web::Data<AppState>,
    req: web::Json<RegistrationRequest>,
) -> HttpResponse {
    info!("Registration request received");
    
    // Calculate commitment
    let commit = calculate_commitment(&req.user_data, req.external_randomness);
    
    // Sign the commitment
    let sig: Signature = {
        let signing_key = data.signing_key.lock().unwrap();
        signing_key.sign(&commit)
    };
    
    // Get the verifying key bytes
    let vk_bytes = {
        let vk = data.verifying_key.lock().unwrap();
        vk.to_encoded_point(false).as_bytes().to_vec()
    };
    
    // Create response
    let response = RegistrationResponse {
        commit,
        signature: sig.to_bytes().to_vec(),
        verifying_key: vk_bytes,
    };
    
    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    info!("Generating or loading server keys...");
    
    // Generate or load server keys
    let (signing_key, verifying_key) = generate_or_load_keys()?;
    
    let app_state = web::Data::new(AppState {
        signing_key: Mutex::new(signing_key),
        verifying_key: Mutex::new(verifying_key),
    });
    
    info!("Starting server on 127.0.0.1:8080");
    
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .service(register)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

fn generate_or_load_keys() -> std::io::Result<(SigningKey, VerifyingKey)> {
    // Check if key file exists
    if let Ok(mut file) = File::open("server_keys.bin") {
        info!("Loading existing keys from file");
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        
        if bytes.len() == 32 {
            let signing_key = SigningKey::from_slice(&bytes)
                .expect("Invalid signing key data");
            let verifying_key = VerifyingKey::from(&signing_key);
            return Ok((signing_key, verifying_key));
        }
    }
    
    // Generate new keys
    info!("Generating new server keys");
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Save keys to file
    let mut file = File::create("server_keys.bin")?;
    file.write_all(signing_key.to_bytes().as_slice())?;
    
    Ok((signing_key, verifying_key))
}
