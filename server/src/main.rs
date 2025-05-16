use actix_web::{web, App, HttpServer, HttpResponse, post, get, middleware::Logger};
use k256::ecdsa::{SigningKey, VerifyingKey, signature::Signer, Signature};
use log::{info, warn, error};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use std::{io::Write, fs::File, collections::HashMap, path::Path};
use std::io::Read;
use sha2::{Sha256, Digest};
use group_core::UserIdentity;

struct AppState {
    signing_key: Mutex<SigningKey>,
    verifying_key: Mutex<VerifyingKey>,
    callback_ledger: Mutex<HashMap<u128, String>>,
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

#[derive(Deserialize)]
struct AddTicketRequest {
    ticket: u128,
    reason: String,
}

#[derive(Serialize, Deserialize)]
struct CallbackLedger {
    entries: HashMap<u128, String>,
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

// Save the callback ledger to a file
fn save_callback_ledger(ledger: &HashMap<u128, String>) -> std::io::Result<()> {
    let callback_ledger = CallbackLedger {
        entries: ledger.clone(),
    };
    
    let json = serde_json::to_string_pretty(&callback_ledger)?;
    let mut file = File::create("callback_ledger.json")?;
    file.write_all(json.as_bytes())?;
    
    info!("Callback ledger saved to callback_ledger.json");
    Ok(())
}

// Load the callback ledger from a file
fn load_callback_ledger() -> HashMap<u128, String> {
    if !Path::new("callback_ledger.json").exists() {
        info!("No callback ledger found, creating an empty one");
        return HashMap::new();
    }
    
    match File::open("callback_ledger.json") {
        Ok(mut file) => {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_err() {
                error!("Failed to read callback ledger file");
                return HashMap::new();
            }
            
            match serde_json::from_str::<CallbackLedger>(&contents) {
                Ok(ledger) => {
                    info!("Loaded callback ledger with {} entries", ledger.entries.len());
                    ledger.entries
                },
                Err(e) => {
                    error!("Failed to parse callback ledger: {}", e);
                    HashMap::new()
                }
            }
        },
        Err(e) => {
            error!("Failed to open callback ledger file: {}", e);
            HashMap::new()
        }
    }
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

#[post("/add_to_ledger")]
async fn add_to_ledger(
    data: web::Data<AppState>,
    req: web::Json<AddTicketRequest>,
) -> HttpResponse {
    info!("Adding ticket {} to callback ledger", req.ticket);
    
    let mut ledger = data.callback_ledger.lock().unwrap();
    ledger.insert(req.ticket, req.reason.clone());
    
    // Save the updated ledger
    if let Err(e) = save_callback_ledger(&ledger) {
        error!("Failed to save callback ledger: {}", e);
        return HttpResponse::InternalServerError().json("Failed to save callback ledger");
    }
    
    HttpResponse::Ok().json("Ticket added to callback ledger")
}

#[get("/ledger")]
async fn get_ledger(data: web::Data<AppState>) -> HttpResponse {
    info!("Request to view callback ledger");
    
    let ledger = data.callback_ledger.lock().unwrap();
    let entries = ledger.clone();
    
    HttpResponse::Ok().json(entries)
}

#[derive(Deserialize)]
struct ScanRequest {
    user_data: Vec<u8>,
}

#[post("/scan_user")]
async fn scan_user(
    data: web::Data<AppState>,
    req: web::Json<ScanRequest>,
) -> HttpResponse {
    info!("Scanning user for callback ledger entries");
    
    // Parse the user data
    let user: UserIdentity = match serde_json::from_slice(&req.user_data) {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to parse user data: {}", e);
            return HttpResponse::BadRequest().json("Invalid user data");
        }
    };
    
    // Check if user's tickets are in the ledger
    let ledger = data.callback_ledger.lock().unwrap();
    let mut matching_tickets = Vec::new();
    
    for ticket in &user.tickets {
        if ledger.contains_key(ticket) {
            matching_tickets.push((*ticket, ledger.get(ticket).unwrap().clone()));
        }
    }
    
    if matching_tickets.is_empty() {
        HttpResponse::Ok().json("User has no tickets in the callback ledger")
    } else {
        HttpResponse::Ok().json(matching_tickets)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    info!("Generating or loading server keys...");
    
    // Generate or load server keys
    let (signing_key, verifying_key) = generate_or_load_keys()?;
    
    // Load the callback ledger
    let callback_ledger = load_callback_ledger();
    info!("Loaded callback ledger with {} entries", callback_ledger.len());
    
    let app_state = web::Data::new(AppState {
        signing_key: Mutex::new(signing_key),
        verifying_key: Mutex::new(verifying_key),
        callback_ledger: Mutex::new(callback_ledger),
    });
    
    info!("Starting server on 127.0.0.1:8081");
    
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .service(register)
            .service(add_to_ledger)
            .service(get_ledger)
            .service(scan_user)
    })
    .bind("127.0.0.1:8081")?
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
