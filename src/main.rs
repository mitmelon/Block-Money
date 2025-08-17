mod backup;
use tokio_cron_scheduler::{Job, JobScheduler};
use std::process;
use actix_web::{web, App, HttpResponse, HttpServer, middleware::Logger, HttpRequest, dev::ServiceRequest, Error as ActixError};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use chrono::{Utc, NaiveDate};
use serde::{Deserialize, Serialize};
use serde_json;
use sled::Db;
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair, Ed25519KeyPair},
};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use hex;
use log::{info, error, debug};
use fern;
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::env;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, AeadCore,
};
use tokio::sync::Semaphore;
use regex::Regex;
use aes_gcm::aead::OsRng; 


// Constants
const DECIMAL_PRECISION: u64 = 10_000; // 10^4 for 4 decimal places
const MAX_AMOUNT_UNITS: u64 = 1_000_000_000_000 * DECIMAL_PRECISION; // 1 trillion tokens in units
const MIN_AMOUNT_UNITS: u64 = 1; // 0.0001 tokens in units
const MIN_NET_AMOUNT_UNITS: u64 = 1; // 0.0001 tokens in units after fee

// Represents a single transaction in the blockchain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Transaction {
    hash: String,
    from: String, // Public Key
    to: String,   // Public Key
    amount: u64,  // Amount in units (tokens * 10^4)
    timestamp: i64,
    signature: String,
    fee: u64, // Fee in units
    description: String, // Description of the transaction
    nonce: u64,
}

// Represents a block in the blockchain.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    timestamp: i64,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
    nonce: u64,
}

// Represents the entire blockchain.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Chain {
    blocks: Vec<Block>,
    pending_transactions: Vec<Transaction>,
    wallets: HashMap<String, u64>, // Balances in units
    last_transaction_times: HashMap<String, i64>,
    blacklisted_wallets: HashMap<String, bool>,
    wallet_nonces: HashMap<String, u64>,
}

// Represents the genesis wallet stored in JSON.
#[derive(Serialize, Deserialize, Debug)]
struct GenesisWallet {
    private_key: String,
    public_key: String,
}

// A wrapper for the database, blockchain state, bearer token, encryption cipher, and identity hashes.
struct AppState {
    db: Db,
    chain: Mutex<Chain>,
    genesis_public_key: String,
    bearer_token: String,
    cipher: Aes256Gcm,
    tx_semaphore: Arc<Semaphore>,
    identity_hashes: Mutex<HashMap<String, (String, String)>>, // Maps identity hash to (public_key, private_key)
}

impl Block {
    fn calculate_hash(&self) -> String {
        let mut headers = self.timestamp.to_string();
        headers.push_str(&serde_json::to_string(&self.transactions).unwrap());
        headers.push_str(&self.previous_hash);
        headers.push_str(&self.nonce.to_string());
        let mut hasher = Sha256::new();
        hasher.update(headers.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn mine_block(&mut self, difficulty: usize) {
        debug!("Starting block mining with difficulty {}", difficulty);
        let prefix = "0".repeat(difficulty);
        self.hash = self.calculate_hash();
        while self.hash.len() < difficulty || &self.hash[..difficulty] != prefix {
            self.nonce += 1;
            self.hash = self.calculate_hash();
        }
        debug!("Block mined with hash {} and nonce {}", self.hash, self.nonce);
    }
}

impl Chain {
    fn new(genesis_public_key: String) -> Self {
        debug!("Initializing new chain with genesis public key {}", genesis_public_key);
        
        let genesis_tx = Transaction {
            hash: hex::encode(Sha256::new().finalize()),
            from: "system".to_string(),
            to: genesis_public_key.clone(),
            amount: 1_000_000_000 * DECIMAL_PRECISION,
            timestamp: Utc::now().timestamp(),
            signature: "genesis".to_string(),
            fee: 0,
            description: "Genesis transaction".to_string(),
            nonce: 0,
        };
        let mut genesis_block = Block {
            timestamp: Utc::now().timestamp(),
            transactions: vec![genesis_tx.clone()],
            previous_hash: "0".to_string(),
            hash: String::new(),
            nonce: 0,
        };
        genesis_block.hash = genesis_block.calculate_hash();
        let mut wallets = HashMap::new();
        wallets.insert(genesis_public_key.clone(), genesis_tx.amount);
        
        Chain {
            blocks: vec![genesis_block],
            pending_transactions: vec![],
            wallets,
            last_transaction_times: HashMap::new(),
            blacklisted_wallets: HashMap::new(),
            wallet_nonces: HashMap::new(),
        }
    }

    fn get_last_block(&self) -> &Block {
        self.blocks.last().expect("Chain should have at least one block")
    }
}

// Middleware to validate bearer token
async fn validate_token(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
    let data = match req.app_data::<web::Data<AppState>>() {
        Some(data) => data,
        None => {
            let err = actix_web::error::ErrorUnauthorized("App state not found");
            return Err((err, req));
        }
    };
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    if credentials.token() == data.bearer_token {
        info!("Authorized request from {} to {}", client_ip, req.path());
        Ok(req)
    } else {
        error!("Unauthorized request from {} to {}", client_ip, req.path());
        let err = actix_web::error::ErrorUnauthorized("Invalid bearer token");
        Err((err, req))
    }
}

// Sets up directories and logging with fern
fn setup_logging() -> io::Result<()> {
    let log_dir = Path::new("data/logs");
    fs::create_dir_all(log_dir)?;

    let log_file = log_dir.join(format!("server_{}.log", Utc::now().format("%Y%m%d_%H%M%S")));
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] - {}",
                Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout())
        .chain(File::create(&log_file)?)
        .apply()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Logger setup failed: {}", e)))?;

    info!("Logging initialized to {:?}", log_file);
    Ok(())
}

// Creates directories for database and genesis wallet
fn setup_directories() -> io::Result<()> {
    let data_dir = Path::new("data");
    let db_dir = data_dir.join("db");
    fs::create_dir_all(db_dir)?;
    Ok(())
}

// Loads or creates the genesis wallet
fn load_or_create_genesis_wallet() -> io::Result<GenesisWallet> {
    let wallet_path = Path::new("data/genesis_wallet.json");
    if wallet_path.exists() {
        let file = File::open(wallet_path)?;
        let wallet: GenesisWallet = serde_json::from_reader(file)?;
        info!("Loaded genesis wallet from {:?}", wallet_path);
        Ok(wallet)
    } else {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to generate PKCS8"))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to parse PKCS8"))?;
        let private_key = hex::encode(&pkcs8_bytes);
        let public_key = hex::encode(key_pair.public_key().as_ref());
        let wallet = GenesisWallet {
            private_key,
            public_key,
        };
        let contents = serde_json::to_string_pretty(&wallet)?;
        fs::write(wallet_path, contents)?;
        info!("Created genesis wallet at {:?}", wallet_path);
        Ok(wallet)
    }
}

// Encrypts data using AES-GCM with a random nonce
fn encrypt_data(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>, String> {
    // Generate a random 96-bit (12-byte) nonce. NEVER REUSE A NONCE WITH THE SAME KEY.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    // Prepend the nonce to the ciphertext for storage.
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// Decrypts data using AES-GCM
fn decrypt_data(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Invalid encrypted data: too short to contain a nonce".to_string());
    }
    // Extract the nonce from the beginning of the data.
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))
}

// Helper to handle poisoned mutex gracefully
fn lock_chain<'a>(mutex: &'a Mutex<Chain>, client_ip: &str, endpoint: &str) -> Result<std::sync::MutexGuard<'a, Chain>, ActixError> {
    mutex.lock().map_err(|e| {
        error!("Mutex poisoned in {} for {}: {:?}", endpoint, client_ip, e);
        actix_web::error::ErrorInternalServerError("Server error: Mutex poisoned")
    })
}

// Helper to handle poisoned identity_hashes mutex
fn lock_identity_hashes<'a>(mutex: &'a Mutex<HashMap<String, (String, String)>>, client_ip: &str, endpoint: &str) -> Result<std::sync::MutexGuard<'a, HashMap<String, (String, String)>>, ActixError> {
    mutex.lock().map_err(|e| {
        error!("Mutex poisoned in {} for {}: {:?}", endpoint, client_ip, e);
        actix_web::error::ErrorInternalServerError("Server error: Mutex poisoned")
    })
}

// Parses token string (e.g., "1.2345") to units (u64)
fn parse_tokens_to_units(tokens: &str) -> Result<u64, String> {
    let re = Regex::new(r"^(0|[1-9]\d*)(\.\d{1,4})?$").map_err(|_| "Invalid regex".to_string())?;
    if !re.is_match(tokens) {
        return Err("Amount must be a non-negative number with up to 4 decimal places".to_string());
    }
    let parts: Vec<&str> = tokens.split('.').collect();
    let integer_part: u64 = parts[0].parse().map_err(|_| "Invalid integer part".to_string())?;
    let decimal_part = if parts.len() > 1 { parts[1] } else { "0" };
    let decimal_str = format!("{:0<4}", decimal_part);
    let decimal_value: u64 = decimal_str.parse().map_err(|_| "Invalid decimal part".to_string())?;
    let units = integer_part
        .checked_mul(DECIMAL_PRECISION)
        .ok_or("Amount too large")?
        .checked_add(decimal_value)
        .ok_or("Amount too large")?;
    if units > MAX_AMOUNT_UNITS {
        return Err("Amount exceeds maximum allowed".to_string());
    }
    if units < MIN_AMOUNT_UNITS {
        return Err(format!("Amount must be at least {}", format_units_to_tokens(MIN_AMOUNT_UNITS)));
    }
    Ok(units)
}

// Formats units (u64) to token string (e.g., "1.2345")
fn format_units_to_tokens(units: u64) -> String {
    let integer = units / DECIMAL_PRECISION;
    let decimal = units % DECIMAL_PRECISION;
    format!("{}.{:04}", integer, decimal)
}

// Validates personal details and returns a hash of them
fn validate_and_hash_personal_details(first_name: &str, last_name: &str, dob: &str, gender: &str, client_ip: &str) -> Result<String, ActixError> {
    let name_re = Regex::new(r"^[A-Za-z\s\-]+$").map_err(|_| {
        error!("Invalid regex for name validation for {}", client_ip);
        actix_web::error::ErrorInternalServerError("Server error")
    })?;
    if !name_re.is_match(first_name) || !name_re.is_match(last_name) {
        error!("Invalid name format for {}: first_name={}, last_name={}", client_ip, first_name, last_name);
        return Err(actix_web::error::ErrorBadRequest("First and last names must contain only letters, spaces, or hyphens"));
    }

    let dob_re = Regex::new(r"^\d{2}-\d{2}-\d{4}$").map_err(|_| {
        error!("Invalid regex for date of birth validation for {}", client_ip);
        actix_web::error::ErrorInternalServerError("Server error")
    })?;
    if !dob_re.is_match(dob) {
        error!("Invalid date of birth format for {}: dob={}", client_ip, dob);
        return Err(actix_web::error::ErrorBadRequest("Date of birth must be in DD-MM-YYYY format"));
    }
    if NaiveDate::parse_from_str(dob, "%d-%m-%Y").is_err() {
        error!("Invalid date of birth for {}: dob={}", client_ip, dob);
        return Err(actix_web::error::ErrorBadRequest("Invalid date of birth"));
    }

    let valid_genders = ["male", "female", "others"];
    if !valid_genders.contains(&gender) {
        error!("Invalid gender for {}: gender={}", client_ip, gender);
        return Err(actix_web::error::ErrorBadRequest("Gender must be male, female, or others"));
    }

    let details = format!("{}{}{}{}", first_name.to_lowercase(), last_name.to_lowercase(), dob, gender);
    let mut hasher = Sha256::new();
    hasher.update(details.as_bytes());
    let identity_hash = hex::encode(hasher.finalize());
    Ok(identity_hash)
}

// Creates a new wallet with personal details
async fn create_wallet(data: web::Data<AppState>, req: HttpRequest, wallet_data: web::Json<serde_json::Value>) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing create_wallet for {}", client_ip);

    let first_name = wallet_data["first_name"].as_str().ok_or_else(|| {
        error!("Missing 'first_name' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'first_name' field")
    })?.to_string();
    let last_name = wallet_data["last_name"].as_str().ok_or_else(|| {
        error!("Missing 'last_name' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'last_name' field")
    })?.to_string();
    let dob = wallet_data["dob"].as_str().ok_or_else(|| {
        error!("Missing 'dob' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'dob' field")
    })?.to_string();
    let gender = wallet_data["gender"].as_str().ok_or_else(|| {
        error!("Missing 'gender' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'gender' field")
    })?.to_string();

    let identity_hash = validate_and_hash_personal_details(&first_name, &last_name, &dob, &gender, &client_ip)?;

    let mut identity_hashes = lock_identity_hashes(&data.identity_hashes, &client_ip, "create_wallet")?;
    if let Some((public_key, private_key)) = identity_hashes.get(&identity_hash) {
        info!("Duplicate identity found for {}: returning existing wallet {}", client_ip, public_key);
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Wallet already exists for this identity",
            "private_key": private_key,
            "public_key": public_key,
        })));
    }

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| {
            error!("Failed to generate key pair for {}: {:?}", client_ip, e);
            actix_web::error::ErrorInternalServerError("Key generation failed")
        })?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| {
            error!("Failed to create key pair for {}: {:?}", client_ip, e);
            actix_web::error::ErrorInternalServerError("Key creation failed")
        })?;

    let private_key = hex::encode(&pkcs8_bytes);
    let public_key = hex::encode(key_pair.public_key().as_ref());
    
    let mut chain = lock_chain(&data.chain, &client_ip, "create_wallet")?;

    if chain.wallets.contains_key(&public_key) {
        error!("Duplicate wallet public key for {}: {}", client_ip, public_key);
        return Ok(HttpResponse::InternalServerError().body("Failed to generate a unique wallet"));
    }
    chain.wallets.insert(public_key.clone(), 0);
    identity_hashes.insert(identity_hash, (public_key.clone(), private_key.clone()));

    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let serialized_hashes = serde_json::to_string(&*identity_hashes).map_err(|e| {
        error!("Identity hashes serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_hashes = encrypt_data(&data.cipher, serialized_hashes.as_bytes()).map_err(|e| {
        error!("Identity hashes encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("identity_hashes", encrypted_hashes).map_err(|e| {
        error!("Identity hashes database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    data.db.flush_async().await.map_err(|e| {
        error!("Database flush failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database flush error")
    })?;

    info!("Created wallet {} with zero balance for {}", public_key, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "private_key": private_key,
        "public_key": public_key,
    })))
}

// Retrieves wallet balance
async fn get_balance(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing get_balance for {}", client_ip);
    let public_key = path.into_inner();
    let chain = lock_chain(&data.chain, &client_ip, "get_balance")?;

    if chain.blacklisted_wallets.get(&public_key).unwrap_or(&false) == &true {
        info!("Balance check for blacklisted wallet {} by {}", public_key, client_ip);
        return Ok(HttpResponse::Forbidden().body("Wallet is blacklisted"));
    }

    match chain.wallets.get(&public_key) {
        Some(&balance) => {
            let balance_tokens = format_units_to_tokens(balance);
            info!("Balance check for {} by {}: {}", public_key, client_ip, balance_tokens);
            Ok(HttpResponse::Ok().json(balance_tokens))
        }
        None => {
            info!("Balance check for non-existent wallet {} by {}", public_key, client_ip);
            Ok(HttpResponse::NotFound().body("Wallet not found"))
        }
    }
}

// Sends tokens with 1% fee deducted from amount for non-genesis transactions
async fn send_token(trans_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let _permit = data.tx_semaphore.acquire().await
        .map_err(|_| actix_web::error::ErrorServiceUnavailable("Transaction processing limit reached"))?;
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing send_token for {}", client_ip);
    
    let from = trans_data["from"].as_str().ok_or_else(|| {
        error!("Invalid 'from' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'from' field")
    })?.to_string();
    let to = trans_data["to"].as_str().ok_or_else(|| {
        error!("Invalid 'to' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'to' field")
    })?.to_string();
    let amount_str = trans_data["amount"].as_str().ok_or_else(|| {
        error!("Invalid 'amount' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'amount' field")
    })?.to_string();
    let private_key = trans_data["private_key"].as_str().ok_or_else(|| {
        error!("Invalid 'private_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'private_key' field")
    })?.to_string();
    let description = trans_data["description"].as_str().ok_or_else(|| {
        error!("Missing 'description' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'description' field")
    })?.to_string();

    // Validate description (e.g., max length 200 characters, printable ASCII)
    if description.len() > 200 {
        error!("Description too long for {}: length={}", client_ip, description.len());
        return Ok(HttpResponse::BadRequest().body("Description must not exceed 200 characters"));
    }
    let desc_re = Regex::new(r"^[\x20-\x7E]+$").map_err(|_| {
        error!("Invalid regex for description validation for {}", client_ip);
        actix_web::error::ErrorInternalServerError("Server error")
    })?;
    if !desc_re.is_match(&description) {
        error!("Invalid description format for {}: description={}", client_ip, description);
        return Ok(HttpResponse::BadRequest().body("Description must contain only printable ASCII characters"));
    }

    let amount = parse_tokens_to_units(&amount_str).map_err(|e| {
        error!("Invalid amount {} for {}: {}", amount_str, client_ip, e);
        actix_web::error::ErrorBadRequest(e)
    })?;
    if amount < MIN_AMOUNT_UNITS {
        error!("Amount {} below minimum {} for {}", amount, MIN_AMOUNT_UNITS, client_ip);
        return Ok(HttpResponse::BadRequest().body(format!("Amount must be at least {}", format_units_to_tokens(MIN_AMOUNT_UNITS))));
    }
    if amount > MAX_AMOUNT_UNITS {
        error!("Amount {} exceeds maximum {} for {}", amount, MAX_AMOUNT_UNITS, client_ip);
        return Ok(HttpResponse::BadRequest().body("Amount exceeds maximum allowed"));
    }

    let nonce = trans_data["nonce"].as_u64().ok_or_else(|| {
        error!("Missing 'nonce' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'nonce' field")
    })?;

    let mut chain = lock_chain(&data.chain, &client_ip, "send_token")?;

    let expected_nonce = chain.wallet_nonces.get(&from).cloned().unwrap_or(0);
    if nonce != expected_nonce {
        error!("Invalid nonce for {}. Expected {}, got {}.", from, expected_nonce, nonce);
        return Ok(HttpResponse::BadRequest().body(format!("Invalid nonce. Expected {}", expected_nonce)));
    }

    if chain.blacklisted_wallets.get(&from).unwrap_or(&false) == &true ||
       chain.blacklisted_wallets.get(&to).unwrap_or(&false) == &true {
        info!("Transaction attempt with blacklisted wallet from {} to {} by {}", from, to, client_ip);
        return Ok(HttpResponse::Forbidden().body("Sender or receiver is blacklisted"));
    }

    let current_time = Utc::now().timestamp();
    if let Some(last_tx_time) = chain.last_transaction_times.get(&from) {
        if current_time - last_tx_time < 30 {
            info!("Transaction cooldown violation for {} by {}", from, client_ip);
            return Ok(HttpResponse::BadRequest().body("Transaction cooldown: 30 seconds not elapsed"));
        }
    }

    let total_supply: u64 = chain.wallets.values().sum();
    let max_tx_amount = total_supply / 50; // 2% of total supply
    let max_wallet_balance = total_supply / 33; // ~3% of total supply

    if amount > max_tx_amount {
        info!("Transaction amount {} exceeds 2% limit {} for {} by {}", amount, max_tx_amount, from, client_ip);
        return Ok(HttpResponse::BadRequest().body(format!("Transaction amount exceeds 2% of total supply ({})", format_units_to_tokens(max_tx_amount))));
    }

    let is_genesis_involved = from == data.genesis_public_key || to == data.genesis_public_key;
    let (fee, net_amount) = if is_genesis_involved {
        (0, amount)
    } else {
        let fee = amount / 100; // 1% fee
        let net = amount.checked_sub(fee).ok_or_else(|| {
            error!("Net amount underflow for amount {} by {}", amount, client_ip);
            actix_web::error::ErrorBadRequest("Arithmetic underflow")
        })?;
        if net < MIN_NET_AMOUNT_UNITS {
            error!("Net amount {} below minimum {} for amount {} by {}", net, MIN_NET_AMOUNT_UNITS, amount, client_ip);
            return Ok(HttpResponse::BadRequest().body(format!("Amount too small; net amount after 1% fee must be at least {}", format_units_to_tokens(MIN_NET_AMOUNT_UNITS))));
        }
        (fee, net)
    };

    let from_balance = chain.wallets.get(&from).cloned().unwrap_or(0);
    let total_deduction = net_amount.checked_add(fee).ok_or_else(|| {
        error!("Total deduction overflow for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Arithmetic overflow")
    })?;
    if from_balance < total_deduction {
        info!("Insufficient funds for {} (required: {}, available: {}) by {}", from, format_units_to_tokens(total_deduction), format_units_to_tokens(from_balance), client_ip);
        return Ok(HttpResponse::BadRequest().body("Insufficient funds"));
    }

    if let Some(to_balance) = chain.wallets.get(&to) {
        let new_balance = to_balance.checked_add(net_amount).ok_or_else(|| {
            error!("Arithmetic overflow in receiver balance for {}", client_ip);
            actix_web::error::ErrorBadRequest("Arithmetic overflow")
        })?;
        if to != data.genesis_public_key && new_balance > max_wallet_balance {
            info!("Receiver balance would exceed 3% limit {} for {} by {}", format_units_to_tokens(max_wallet_balance), to, client_ip);
            return Ok(HttpResponse::BadRequest().body(format!("Receiver's balance would exceed 3% of total supply ({})", format_units_to_tokens(max_wallet_balance))));
        }
    }

    let private_key_bytes = hex::decode(&private_key).map_err(|_| {
        error!("Invalid private key format for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key format")
    })?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes).map_err(|_| {
        error!("Invalid private key for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key")
    })?;
    let public_key_bytes = key_pair.public_key().as_ref();
    if hex::encode(public_key_bytes) != from {
        error!("Private key mismatch for {} by {}", from, client_ip);
        return Ok(HttpResponse::Unauthorized().body("Private key does not match sender's public key"));
    }

    let message_to_sign = format!("{}{}{}{}{}", from, to, amount_str, description, nonce);
    let signature = key_pair.sign(message_to_sign.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());

    let from_public_key_bytes = hex::decode(&from).map_err(|_| {
        error!("Invalid public key format for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'from' public key format")
    })?;
    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &from_public_key_bytes);
    if public_key.verify(message_to_sign.as_bytes(), signature.as_ref()).is_err() {
        error!("Signature verification failed for {} by {}", from, client_ip);
        return Ok(HttpResponse::Unauthorized().body("Signature verification failed"));
    }

    let timestamp = current_time;
    let tx_content = format!("{}{}{}{}{}", from, to, net_amount, timestamp, description);
    let mut hasher = Sha256::new();
    hasher.update(tx_content.as_bytes());
    let tx_hash = hex::encode(hasher.finalize());

    let transaction = Transaction {
        hash: tx_hash.clone(),
        from: from.clone(),
        to: to.clone(),
        amount: net_amount,
        timestamp,
        signature: signature_hex,
        fee,
        description,
        nonce,
    };

    chain.pending_transactions.push(transaction.clone());

    if fee > 0 {
        let fee_tx_content = format!("{}genesis_fee{}{}", from, fee, timestamp);
        let mut fee_hasher = Sha256::new();
        fee_hasher.update(fee_tx_content.as_bytes());
        let fee_tx_hash = hex::encode(fee_hasher.finalize());
        let fee_transaction = Transaction {
            hash: fee_tx_hash,
            from: from.clone(),
            to: data.genesis_public_key.clone(),
            amount: fee,
            timestamp,
            signature: String::from("system_fee"),
            fee: 0,
            description: "Transaction fee".to_string(),
            nonce,
        };
        chain.pending_transactions.push(fee_transaction);
    }

    chain.wallet_nonces.insert(from.clone(), nonce + 1);
    chain.last_transaction_times.insert(from.clone(), timestamp);

     // 1. Clone the necessary data that needs to be saved.
    let chain_to_save = chain.clone();

    // 2. Explicitly drop the lock *before* performing slow I/O.
    drop(chain);

    // 3. Perform serialization, encryption, and database writes on the cloned data,
    //    allowing other requests to access the blockchain concurrently.
    let serialized_chain = serde_json::to_string(&chain_to_save).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // The rest of the function remains the same
    info!("Transaction submitted from {} to {} (amount: {}, net_amount: {}, fee: {}, description: {}) by {}", 
        from, to, amount_str, format_units_to_tokens(net_amount), format_units_to_tokens(fee), transaction.description, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Transaction submitted successfully",
        "transaction_hash": tx_hash,
        "amount": amount_str,
        "net_amount": format_units_to_tokens(net_amount),
        "fee": format_units_to_tokens(fee),
        "timestamp": timestamp,
        "description": transaction.description
    })))

}

// Mines a new block with a mining reward
async fn mine_pending_transactions(data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let _permit = data.tx_semaphore.acquire().await
        .map_err(|_| actix_web::error::ErrorServiceUnavailable("Mining in progress"))?;
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing mine_pending_transactions for {}", client_ip);
    let mut chain = lock_chain(&data.chain, &client_ip, "mine_pending_transactions")?;

    if chain.pending_transactions.is_empty() {
        info!("No pending transactions to mine for {}", client_ip);
        return Ok(HttpResponse::Ok().body("No pending transactions to mine"));
    }

    debug!("Processing {} pending transactions", chain.pending_transactions.len());
    let transactions = chain.pending_transactions.clone();
    
    for tx in &transactions {
        debug!("Processing transaction {} from {} to {}", tx.hash, tx.from, tx.to);
        if tx.from != "system" && tx.signature != "system_fee" {
            let from_balance = chain.wallets.get(&tx.from).cloned().unwrap_or(0);
            let total_deduction = tx.amount.checked_add(tx.fee).ok_or_else(|| {
                error!("Total deduction overflow in transaction {} for {}", tx.hash, client_ip);
                actix_web::error::ErrorBadRequest("Arithmetic overflow")
            })?;
            if from_balance < total_deduction {
                error!("Invalid transaction {}: insufficient funds for {} (required: {}, available: {})", 
                    tx.hash, tx.from, format_units_to_tokens(total_deduction), format_units_to_tokens(from_balance));
                return Ok(HttpResponse::BadRequest().body("Invalid transaction: insufficient funds"));
            }
        }
        if let Some(balance) = chain.wallets.get_mut(&tx.from) {
            let deduction = tx.amount.checked_add(tx.fee).ok_or_else(|| {
                error!("Deduction overflow in transaction {} for {}", tx.hash, client_ip);
                actix_web::error::ErrorBadRequest("Arithmetic overflow")
            })?;
            *balance = balance.checked_sub(deduction).ok_or_else(|| {
                error!("Arithmetic underflow in transaction {} for {}", tx.hash, client_ip);
                actix_web::error::ErrorBadRequest("Arithmetic underflow")
            })?;
            debug!("Deducted {} from {} (new balance: {})", format_units_to_tokens(deduction), tx.from, format_units_to_tokens(*balance));
        }
        if tx.to != "burn" {
            let to_balance = chain.wallets.entry(tx.to.clone()).or_insert(0);
            *to_balance = to_balance.checked_add(tx.amount).ok_or_else(|| {
                error!("Arithmetic overflow in transaction {} for {}", tx.hash, client_ip);
                actix_web::error::ErrorBadRequest("Arithmetic overflow")
            })?;
            debug!("Added {} to {} (new balance: {})", format_units_to_tokens(tx.amount), tx.to, format_units_to_tokens(*to_balance));
        }
    }

    let reward = 1_000_000 * DECIMAL_PRECISION; // 1,000,000 tokens in units
    let timestamp = Utc::now().timestamp();
    debug!("Adding mining reward of {} to genesis wallet", format_units_to_tokens(reward));
    let reward_tx_content = format!("mining_reward{}{}", data.genesis_public_key, timestamp);
    let mut hasher = Sha256::new();
    hasher.update(reward_tx_content.as_bytes());
    let reward_tx_hash = hex::encode(hasher.finalize());
    let reward_transaction = Transaction {
        hash: reward_tx_hash,
        from: String::from("system"),
        to: data.genesis_public_key.clone(),
        amount: reward,
        timestamp,
        signature: String::from("mining_reward"),
        fee: 0,
        description: "Mining reward".to_string(),
        nonce: 0, // Use 0 for system transactions
    };
    chain.pending_transactions.push(reward_transaction);
    
    let genesis_balance = chain.wallets.entry(data.genesis_public_key.clone()).or_insert(0);
    *genesis_balance = genesis_balance.checked_add(reward).ok_or_else(|| {
        error!("Arithmetic overflow in mining reward for {}", client_ip);
        actix_web::error::ErrorBadRequest("Arithmetic overflow")
    })?;
    debug!("Genesis wallet balance updated to {}", format_units_to_tokens(*genesis_balance));

    let last_block = chain.get_last_block();
    let mut new_block = Block {
        timestamp,
        transactions: chain.pending_transactions.clone(),
        previous_hash: last_block.hash.clone(),
        hash: String::new(),
        nonce: 0,
    };

    debug!("Mining new block with previous hash {}", new_block.previous_hash);
    new_block.mine_block(4);
    
    info!("New block mined with hash {} and reward {} by {}", new_block.hash, format_units_to_tokens(reward), client_ip);
    
    chain.blocks.push(new_block);
    chain.pending_transactions.clear();
    
    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().body(format!("New block mined with reward {} and added to the chain", format_units_to_tokens(reward))))
}

// Retrieves a transaction by hash
async fn get_transaction(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing get_transaction for {}", client_ip);
    let tx_hash = path.into_inner();
    let chain = lock_chain(&data.chain, &client_ip, "get_transaction")?;

    for block in &chain.blocks {
        for tx in &block.transactions {
            if tx.hash == tx_hash {
                info!("Transaction {} retrieved by {}", tx_hash, client_ip);
                return Ok(HttpResponse::Ok().json(serde_json::json!({
                    "hash": tx.hash,
                    "from": tx.from,
                    "to": tx.to,
                    "amount": format_units_to_tokens(tx.amount),
                    "timestamp": tx.timestamp,
                    "signature": tx.signature,
                    "fee": format_units_to_tokens(tx.fee),
                    "description": tx.description
                })));
            }
        }
    }
    
    for tx in &chain.pending_transactions {
        if tx.hash == tx_hash {
            info!("Pending transaction {} retrieved by {}", tx_hash, client_ip);
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "pending",
                "transaction": {
                    "hash": tx.hash,
                    "from": tx.from,
                    "to": tx.to,
                    "amount": format_units_to_tokens(tx.amount),
                    "timestamp": tx.timestamp,
                    "signature": tx.signature,
                    "fee": format_units_to_tokens(tx.fee),
                    "description": tx.description
                }
            })));
        }
    }

    info!("Transaction {} not found by {}", tx_hash, client_ip);
    Ok(HttpResponse::NotFound().body("Transaction not found"))
}

// Blacklists a wallet
async fn blacklist_wallet(wallet_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing blacklist_wallet for {}", client_ip);
    let public_key = wallet_data["public_key"].as_str().ok_or_else(|| {
        error!("Invalid 'public_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'public_key' field")
    })?.to_string();
    let mut chain = lock_chain(&data.chain, &client_ip, "blacklist_wallet")?;

    chain.blacklisted_wallets.insert(public_key.clone(), true);
    
    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    info!("Wallet {} blacklisted by {}", public_key, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Wallet {} has been blacklisted", public_key)
    })))
}

// Unblacklists a wallet
async fn unblacklist_wallet(wallet_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing unblacklist_wallet for {}", client_ip);
    let public_key = wallet_data["public_key"].as_str().ok_or_else(|| {
        error!("Invalid 'public_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'public_key' field")
    })?.to_string();
    let mut chain = lock_chain(&data.chain, &client_ip, "unblacklist_wallet")?;

    if !chain.blacklisted_wallets.contains_key(&public_key) {
        info!("Attempt to unblacklist non-blacklisted wallet {} by {}", public_key, client_ip);
        return Ok(HttpResponse::BadRequest().body("Wallet is not blacklisted"));
    }

    chain.blacklisted_wallets.remove(&public_key);
    
    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    info!("Wallet {} unblacklisted by {}", public_key, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Wallet {} has been unblacklisted", public_key)
    })))
}

// Mints new tokens
async fn mint_tokens(mint_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let _permit = data.tx_semaphore.acquire().await
        .map_err(|_| actix_web::error::ErrorServiceUnavailable("Transaction processing limit reached"))?;
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing mint_tokens for {}", client_ip);
    let from = mint_data["from"].as_str().ok_or_else(|| {
        error!("Invalid 'from' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'from' field")
    })?.to_string();
    let to = mint_data["to"].as_str().ok_or_else(|| {
        error!("Invalid 'to' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'to' field")
    })?.to_string();
    let amount_str = mint_data["amount"].as_str().ok_or_else(|| {
        error!("Invalid 'amount' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'amount' field")
    })?.to_string();
    let private_key = mint_data["private_key"].as_str().ok_or_else(|| {
        error!("Invalid 'private_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'private_key' field")
    })?.to_string();

    let amount = parse_tokens_to_units(&amount_str).map_err(|e| {
        error!("Invalid amount {} for {}: {}", amount_str, client_ip, e);
        actix_web::error::ErrorBadRequest(e)
    })?;
    if amount < MIN_AMOUNT_UNITS {
        error!("Amount {} below minimum {} for {}", amount, MIN_AMOUNT_UNITS, client_ip);
        return Ok(HttpResponse::BadRequest().body(format!("Amount must be at least {}", format_units_to_tokens(MIN_AMOUNT_UNITS))));
    }
    if amount > MAX_AMOUNT_UNITS {
        error!("Amount {} exceeds maximum {} for {}", amount, MAX_AMOUNT_UNITS, client_ip);
        return Ok(HttpResponse::BadRequest().body("Amount exceeds maximum allowed"));
    }

    let nonce = mint_data["nonce"].as_u64().ok_or_else(|| {
        error!("Missing 'nonce' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'nonce' field")
    })?;

    let mut chain = lock_chain(&data.chain, &client_ip, "mint_tokens")?;

    let expected_nonce = chain.wallet_nonces.get(&from).cloned().unwrap_or(0);
    if nonce != expected_nonce {
        error!("Invalid nonce for {}. Expected {}, got {}.", from, expected_nonce, nonce);
        return Ok(HttpResponse::BadRequest().body(format!("Invalid nonce. Expected {}", expected_nonce)));
    }
    
    if from != data.genesis_public_key {
        error!("Unauthorized mint attempt by {} from {}", client_ip, from);
        return Ok(HttpResponse::Unauthorized().body("Only the genesis wallet can mint tokens"));
    }

    let private_key_bytes = hex::decode(&private_key).map_err(|_| {
        error!("Invalid private key format for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key format")
    })?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes).map_err(|_| {
        error!("Invalid private key for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key")
    })?;
    if hex::encode(key_pair.public_key().as_ref()) != from {
        error!("Private key mismatch for {} by {}", from, client_ip);
        return Ok(HttpResponse::Unauthorized().body("Private key does not match genesis public key"));
    }

    if chain.blacklisted_wallets.get(&to).unwrap_or(&false) == &true {
        info!("Mint attempt to blacklisted wallet {} by {}", to, client_ip);
        return Ok(HttpResponse::Forbidden().body("Receiver is blacklisted"));
    }

    let total_supply = chain.wallets.values().sum::<u64>().checked_add(amount).ok_or_else(|| {
        error!("Total supply overflow for {} by {}", client_ip, from);
        actix_web::error::ErrorBadRequest("Total supply overflow")
    })?;
    let max_wallet_balance = total_supply / 33;

    if let Some(to_balance) = chain.wallets.get(&to) {
        let new_balance = to_balance.checked_add(amount).ok_or_else(|| {
            error!("Arithmetic overflow in receiver balance for {}", client_ip);
            actix_web::error::ErrorBadRequest("Arithmetic overflow")
        })?;
        if to != data.genesis_public_key && new_balance > max_wallet_balance {
            info!("Mint would exceed 3% limit {} for {} by {}", format_units_to_tokens(max_wallet_balance), to, client_ip);
            return Ok(HttpResponse::BadRequest().body(format!("Receiver's balance would exceed 3% of total supply ({})", format_units_to_tokens(max_wallet_balance))));
        }
    }

    let message_to_sign = format!("{}{}{}", from, to, amount_str);
    let signature = key_pair.sign(message_to_sign.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());

    let timestamp = Utc::now().timestamp();
    let tx_content = format!("{}{}{}{}", from, to, amount, timestamp);
    let mut hasher = Sha256::new();
    hasher.update(tx_content.as_bytes());
    let tx_hash = hex::encode(hasher.finalize());

    let transaction = Transaction {
        hash: tx_hash.clone(),
        from: from.clone(),
        to: to.clone(),
        amount,
        timestamp,
        signature: signature_hex,
        fee: 0,
        description: "Token minting".to_string(),
        nonce,
    };
    
    chain.pending_transactions.push(transaction);
    chain.last_transaction_times.insert(data.genesis_public_key.clone(), timestamp);
    chain.wallet_nonces.insert(from.clone(), nonce + 1);

    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    info!("Minted {} tokens from {} to {} by {}", amount_str, from, to, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Minting transaction submitted successfully",
        "transaction_hash": tx_hash,
        "amount": amount_str,
        "timestamp": timestamp
    })))
}

// Burns tokens
async fn burn_tokens(burn_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let _permit = data.tx_semaphore.acquire().await
        .map_err(|_| actix_web::error::ErrorServiceUnavailable("Transaction processing limit reached"))?;
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing burn_tokens for {}", client_ip);
    let from = burn_data["from"].as_str().ok_or_else(|| {
        error!("Invalid 'from' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'from' field")
    })?.to_string();
    let amount_str = burn_data["amount"].as_str().ok_or_else(|| {
        error!("Invalid 'amount' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'amount' field")
    })?.to_string();
    let private_key = burn_data["private_key"].as_str().ok_or_else(|| {
        error!("Invalid 'private_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'private_key' field")
    })?.to_string();

    let amount = parse_tokens_to_units(&amount_str).map_err(|e| {
        error!("Invalid amount {} for {}: {}", amount_str, client_ip, e);
        actix_web::error::ErrorBadRequest(e)
    })?;
    if amount < MIN_AMOUNT_UNITS {
        error!("Amount {} below minimum {} for {}", amount, MIN_AMOUNT_UNITS, client_ip);
        return Ok(HttpResponse::BadRequest().body(format!("Amount must be at least {}", format_units_to_tokens(MIN_AMOUNT_UNITS))));
    }
    if amount > MAX_AMOUNT_UNITS {
        error!("Amount {} exceeds maximum {} for {}", amount, MAX_AMOUNT_UNITS, client_ip);
        return Ok(HttpResponse::BadRequest().body("Amount exceeds maximum allowed"));
    }

    // At the start of the function, after parsing other fields
    let nonce = burn_data["nonce"].as_u64().ok_or_else(|| {
        error!("Missing 'nonce' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Missing 'nonce' field")
    })?;

    let mut chain = lock_chain(&data.chain, &client_ip, "burn_tokens")?;

    // Validate nonce
    let expected_nonce = chain.wallet_nonces.get(&from).cloned().unwrap_or(0);
    if nonce != expected_nonce {
        error!("Invalid nonce for {}. Expected {}, got {}.", from, expected_nonce, nonce);
        return Ok(HttpResponse::BadRequest().body(format!("Invalid nonce. Expected {}", expected_nonce)));
    }
    
    if chain.blacklisted_wallets.get(&from).unwrap_or(&false) == &true {
        info!("Burn attempt by blacklisted wallet {} by {}", from, client_ip);
        return Ok(HttpResponse::Forbidden().body("Wallet is blacklisted"));
    }

    let current_time = Utc::now().timestamp();
    if let Some(last_tx_time) = chain.last_transaction_times.get(&from) {
        if current_time - last_tx_time < 30 {
            info!("Burn cooldown violation for {} by {}", from, client_ip);
            return Ok(HttpResponse::BadRequest().body("Transaction cooldown: 30 seconds not elapsed"));
        }
    }

    let from_balance = chain.wallets.get(&from).cloned().unwrap_or(0);
    if amount > from_balance {
        info!("Insufficient funds for burn by {} (required: {}, available: {}) by {}", from, format_units_to_tokens(amount), format_units_to_tokens(from_balance), client_ip);
        return Ok(HttpResponse::BadRequest().body("Insufficient funds to burn"));
    }

    let private_key_bytes = hex::decode(&private_key).map_err(|_| {
        error!("Invalid private key format for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key format")
    })?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes).map_err(|_| {
        error!("Invalid private key for {} by {}", from, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key")
    })?;
    if hex::encode(key_pair.public_key().as_ref()) != from {
        error!("Private key mismatch for {} by {}", from, client_ip);
        return Ok(HttpResponse::Unauthorized().body("Private key does not match sender's public key"));
    }

    let message_to_sign = format!("{}burn{}", from, amount_str);
    let signature = key_pair.sign(message_to_sign.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());

    let total_supply: u64 = chain.wallets.values().sum();
    let max_tx_amount = total_supply / 50;
    if amount > max_tx_amount {
        info!("Burn amount {} exceeds 2% limit {} for {} by {}", amount, max_tx_amount, from, client_ip);
        return Ok(HttpResponse::BadRequest().body(format!("Burn amount exceeds 2% of total supply ({})", format_units_to_tokens(max_tx_amount))));
    }

    let timestamp = current_time;
    let tx_content = format!("{}burn{}{}", from, amount, timestamp);
    let mut hasher = Sha256::new();
    hasher.update(tx_content.as_bytes());
    let tx_hash = hex::encode(hasher.finalize());

    let transaction = Transaction {
        hash: tx_hash.clone(),
        from: from.clone(),
        to: String::from("burn"),
        amount,
        timestamp,
        signature: signature_hex,
        fee: 0,
        description: "Token burning".to_string(),
        nonce,
    };
    
    chain.pending_transactions.push(transaction);
    chain.last_transaction_times.insert(from.clone(), timestamp);
    chain.wallet_nonces.insert(from.clone(), nonce + 1);

    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    info!("Burned {} tokens from {} by {}", amount_str, from, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Burning transaction submitted successfully",
        "transaction_hash": tx_hash,
        "amount": amount_str,
        "timestamp": timestamp
    })))
}

// Deletes a wallet if it has zero balance
async fn delete_wallet(wallet_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing delete_wallet for {}", client_ip);
    let public_key = wallet_data["public_key"].as_str().ok_or_else(|| {
        error!("Invalid 'public_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'public_key' field")
    })?.to_string();
    let private_key = wallet_data["private_key"].as_str().ok_or_else(|| {
        error!("Invalid 'private_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'private_key' field")
    })?.to_string();

    let mut chain = lock_chain(&data.chain, &client_ip, "delete_wallet")?;
    let mut identity_hashes = lock_identity_hashes(&data.identity_hashes, &client_ip, "delete_wallet")?;
    
    if chain.blacklisted_wallets.get(&public_key).unwrap_or(&false) == &true {
        info!("Delete attempt for blacklisted wallet {} by {}", public_key, client_ip);
        return Ok(HttpResponse::Forbidden().body("Wallet is blacklisted"));
    }

    let balance = chain.wallets.get(&public_key).cloned().unwrap_or(0);
    if balance > 0 {
        info!("Delete attempt for wallet {} with non-zero balance {} by {}", public_key, format_units_to_tokens(balance), client_ip);
        return Ok(HttpResponse::BadRequest().body("Wallet has non-zero balance"));
    }

    let private_key_bytes = hex::decode(&private_key).map_err(|_| {
        error!("Invalid private key format for {} by {}", public_key, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key format")
    })?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes).map_err(|_| {
        error!("Invalid private key for {} by {}", public_key, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key")
    })?;
    if hex::encode(key_pair.public_key().as_ref()) != public_key {
        error!("Private key mismatch for {} by {}", public_key, client_ip);
        return Ok(HttpResponse::Unauthorized().body("Private key does not match public key"));
    }

    chain.wallets.remove(&public_key);
    chain.last_transaction_times.remove(&public_key);
    chain.blacklisted_wallets.remove(&public_key);
    identity_hashes.retain(|_, (pub_key, _)| pub_key != &public_key);

    let serialized_chain = serde_json::to_string(&*chain).map_err(|e| {
        error!("Serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_data = encrypt_data(&data.cipher, serialized_chain.as_bytes()).map_err(|e| {
        error!("Encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("chain", encrypted_data).map_err(|e| {
        error!("Database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let serialized_hashes = serde_json::to_string(&*identity_hashes).map_err(|e| {
        error!("Identity hashes serialization failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Serialization failed")
    })?;
    let encrypted_hashes = encrypt_data(&data.cipher, serialized_hashes.as_bytes()).map_err(|e| {
        error!("Identity hashes encryption failed for {}: {}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database encryption failed")
    })?;
    data.db.insert("identity_hashes", encrypted_hashes).map_err(|e| {
        error!("Identity hashes database insert failed for {}: {:?}", client_ip, e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    info!("Wallet {} deleted by {}", public_key, client_ip);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Wallet {} deleted successfully", public_key)
    })))
}

// Lists all wallets except the genesis wallet (genesis wallet only)
async fn list_all_wallets(wallet_data: web::Json<serde_json::Value>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing list_all_wallets for {}", client_ip);
    let public_key = wallet_data["public_key"].as_str().ok_or_else(|| {
        error!("Invalid 'public_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'public_key' field")
    })?.to_string();
    let private_key = wallet_data["private_key"].as_str().ok_or_else(|| {
        error!("Invalid 'private_key' field for {}", client_ip);
        actix_web::error::ErrorBadRequest("Invalid 'private_key' field")
    })?.to_string();

    if public_key != data.genesis_public_key {
        error!("Unauthorized list wallets attempt by {} from {}", client_ip, public_key);
        return Ok(HttpResponse::Unauthorized().body("Only the genesis wallet can list all wallets"));
    }

    let private_key_bytes = hex::decode(&private_key).map_err(|_| {
        error!("Invalid private key format for {} by {}", public_key, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key format")
    })?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_bytes).map_err(|_| {
        error!("Invalid private key for {} by {}", public_key, client_ip);
        actix_web::error::ErrorBadRequest("Invalid private key")
    })?;
    if hex::encode(key_pair.public_key().as_ref()) != public_key {
        error!("Private key mismatch for {} by {}", public_key, client_ip);
        return Ok(HttpResponse::Unauthorized().body("Private key does not match genesis public key"));
    }

    let chain = lock_chain(&data.chain, &client_ip, "list_all_wallets")?;
    let wallets: Vec<_> = chain.wallets.iter()
        .filter(|(pub_key, _)| *pub_key != &data.genesis_public_key)
        .map(|(pub_key, balance)| {
            serde_json::json!({
                "public_key": pub_key,
                "balance": format_units_to_tokens(*balance),
                "blacklisted": chain.blacklisted_wallets.get(pub_key).unwrap_or(&false)
            })
        })
        .collect();

    info!("Wallet list retrieved by genesis wallet for {}", client_ip);
    Ok(HttpResponse::Ok().json(wallets))
}

// Retrieves server logs
async fn get_logs(_data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing get_logs for {}", client_ip);
    let log_dir = Path::new("data/logs");
    let mut logs = String::new();

    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                logs.push_str(&content);
                logs.push_str("\n");
            }
        }
    } else {
        error!("Failed to read logs for {}", client_ip);
        return Ok(HttpResponse::InternalServerError().body("Failed to read logs"));
    }

    info!("Logs retrieved by {}", client_ip);
    Ok(HttpResponse::Ok().body(logs))
}

// Lists all blocks
async fn get_blocks(data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing get_blocks for {}", client_ip);
    let chain = lock_chain(&data.chain, &client_ip, "get_blocks")?;
    let blocks: Vec<_> = chain.blocks.iter().map(|block| {
        serde_json::json!({
            "timestamp": block.timestamp,
            "transactions": block.transactions.iter().map(|tx| {
                serde_json::json!({
                    "hash": tx.hash,
                    "from": tx.from,
                    "to": tx.to,
                    "amount": format_units_to_tokens(tx.amount),
                    "timestamp": tx.timestamp,
                    "signature": tx.signature,
                    "fee": format_units_to_tokens(tx.fee),
                    "description": tx.description
                })
            }).collect::<Vec<_>>(),
            "previous_hash": block.previous_hash,
            "hash": block.hash,
            "nonce": block.nonce
        })
    }).collect();
    info!("Blocks retrieved by {}", client_ip);
    Ok(HttpResponse::Ok().json(blocks))
}

// Retrieves blockchain stats
async fn get_stats(data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing get_stats for {}", client_ip);
    let chain = lock_chain(&data.chain, &client_ip, "get_stats")?;
    let total_transactions: usize = chain.blocks.iter().map(|b| b.transactions.len()).sum::<usize>() + chain.pending_transactions.len();
    let total_supply: u64 = chain.wallets.values().sum();
    let genesis_balance = chain.wallets.get(&data.genesis_public_key).cloned().unwrap_or(0);
    let circulating_supply = total_supply.saturating_sub(genesis_balance);
    let stats = serde_json::json!({
        "block_count": chain.blocks.len(),
        "transaction_count": total_transactions,
        "wallet_count": chain.wallets.len(),
        "total_supply": format_units_to_tokens(total_supply),
        "circulating_supply": format_units_to_tokens(circulating_supply),
    });
    info!("Stats retrieved by {}", client_ip);
    Ok(HttpResponse::Ok().json(stats))
}

async fn get_nonce(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let client_ip = req.connection_info().peer_addr().unwrap_or("unknown").to_string();
    debug!("Processing get_nonce for {}", client_ip);
    let public_key = path.into_inner();
    let chain = lock_chain(&data.chain, &client_ip, "get_nonce")?;

    if chain.blacklisted_wallets.get(&public_key).unwrap_or(&false) == &true {
        info!("Nonce check for blacklisted wallet {} by {}", public_key, client_ip);
        return Ok(HttpResponse::Forbidden().body("Wallet is blacklisted"));
    }

    match chain.wallet_nonces.get(&public_key) {
        Some(&nonce) => {
            info!("Nonce for {} retrieved by {}: {}", public_key, client_ip, nonce);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "public_key": public_key,
                "nonce": nonce
            })))
        }
        None => {
            if chain.wallets.contains_key(&public_key) {
                info!("Nonce for {} retrieved by {}: 0 (no prior transactions)", public_key, client_ip);
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "public_key": public_key,
                    "nonce": 0
                })))
            } else {
                info!("Nonce check for non-existent wallet {} by {}", public_key, client_ip);
                Ok(HttpResponse::NotFound().body("Wallet not found"))
            }
        }
    }
}

/// If decryption fails, it triggers a restore and retries once.
async fn load_or_restore_chain(db: &sled::Db, cipher: &Aes256Gcm, genesis_public_key: &str) -> io::Result<Chain> {
    match db.get("chain") {
        Ok(Some(data)) => {
            // Try to decrypt
            match decrypt_data(cipher, &data) {
                Ok(decrypted) => {
                    // If decryption is successful, deserialize
                    serde_json::from_slice(&decrypted).map_err(|e| {
                        error!("Database deserialization failed after successful decryption: {:?}", e);
                        io::Error::new(io::ErrorKind::Other, format!("Deserialization error: {:?}", e))
                    })
                }
                Err(e) => {
                    // THIS IS THE CRITICAL PART: Decryption failed, indicating corruption.
                    error!("Database decryption failed: {}. ATTEMPTING RESTORE.", e);
                    
                    // 1. Attempt to restore from S3
                    if let Err(restore_err) = backup::restore_from_s3().await {
                        error!("FATAL: Restore from S3 failed: {}. Cannot start server.", restore_err);
                        return Err(io::Error::new(io::ErrorKind::Other, "DB is corrupted and restore from backup failed."));
                    }

                    // 2. If restore was successful, try loading the DB again.
                    info!("Restore successful. Reloading database...");
                    match db.get("chain") {
                         Ok(Some(restored_data)) => {
                            let decrypted = decrypt_data(cipher, &restored_data).map_err(|e| {
                                error!("FATAL: Decryption failed even after restoring backup: {}", e);
                                io::Error::new(io::ErrorKind::Other, "Restored DB is also corrupted.")
                            })?;
                            serde_json::from_slice(&decrypted).map_err(|e| {
                                error!("FATAL: Deserialization of restored DB failed: {:?}", e);
                                io::Error::new(io::ErrorKind::Other, "Could not deserialize restored DB.")
                            })
                         },
                         _ => {
                             error!("FATAL: Could not read chain from DB after restore.");
                             Err(io::Error::new(io::ErrorKind::Other, "DB read failed after restore."))
                         }
                    }
                }
            }
        }
        Ok(None) => {
            info!("No existing blockchain found. Creating a new one.");
            Ok(Chain::new(genesis_public_key.to_string()))
        },
        Err(e) => {
            error!("Initial database read failed: {:?}", e);
            Err(io::Error::new(io::ErrorKind::Other, format!("Database read error: {:?}", e)))
        }
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <bearer_token>", args[0]);
        std::process::exit(1);
    }
    let bearer_token = args[1].clone();

    let mut hasher = Sha256::new();
    hasher.update(bearer_token.as_bytes());
    let key_bytes: [u8; 32] = hasher.finalize().into();
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Invalid key length");

    if let Err(e) = setup_directories() {
        eprintln!("Failed to setup directories: {:?}", e);
        std::process::exit(1);
    }
    if let Err(e) = setup_logging() {
        eprintln!("Failed to setup logging: {:?}", e);
        std::process::exit(1);
    }

    let genesis_wallet = load_or_create_genesis_wallet().map_err(|e| {
        eprintln!("Failed to load or create genesis wallet: {:?}", e);
        io::Error::new(io::ErrorKind::Other, format!("Genesis wallet error: {:?}", e))
    })?;

    let db_path = Path::new("data/db/blockchain_db_v2");
    let db = sled::open(db_path).map_err(|e| {
        error!("Failed to open database: {:?}", e);
        io::Error::new(io::ErrorKind::Other, format!("Database open error: {:?}", e))
    })?;

    let initial_chain = match load_or_restore_chain(&db, &cipher, &genesis_wallet.public_key).await {
        Ok(chain) => chain,
        Err(e) => {
            eprintln!("\nFATAL ERROR: Could not load the blockchain.\nError: {}\nExiting.", e);
            process::exit(1);
        }
    };

    let identity_hashes = match db.get("identity_hashes") {
        Ok(Some(data)) => {
            let decrypted = decrypt_data(&cipher, &data).map_err(|e| {
                error!("Identity hashes decryption failed: {}", e);
                io::Error::new(io::ErrorKind::Other, format!("Decryption error: {}", e))
            })?;
            serde_json::from_slice(&decrypted).map_err(|e| {
                error!("Identity hashes deserialization failed: {:?}", e);
                io::Error::new(io::ErrorKind::Other, format!("Deserialization error: {:?}", e))
            })?
        }
        Ok(None) => HashMap::new(),
        Err(e) => {
            error!("Identity hashes database read failed: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, format!("Database read error: {:?}", e)));
        }
    };

    let scheduler = JobScheduler::new().await.expect("Failed to create scheduler");

    // Clone the db handle to be moved into the async closure for the backup job.
    let db_for_backup = db.clone();

    scheduler.add(
        Job::new_async("0 0 */6 * * *", move |_, _| { // Runs every 6 hours
            // The 'move' keyword takes ownership of db_for_backup.
            // We clone it again here for use inside this specific job run.
            let db_clone = db_for_backup.clone();
            Box::pin(async move {
                info!("Starting scheduled backup...");
                // Pass the database handle to the backup function.
                if let Err(e) = backup::backup_to_s3(&db_clone).await {
                    error!("Scheduled backup failed: {}", e);
                } else {
                    info!("Scheduled backup completed successfully.");
                }
            })
        })
        .expect("Failed to create backup job"),
    )
    .await
    .expect("Failed to add backup job to scheduler");

    scheduler.start().await.expect("Failed to start scheduler");
    info!("Periodic backup scheduler started. Backups will run every 6 hours.");

    
    let app_state = web::Data::new(AppState {
        db,
        chain: Mutex::new(initial_chain),
        genesis_public_key: genesis_wallet.public_key,
        bearer_token,
        cipher,
        tx_semaphore: Arc::new(Semaphore::new(10)),
        identity_hashes: Mutex::new(identity_hashes),
    });

    info!("Server started at http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(Logger::default())
            .wrap(HttpAuthentication::bearer(validate_token))
            .route("/create_wallet", web::post().to(create_wallet))
            .route("/balance/{public_key}", web::get().to(get_balance))
            .route("/send", web::post().to(send_token))
            .route("/mine", web::post().to(mine_pending_transactions))
            .route("/transaction/{hash}", web::get().to(get_transaction))
            .route("/blacklist", web::post().to(blacklist_wallet))
            .route("/unblacklist", web::post().to(unblacklist_wallet))
            .route("/mint", web::post().to(mint_tokens))
            .route("/burn", web::post().to(burn_tokens))
            .route("/delete_wallet", web::post().to(delete_wallet))
            .route("/list_all_wallets", web::post().to(list_all_wallets))
            .route("/logs", web::get().to(get_logs))
            .route("/blocks", web::get().to(get_blocks))
            .route("/stats", web::get().to(get_stats))
            .route("/nonce/{public_key}", web::get().to(get_nonce))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}