# Block Money

Block Money is a Rust-based blockchain application that provides a secure, decentralized ledger for managing digital assets. It features a complete set of tools for wallet management, transaction processing, mining, and automated backups to S3-compatible storage.

## Features

- **Blockchain Core**: Implements a chain of blocks containing transactions, secured by Proof-of-Work (PoW).
- **Wallet Management**:
  - Secure wallet creation with personal details (First Name, Last Name, DOB, Gender).
  - Identity hashing to prevent duplicate wallets for the same person.
  - Ed25519 digital signatures for transaction security.
  - Wallet blacklisting and unblacklisting.
  - Wallet deletion (for zero-balance wallets).
- **Transactions**:
  - Send tokens between wallets.
  - 1% transaction fee (sent to the Genesis wallet).
  - Transaction cooldowns (30 seconds) to prevent spam.
  - Limits on transaction amounts (max 2% of total supply) and wallet balances (max 3% of total supply).
  - Minting and Burning tokens (Genesis wallet only for minting, any wallet for burning).
- **Mining**:
  - Proof-of-Work mining to validate pending transactions and add them to the blockchain.
  - Mining rewards.
- **Security**:
  - Bearer Token authentication for all API endpoints.
  - AES-256-GCM encryption for database storage (at rest).
  - Input validation using Regex.
  - Rate limiting (Semaphore-based concurrency control).
- **Storage & Backup**:
  - Uses `sled` embedded database for high-performance storage.
  - Automated backups to S3-compatible storage every 6 hours.
  - Automatic restore from S3 if the local database is corrupted or missing.
- **Observability**:
  - Comprehensive logging to file and stdout using `fern` and `log`.
  - API endpoints for retrieving logs and blockchain statistics.

## Prerequisites

- **Rust**: Ensure you have Rust installed (version 1.70 or later recommended).
- **S3 Compatible Storage**: You need an S3 bucket (e.g., AWS S3, MinIO) for backups.

## Configuration

Create a `config.json` file in the root directory with your S3 configuration:

```json
{
  "s3_endpoint": "http://127.0.0.1:9000",
  "s3_bucket": "cbm",
  "s3_access_key": "YOUR_ACCESS_KEY",
  "s3_secret_key": "YOUR_SECRET_KEY",
  "s3_region": "us-east-1"
}
```

## Building and Running

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd block_money
    ```

2.  **Build the project:**
    ```bash
    cargo build --release
    ```

3.  **Run the application:**
    You must provide a Bearer Token as a command-line argument. This token will be required for all API requests.

    ```bash
    cargo run -- <YOUR_BEARER_TOKEN>
    ```

    Example:
    ```bash
    cargo run -- mysecrettoken
    ```

    The server will start at `http://127.0.0.1:1200`.

## API Documentation

All API requests must include the `Authorization` header:
`Authorization: Bearer <YOUR_BEARER_TOKEN>`

### Wallet Management

#### Create Wallet
Creates a new wallet. Returns a private and public key.
- **Endpoint**: `POST /create_wallet`
- **Body**:
  ```json
  {
    "first_name": "John",
    "last_name": "Doe",
    "dob": "01-01-1990",
    "gender": "male"
  }
  ```

#### Get Balance
Retrieves the balance of a wallet.
- **Endpoint**: `GET /balance/{public_key}`

#### Delete Wallet
Deletes a wallet (must have 0 balance).
- **Endpoint**: `POST /delete_wallet`
- **Body**:
  ```json
  {
    "public_key": "...",
    "private_key": "..."
  }
  ```

#### List All Wallets (Genesis Only)
Lists all wallets in the system.
- **Endpoint**: `POST /list_all_wallets`
- **Body**:
  ```json
  {
    "public_key": "<GENESIS_PUBLIC_KEY>",
    "private_key": "<GENESIS_PRIVATE_KEY>"
  }
  ```

### Transactions

#### Send Tokens
Sends tokens from one wallet to another.
- **Endpoint**: `POST /send`
- **Body**:
  ```json
  {
    "from": "<SENDER_PUBLIC_KEY>",
    "to": "<RECEIVER_PUBLIC_KEY>",
    "amount": "10.0",
    "private_key": "<SENDER_PRIVATE_KEY>",
    "description": "Payment for services",
    "nonce": <NONCE>
  }
  ```

#### Get Nonce
Retrieves the next nonce for a wallet (required for transactions).
- **Endpoint**: `GET /nonce/{public_key}`

#### Get Transaction
Retrieves transaction details by hash.
- **Endpoint**: `GET /transaction/{hash}`

#### Mint Tokens (Genesis Only)
Mints new tokens to a specific wallet.
- **Endpoint**: `POST /mint`
- **Body**:
  ```json
  {
    "from": "<GENESIS_PUBLIC_KEY>",
    "to": "<RECEIVER_PUBLIC_KEY>",
    "amount": "100.0",
    "private_key": "<GENESIS_PRIVATE_KEY>",
    "nonce": <NONCE>
  }
  ```

#### Burn Tokens
Burns tokens from a wallet.
- **Endpoint**: `POST /burn`
- **Body**:
  ```json
  {
    "from": "<WALLET_PUBLIC_KEY>",
    "amount": "5.0",
    "private_key": "<WALLET_PRIVATE_KEY>",
    "nonce": <NONCE>
  }
  ```

### Mining

#### Mine Pending Transactions
Mines a new block containing pending transactions.
- **Endpoint**: `POST /mine`

### Administrative

#### Blacklist Wallet
Blacklists a wallet, preventing it from transacting.
- **Endpoint**: `POST /blacklist`
- **Body**:
  ```json
  {
    "public_key": "..."
  }
  ```

#### Unblacklist Wallet
Removes a wallet from the blacklist.
- **Endpoint**: `POST /unblacklist`
- **Body**:
  ```json
  {
    "public_key": "..."
  }
  ```

### Information

#### Get Blocks
Retrieves the entire blockchain.
- **Endpoint**: `GET /blocks`

#### Get Stats
Retrieves blockchain statistics (block count, transaction count, supply, etc.).
- **Endpoint**: `GET /stats`

#### Get Logs
Retrieves server logs.
- **Endpoint**: `GET /logs`

## Backup and Restore

- **Backup**: The system automatically backs up the database and logs to the configured S3 bucket every 6 hours.
- **Restore**: On startup, if the local database is corrupted or missing, the system will attempt to download and restore the latest backup from S3.

## Data Storage

Data is stored in the `data/` directory:
- `data/db/`: Contains the `sled` database files.
- `data/logs/`: Contains application logs.
- `data/genesis_wallet.json`: Stores the Genesis wallet keys (created on first run).
