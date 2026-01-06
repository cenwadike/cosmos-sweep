use cosmos_client::signer::Signer;
use cosmrs::tx::Msg;
use cosmrs::{
    AccountId, Coin, Denom,
    bank::MsgSend,
    tx::{Body, Fee, Raw, SignDoc, SignerInfo},
};
use csv::ReaderBuilder;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::time::Instant;

const CHAIN_ID: &str = "cosmoshub-4";
const BASE_DENOM: &str = "uatom";
const GAS_LIMIT: u64 = 120_000;
const BASE_FEE_AMOUNT: u128 = 1_000; // Fee in uatom for each transaction

#[derive(Debug)]
struct WalletEntry {
    seed_phrase: String,
    address: String,
}

#[derive(Debug, Clone)]
struct TokenBalance {
    denom: String,
    amount: u128,
}

#[derive(Debug, Default)]
struct AccountingRecord {
    wallet_address: String,
    denom: String,
    balance: u128,
    amount_sent: u128,
    gas_fee: u128, // Only applies to ATOM
    success: bool,
    tx_hash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default)]
struct GlobalAccounting {
    total_wallets: usize,
    successful_transfers: usize,
    failed_transfers: usize,
    skipped_wallets: usize,
    // Per-denom tracking
    balances_by_denom: HashMap<String, u128>,
    sent_by_denom: HashMap<String, u128>,
    remaining_by_denom: HashMap<String, u128>,
    total_gas_fees_paid: u128,
    records: Vec<AccountingRecord>,
}

impl GlobalAccounting {
    fn new() -> Self {
        Self::default()
    }

    fn add_record(&mut self, record: AccountingRecord) {
        *self
            .balances_by_denom
            .entry(record.denom.clone())
            .or_insert(0) += record.balance;

        if record.success {
            self.successful_transfers += 1;
            *self.sent_by_denom.entry(record.denom.clone()).or_insert(0) += record.amount_sent;
            self.total_gas_fees_paid += record.gas_fee;
        } else if record.error.is_some() {
            self.failed_transfers += 1;
            *self
                .remaining_by_denom
                .entry(record.denom.clone())
                .or_insert(0) += record.balance;
        }

        self.records.push(record);
    }

    fn add_skipped(&mut self, wallet_address: String, denom: String, balance: u128, reason: &str) {
        self.skipped_wallets += 1;
        *self.balances_by_denom.entry(denom.clone()).or_insert(0) += balance;
        *self.remaining_by_denom.entry(denom.clone()).or_insert(0) += balance;

        self.records.push(AccountingRecord {
            wallet_address,
            denom,
            balance,
            amount_sent: 0,
            gas_fee: 0,
            success: false,
            tx_hash: None,
            error: Some(reason.to_string()),
        });
    }

    fn print_summary(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║                    ACCOUNTING SUMMARY                         ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");

        println!("\n📊 WALLET STATISTICS:");
        println!("   Total Wallets Processed:    {}", self.total_wallets);
        println!(
            "   ✓ Successful Transfers:     {}",
            self.successful_transfers
        );
        println!("   ✗ Failed Transfers:         {}", self.failed_transfers);
        println!("   ⊘ Skipped Operations:       {}", self.skipped_wallets);

        println!("\n💰 BALANCE SUMMARY BY TOKEN:");

        // Sort denoms for consistent display
        let mut denoms: Vec<_> = self.balances_by_denom.keys().collect();
        denoms.sort();

        for denom in denoms {
            let balance = self.balances_by_denom.get(denom).unwrap_or(&0);
            let sent = self.sent_by_denom.get(denom).unwrap_or(&0);
            let remaining = self.remaining_by_denom.get(denom).unwrap_or(&0);

            println!("\n   Token: {}", denom);
            println!("   ├─ Total Found:       {}", format_token(*balance, denom));
            println!("   ├─ Total Sent:        {}", format_token(*sent, denom));
            println!(
                "   └─ Total Remaining:   {}",
                format_token(*remaining, denom)
            );

            if *balance > 0 {
                let efficiency = (*sent as f64 / *balance as f64) * 100.0;
                println!("      Transfer Efficiency: {:.2}%", efficiency);
            }
        }

        println!("\n⛽ GAS FEES (paid in ATOM):");
        println!(
            "   Total Gas Fees Paid:        {} uatom ({:.6} ATOM)",
            self.total_gas_fees_paid,
            self.total_gas_fees_paid as f64 / 1_000_000.0
        );

        println!("\n📋 DETAILED RECORDS:");
        println!(
            "   {:<45} {:<20} {:<15} {:<15} {:<12} {:<10}",
            "Address", "Token", "Balance", "Sent", "Gas Fee", "Status"
        );
        println!("   {}", "─".repeat(120));

        for record in &self.records {
            let status = if record.success {
                "✓ Success"
            } else if record
                .error
                .as_ref()
                .map_or(false, |e| e.contains("Skipped"))
            {
                "⊘ Skipped"
            } else {
                "✗ Failed"
            };

            println!(
                "   {:<45} {:<20} {:<15} {:<15} {:<12} {:<10}",
                &record.wallet_address[..record.wallet_address.len().min(45)],
                &record.denom[..record.denom.len().min(20)],
                format_token(record.balance, &record.denom),
                format_token(record.amount_sent, &record.denom),
                if record.gas_fee > 0 {
                    format!("{:.6} ATOM", record.gas_fee as f64 / 1_000_000.0)
                } else {
                    "N/A".to_string()
                },
                status
            );

            if let Some(tx_hash) = &record.tx_hash {
                println!("      TX: {}", tx_hash);
            }
            if let Some(error) = &record.error {
                println!("      Error: {}", error);
            }
        }

        println!("\n═══════════════════════════════════════════════════════════════");
    }

    fn save_to_csv(&self, filename: &str) -> Result<(), Box<dyn Error>> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(filename)?;

        // Write header
        writeln!(
            file,
            "wallet_address,denom,balance_raw,balance_formatted,amount_sent_raw,amount_sent_formatted,gas_fee_uatom,gas_fee_atom,status,tx_hash,error"
        )?;

        // Write records
        for record in &self.records {
            let status = if record.success {
                "success"
            } else if record
                .error
                .as_ref()
                .map_or(false, |e| e.contains("Skipped"))
            {
                "skipped"
            } else {
                "failed"
            };

            writeln!(
                file,
                "{},{},{},{},{},{},{},{:.6},{},{},{}",
                record.wallet_address,
                record.denom,
                record.balance,
                format_token(record.balance, &record.denom),
                record.amount_sent,
                format_token(record.amount_sent, &record.denom),
                record.gas_fee,
                record.gas_fee as f64 / 1_000_000.0,
                status,
                record.tx_hash.as_deref().unwrap_or(""),
                record.error.as_deref().unwrap_or("")
            )?;
        }

        // Write summary
        writeln!(file, "\nSUMMARY")?;
        writeln!(file, "total_wallets,{}", self.total_wallets)?;
        writeln!(file, "successful_transfers,{}", self.successful_transfers)?;
        writeln!(file, "failed_transfers,{}", self.failed_transfers)?;
        writeln!(file, "skipped_operations,{}", self.skipped_wallets)?;
        writeln!(
            file,
            "total_gas_fees_paid_uatom,{}",
            self.total_gas_fees_paid
        )?;
        writeln!(
            file,
            "total_gas_fees_paid_atom,{:.6}",
            self.total_gas_fees_paid as f64 / 1_000_000.0
        )?;

        writeln!(file, "\nBALANCES_BY_TOKEN")?;
        let mut denoms: Vec<_> = self.balances_by_denom.keys().collect();
        denoms.sort();
        for denom in denoms {
            let balance = self.balances_by_denom.get(denom).unwrap_or(&0);
            let sent = self.sent_by_denom.get(denom).unwrap_or(&0);
            let remaining = self.remaining_by_denom.get(denom).unwrap_or(&0);
            writeln!(file, "{},{},{},{}", denom, balance, sent, remaining)?;
        }

        Ok(())
    }
}

fn format_token(amount: u128, denom: &str) -> String {
    // Format based on denom
    if denom == "uatom" {
        format!("{:.6} ATOM", amount as f64 / 1_000_000.0)
    } else if denom.starts_with("ibc/") {
        // IBC tokens - show raw amount since we don't know the decimals
        format!("{}", amount)
    } else {
        // Other tokens
        format!("{}", amount)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let start_time = Instant::now();

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <csv_file> <destination_address>", args[0]);
        eprintln!("\nExample: {} wallets.csv cosmos1abc123...", args[0]);
        std::process::exit(1);
    }

    let csv_path = &args[1];
    let dest_address = &args[2];

    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║             COSMOS HUB WALLET SWEEP TOOL                      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Initialize accounting
    let mut accounting = GlobalAccounting::new();

    // Verify destination address is valid
    println!("🔍 Validating destination address...");
    let _dest_account_id = match dest_address.parse::<AccountId>() {
        Ok(addr) => {
            println!("   ✓ Destination address is valid: {}", addr);
            addr
        }
        Err(e) => {
            eprintln!("   ✗ Invalid destination address: {}", e);
            std::process::exit(1);
        }
    };

    // Verify destination has ATOM balance (for paying fees)
    println!("\n🔍 Checking destination ATOM balance (for fees)...");
    match get_balance(&dest_address, BASE_DENOM).await {
        Ok(balance) => {
            println!(
                "   ✓ Destination has {} uatom ({:.6} ATOM)",
                balance,
                balance as f64 / 1_000_000.0
            );
        }
        Err(e) => {
            eprintln!("   ✗ Destination check failed: {}", e);
            std::process::exit(1);
        }
    }

    // Read CSV file
    println!("\n📂 Reading wallet file: {}", csv_path);
    let entries = match read_csv(csv_path) {
        Ok(e) => {
            println!("   ✓ Loaded {} wallet entries", e.len());
            e
        }
        Err(e) => {
            eprintln!("   ✗ Failed to read CSV: {}", e);
            std::process::exit(1);
        }
    };

    accounting.total_wallets = entries.len();

    println!("{}", "═".repeat(67));
    println!("STARTING WALLET PROCESSING");
    println!("{}", "═".repeat(67));

    // Process each wallet
    for (index, entry) in entries.iter().enumerate() {
        println!("┌─────────────────────────────────────────────────────────────────┐");
        println!(
            "│ Wallet {}/{}: Processing...                                     │",
            index + 1,
            entries.len()
        );
        println!("└─────────────────────────────────────────────────────────────────┘");
        println!("   CSV Address: {}", entry.address);

        // Derive address from seed phrase
        let derived_address =
            match derive_address_from_seed(&entry.seed_phrase, "cosmos", BASE_DENOM) {
                Ok(addr) => {
                    println!("   Derived:     {}", addr);
                    addr
                }
                Err(e) => {
                    eprintln!("   ✗ Failed to derive address: {}", e);
                    accounting.add_skipped(
                        entry.address.clone(),
                        "N/A".to_string(),
                        0,
                        &format!("Derivation failed: {}", e),
                    );
                    continue;
                }
            };

        // Verify addresses match
        if entry.address != derived_address {
            eprintln!("   ✗ Address mismatch! CSV ≠ Derived");
            accounting.add_skipped(
                entry.address.clone(),
                "N/A".to_string(),
                0,
                "Address mismatch",
            );
            continue;
        }
        println!("   ✓ Addresses match!");

        // Get ALL balances for this wallet
        let balances = match get_all_balances(&entry.address).await {
            Ok(b) => {
                println!("   Found {} token type(s):", b.len());
                for balance in &b {
                    println!(
                        "      - {}: {}",
                        balance.denom,
                        format_token(balance.amount, &balance.denom)
                    );
                }
                b
            }
            Err(e) => {
                eprintln!("   ✗ Failed to get balances: {}", e);
                accounting.add_skipped(
                    entry.address.clone(),
                    "N/A".to_string(),
                    0,
                    &format!("Balance check failed: {}", e),
                );
                continue;
            }
        };

        if balances.is_empty() {
            println!("   ⊘ No balances to transfer, skipping.");
            accounting.add_skipped(
                entry.address.clone(),
                "N/A".to_string(),
                0,
                "Skipped: Zero balance",
            );
            continue;
        }

        // ──────────────────────────────────────────────────────────────────
        // PROCESS TOKENS: NON-ATOM FIRST, ATOM LAST
        // ──────────────────────────────────────────────────────────────────

        let mut other_tokens: Vec<TokenBalance> = Vec::new();
        let mut atom_balance: u128 = 0;

        for balance in &balances {
            if balance.denom == BASE_DENOM {
                atom_balance = balance.amount;
            } else if balance.amount > 0 {
                other_tokens.push(balance.clone());
            }
        }

        // Count how many transactions we will need for non-ATOM tokens
        let non_atom_tx_count = other_tokens.len() as u128;
        let gas_needed_for_others = non_atom_tx_count * BASE_FEE_AMOUNT;

        // Early check: do we have enough ATOM to pay gas for all other token transfers?
        if atom_balance < gas_needed_for_others && !other_tokens.is_empty() {
            println!(
                "   ⊘ Insufficient ATOM ({}) to cover gas for {} other token transfer(s) (need {})",
                atom_balance,
                other_tokens.len(),
                gas_needed_for_others
            );
            // Skip all tokens in this wallet
            for token in &other_tokens {
                accounting.add_skipped(
                    entry.address.clone(),
                    token.denom.clone(),
                    token.amount,
                    "Insufficient ATOM for gas (multiple tokens)",
                );
            }
            if atom_balance > 0 {
                accounting.add_skipped(
                    entry.address.clone(),
                    BASE_DENOM.to_string(),
                    atom_balance,
                    "Insufficient ATOM remaining after reserving for other tokens",
                );
            }
            continue;
        }

        // ───── Transfer all non-ATOM tokens first ─────
        for token_balance in other_tokens {
            println!(
                "\n   🪙 Processing token (non-ATOM): {}",
                token_balance.denom
            );

            if token_balance.amount == 0 {
                continue;
            }

            let amount_to_send = token_balance.amount;
            let gas_fee = BASE_FEE_AMOUNT;

            println!(
                "      Amount:      {}",
                format_token(amount_to_send, &token_balance.denom)
            );
            println!(
                "      Gas Fee:     {} uatom ({:.6} ATOM)",
                gas_fee,
                gas_fee as f64 / 1_000_000.0
            );

            println!("      🚀 Initiating transfer...");
            match transfer_balance(
                &entry.seed_phrase,
                &entry.address,
                dest_address,
                amount_to_send,
                &token_balance.denom,
            )
            .await
            {
                Ok(tx_hash) => {
                    println!("      ✓ Transfer successful! TX: {}", tx_hash);
                    accounting.add_record(AccountingRecord {
                        wallet_address: entry.address.clone(),
                        denom: token_balance.denom.clone(),
                        balance: token_balance.amount,
                        amount_sent: amount_to_send,
                        gas_fee,
                        success: true,
                        tx_hash: Some(tx_hash),
                        error: None,
                    });
                }
                Err(e) => {
                    eprintln!("      ✗ Transfer failed: {}", e);
                    accounting.add_record(AccountingRecord {
                        wallet_address: entry.address.clone(),
                        denom: token_balance.denom.clone(),
                        balance: token_balance.amount,
                        amount_sent: 0,
                        gas_fee: 0,
                        success: false,
                        tx_hash: None,
                        error: Some(e.to_string()),
                    });
                }
            }

            // Delay between transactions
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        // ───── Finally, transfer ATOM last (if any) ─────
        if atom_balance > 0 {
            println!("\n   🪙 Processing token: {}", BASE_DENOM);

            // Gas already consumed for previous transactions
            let gas_already_spent = non_atom_tx_count * BASE_FEE_AMOUNT;
            let remaining_atom = atom_balance - gas_already_spent;

            if remaining_atom <= BASE_FEE_AMOUNT {
                println!(
                    "      ⊘ Remaining ATOM ({}) not enough for final tx fee ({}), leaving in wallet.",
                    remaining_atom, BASE_FEE_AMOUNT
                );
                accounting.add_skipped(
                    entry.address.clone(),
                    BASE_DENOM.to_string(),
                    atom_balance,
                    "Insufficient remaining ATOM for final transfer fee",
                );
            } else {
                let amount_to_send = remaining_atom - BASE_FEE_AMOUNT;
                let gas_fee = BASE_FEE_AMOUNT;

                println!(
                    "      Amount:      {}",
                    format_token(amount_to_send, BASE_DENOM)
                );
                println!(
                    "      Gas Fee:     {} uatom ({:.6} ATOM)",
                    gas_fee,
                    gas_fee as f64 / 1_000_000.0
                );

                println!("      🚀 Initiating transfer...");
                match transfer_balance(
                    &entry.seed_phrase,
                    &entry.address,
                    dest_address,
                    amount_to_send,
                    BASE_DENOM,
                )
                .await
                {
                    Ok(tx_hash) => {
                        println!("      ✓ Transfer successful! TX: {}", tx_hash);
                        accounting.add_record(AccountingRecord {
                            wallet_address: entry.address.clone(),
                            denom: BASE_DENOM.to_string(),
                            balance: atom_balance,
                            amount_sent: amount_to_send,
                            gas_fee,
                            success: true,
                            tx_hash: Some(tx_hash),
                            error: None,
                        });
                    }
                    Err(e) => {
                        eprintln!("      ✗ ATOM transfer failed: {}", e);
                        accounting.add_record(AccountingRecord {
                            wallet_address: entry.address.clone(),
                            denom: BASE_DENOM.to_string(),
                            balance: atom_balance,
                            amount_sent: 0,
                            gas_fee: 0,
                            success: false,
                            tx_hash: None,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }

        println!();

        // Small delay between wallets to avoid rate limiting
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    let elapsed = start_time.elapsed();

    println!("{}", "═".repeat(67));
    println!("ALL WALLETS PROCESSED");
    println!("{}", "═".repeat(67));
    println!("⏱  Total Time: {:.2} seconds", elapsed.as_secs_f64());

    // Print summary
    accounting.print_summary();

    // Save to CSV
    let report_filename = format!(
        "sweep_report_{}.csv",
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    );
    match accounting.save_to_csv(&report_filename) {
        Ok(_) => println!("\n✓ Detailed report saved to: {}", report_filename),
        Err(e) => eprintln!("\n✗ Failed to save report: {}", e),
    }

    println!("\n");

    Ok(())
}

fn read_csv(path: &str) -> Result<Vec<WalletEntry>, Box<dyn Error>> {
    let file = File::open(Path::new(path))?;
    let mut reader = ReaderBuilder::new().has_headers(false).from_reader(file);

    let mut entries = Vec::new();

    for result in reader.records() {
        let record = result?;
        if record.len() != 2 {
            return Err("CSV format error: expected 2 columns (seed_phrase,address)".into());
        }

        entries.push(WalletEntry {
            seed_phrase: record[0].trim().to_string(),
            address: record[1].trim().to_string(),
        });
    }

    Ok(entries)
}

fn derive_address_from_seed(
    seed_phrase: &str,
    prefix: &str,
    denom: &str,
) -> Result<String, Box<dyn Error>> {
    let signer = Signer::from_mnemonic(seed_phrase, prefix, denom, None, 0, 0)?;

    Ok(signer.public_address.to_string())
}

async fn get_balance(address: &str, denom: &str) -> Result<u128, Box<dyn Error>> {
    let rpc_url = "https://cosmos-rest.publicnode.com";
    let client = reqwest::Client::new();

    let url = format!("{}/cosmos/bank/v1beta1/balances/{}", rpc_url, address);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(format!("RPC request failed: {}", response.status()).into());
    }

    let json: serde_json::Value = response.json().await?;

    if let Some(balances) = json["balances"].as_array() {
        for balance in balances {
            if balance["denom"] == denom {
                let amount_str = balance["amount"].as_str().unwrap_or("0");
                return Ok(amount_str.parse()?);
            }
        }
    }

    Ok(0)
}

async fn get_all_balances(address: &str) -> Result<Vec<TokenBalance>, Box<dyn Error>> {
    let rpc_url = "https://cosmos-rest.publicnode.com";
    let client = reqwest::Client::new();

    let url = format!("{}/cosmos/bank/v1beta1/balances/{}", rpc_url, address);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(format!("RPC request failed: {}", response.status()).into());
    }

    let json: serde_json::Value = response.json().await?;

    let mut balances = Vec::new();

    if let Some(balance_array) = json["balances"].as_array() {
        for balance in balance_array {
            if let (Some(denom), Some(amount_str)) =
                (balance["denom"].as_str(), balance["amount"].as_str())
            {
                if let Ok(amount) = amount_str.parse::<u128>() {
                    if amount > 0 {
                        balances.push(TokenBalance {
                            denom: denom.to_string(),
                            amount,
                        });
                    }
                }
            }
        }
    }

    Ok(balances)
}

async fn transfer_balance(
    seed_phrase: &str,
    from_address: &str,
    to_address: &str,
    amount: u128,
    denom: &str,
) -> Result<String, Box<dyn Error>> {
    // 1. Get Signer
    let signer = Signer::from_mnemonic(seed_phrase, "cosmos", BASE_DENOM, None, 0, 0)?;

    // 2. Get FRESH account info EVERY time (critical for multiple txs)
    let (account_number, sequence) = get_account_info(from_address).await?;

    // 3. Setup message
    let amount_coin = Coin {
        denom: denom.parse::<Denom>()?,
        amount,
    };

    let msg_send = MsgSend {
        from_address: from_address.parse()?,
        to_address: to_address.parse()?,
        amount: vec![amount_coin],
    };

    let body = Body::new(vec![msg_send.to_any()?], "", 0u32);

    // Fee (always in ATOM)
    let fee = Fee::from_amount_and_gas(
        Coin {
            denom: BASE_DENOM.parse()?,
            amount: BASE_FEE_AMOUNT,
        },
        GAS_LIMIT,
    );

    // 4. Build AuthInfo with current sequence
    let auth_info =
        SignerInfo::single_direct(Some(signer.public_key.into()), sequence).auth_info(fee);

    // 5. Sign and broadcast
    let sign_doc = SignDoc::new(&body, &auth_info, &CHAIN_ID.parse()?, account_number)?;
    let tx_raw = sign_doc.sign(&signer.private_key)?;

    broadcast_tx(&tx_raw).await
}

async fn get_account_info(address: &str) -> Result<(u64, u64), Box<dyn Error>> {
    let rpc_url = "https://cosmos-rest.publicnode.com";
    let client = reqwest::Client::new();

    let url = format!("{}/cosmos/auth/v1beta1/accounts/{}", rpc_url, address);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(format!("Failed to get account info: {}", response.status()).into());
    }

    let json: serde_json::Value = response.json().await?;

    let account_number = json["account"]["account_number"]
        .as_str()
        .unwrap_or("0")
        .parse()?;

    let sequence = json["account"]["sequence"]
        .as_str()
        .unwrap_or("0")
        .parse()?;

    Ok((account_number, sequence))
}

async fn broadcast_tx(tx_raw: &Raw) -> Result<String, Box<dyn Error>> {
    use base64::{Engine as _, engine::general_purpose};

    let rpc_url = "https://cosmos-rest.publicnode.com";
    let client = reqwest::Client::new();

    let tx_bytes = tx_raw.to_bytes()?;
    let tx_base64 = general_purpose::STANDARD.encode(&tx_bytes);

    let payload = serde_json::json!({
        "tx_bytes": tx_base64,
        "mode": "BROADCAST_MODE_SYNC"
    });

    let url = format!("{}/cosmos/tx/v1beta1/txs", rpc_url);

    let response = client.post(&url).json(&payload).send().await?;

    if !response.status().is_success() {
        return Err(format!("Broadcast failed: {}", response.status()).into());
    }

    let json: serde_json::Value = response.json().await?;

    if let Some(code) = json["tx_response"]["code"].as_u64() {
        if code != 0 {
            let raw_log = json["tx_response"]["raw_log"]
                .as_str()
                .unwrap_or("Unknown error");
            return Err(format!("Transaction failed: {}", raw_log).into());
        }
    }

    let tx_hash = json["tx_response"]["txhash"]
        .as_str()
        .ok_or("No transaction hash in response")?
        .to_string();

    Ok(tx_hash)
}
