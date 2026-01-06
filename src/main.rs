use cosmos_client::signer::Signer;
use cosmrs::tx::Msg;
use cosmrs::{
    AccountId, Coin, Denom,
    bank::MsgSend,
    tx::{Body, Fee, Raw, SignDoc, SignerInfo},
};
use csv::ReaderBuilder;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::time::Instant;

const CHAIN_ID: &str = "cosmoshub-4";
const DENOM: &str = "uatom";
const GAS_LIMIT: u64 = 120_000;

#[derive(Debug)]
struct WalletEntry {
    seed_phrase: String,
    address: String,
}

#[derive(Debug, Default)]
struct AccountingRecord {
    wallet_address: String,
    balance: u128,
    amount_sent: u128,
    gas_fee: u128,
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
    total_balance_found: u128,
    total_amount_sent: u128,
    total_gas_fees_paid: u128,
    total_gas_fees_reserved: u128,
    total_balance_remaining: u128,
    records: Vec<AccountingRecord>,
}

impl GlobalAccounting {
    fn new() -> Self {
        Self::default()
    }

    fn add_record(&mut self, record: AccountingRecord) {
        self.total_balance_found += record.balance;

        if record.success {
            self.successful_transfers += 1;
            self.total_amount_sent += record.amount_sent;
            self.total_gas_fees_paid += record.gas_fee;
        } else if record.error.is_some() {
            self.failed_transfers += 1;
        }

        self.records.push(record);
    }

    fn add_skipped(&mut self, wallet_address: String, balance: u128, reason: &str) {
        self.skipped_wallets += 1;
        self.total_balance_found += balance;
        self.total_balance_remaining += balance;

        self.records.push(AccountingRecord {
            wallet_address,
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
        println!("   ⊘ Skipped Wallets:          {}", self.skipped_wallets);

        println!("\n💰 BALANCE SUMMARY:");
        println!(
            "   Total Balance Found:        {} uatom ({:.6} ATOM)",
            self.total_balance_found,
            self.total_balance_found as f64 / 1_000_000.0
        );
        println!(
            "   Total Amount Sent:          {} uatom ({:.6} ATOM)",
            self.total_amount_sent,
            self.total_amount_sent as f64 / 1_000_000.0
        );
        println!(
            "   Total Gas Fees Paid:        {} uatom ({:.6} ATOM)",
            self.total_gas_fees_paid,
            self.total_gas_fees_paid as f64 / 1_000_000.0
        );
        println!(
            "   Total Balance Remaining:    {} uatom ({:.6} ATOM)",
            self.total_balance_remaining,
            self.total_balance_remaining as f64 / 1_000_000.0
        );

        let total_swept = self.total_amount_sent + self.total_gas_fees_paid;
        println!("\n📈 TOTALS:");
        println!(
            "   Total Swept (sent + fees):  {} uatom ({:.6} ATOM)",
            total_swept,
            total_swept as f64 / 1_000_000.0
        );

        let efficiency = if self.total_balance_found > 0 {
            (self.total_amount_sent as f64 / self.total_balance_found as f64) * 100.0
        } else {
            0.0
        };
        println!("   Transfer Efficiency:        {:.2}%", efficiency);

        println!("\n📋 DETAILED RECORDS:");
        println!(
            "   {:<45} {:<15} {:<15} {:<12} {:<10}",
            "Address", "Balance", "Sent", "Gas Fee", "Status"
        );
        println!("   {}", "─".repeat(100));

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
                "   {:<45} {:<15} {:<15} {:<12} {:<10}",
                &record.wallet_address[..record.wallet_address.len().min(45)],
                format_atom(record.balance),
                format_atom(record.amount_sent),
                format_atom(record.gas_fee),
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
            "wallet_address,balance_uatom,balance_atom,amount_sent_uatom,amount_sent_atom,gas_fee_uatom,gas_fee_atom,status,tx_hash,error"
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
                "{},{},{:.6},{},{:.6},{},{:.6},{},{},{}",
                record.wallet_address,
                record.balance,
                record.balance as f64 / 1_000_000.0,
                record.amount_sent,
                record.amount_sent as f64 / 1_000_000.0,
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
        writeln!(file, "skipped_wallets,{}", self.skipped_wallets)?;
        writeln!(
            file,
            "total_balance_found_uatom,{}",
            self.total_balance_found
        )?;
        writeln!(
            file,
            "total_balance_found_atom,{:.6}",
            self.total_balance_found as f64 / 1_000_000.0
        )?;
        writeln!(file, "total_amount_sent_uatom,{}", self.total_amount_sent)?;
        writeln!(
            file,
            "total_amount_sent_atom,{:.6}",
            self.total_amount_sent as f64 / 1_000_000.0
        )?;
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
        writeln!(
            file,
            "total_balance_remaining_uatom,{}",
            self.total_balance_remaining
        )?;
        writeln!(
            file,
            "total_balance_remaining_atom,{:.6}",
            self.total_balance_remaining as f64 / 1_000_000.0
        )?;

        Ok(())
    }
}

fn format_atom(uatom: u128) -> String {
    format!("{:.6} ATOM", uatom as f64 / 1_000_000.0)
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
    println!("║              COSMOS HUB WALLET SWEEP TOOL                     ║");
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

    // Verify destination has ATOM balance (using RPC)
    println!("\n🔍 Checking destination balance...");
    match verify_destination_has_balance(&dest_address).await {
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
        let derived_address = match derive_address_from_seed(&entry.seed_phrase, "cosmos", "uatom")
        {
            Ok(addr) => {
                println!("   Derived:     {}", addr);
                addr
            }
            Err(e) => {
                eprintln!("   ✗ Failed to derive address: {}", e);
                accounting.add_skipped(
                    entry.address.clone(),
                    0,
                    &format!("Derivation failed: {}", e),
                );
                continue;
            }
        };

        // Verify addresses match
        if entry.address != derived_address {
            eprintln!("   ✗ Address mismatch! CSV ≠ Derived");
            accounting.add_skipped(entry.address.clone(), 0, "Address mismatch");
            continue;
        }
        println!("   ✓ Addresses match!");

        // Get balance
        let balance = match get_balance(&entry.address).await {
            Ok(b) => {
                println!(
                    "   Balance:     {} uatom ({:.6} ATOM)",
                    b,
                    b as f64 / 1_000_000.0
                );
                b
            }
            Err(e) => {
                eprintln!("   ✗ Failed to get balance: {}", e);
                accounting.add_skipped(
                    entry.address.clone(),
                    0,
                    &format!("Balance check failed: {}", e),
                );
                continue;
            }
        };

        if balance == 0 {
            println!("   ⊘ No balance to transfer, skipping.");
            accounting.add_skipped(entry.address.clone(), balance, "Skipped: Zero balance");
            continue;
        }

        // Calculate amount to send (leave some for fees)
        let fee_amount = 1_000;
        accounting.total_gas_fees_reserved += fee_amount;

        if balance <= fee_amount {
            println!(
                "   ⊘ Balance ({} uatom) too low to cover fees ({} uatom), skipping.",
                balance, fee_amount
            );
            accounting.add_skipped(
                entry.address.clone(),
                balance,
                "Skipped: Insufficient balance for fees",
            );
            accounting.total_balance_remaining += balance;
            continue;
        }

        let amount_to_send = balance - fee_amount;
        println!(
            "   Amount:      {} uatom ({:.6} ATOM)",
            amount_to_send,
            amount_to_send as f64 / 1_000_000.0
        );
        println!(
            "   Gas Fee:     {} uatom ({:.6} ATOM)",
            fee_amount,
            fee_amount as f64 / 1_000_000.0
        );

        // Transfer balance
        println!("   🚀 Initiating transfer...");
        match transfer_balance(
            &entry.seed_phrase,
            &entry.address,
            &dest_address,
            amount_to_send,
        )
        .await
        {
            Ok(tx_hash) => {
                println!("   ✓ Transfer successful!");
                println!("   TX Hash: {}", tx_hash);
                println!("   Explorer: https://www.mintscan.io/cosmos/tx/{}", tx_hash);

                accounting.add_record(AccountingRecord {
                    wallet_address: entry.address.clone(),
                    balance,
                    amount_sent: amount_to_send,
                    gas_fee: fee_amount,
                    success: true,
                    tx_hash: Some(tx_hash),
                    error: None,
                });
            }
            Err(e) => {
                eprintln!("   ✗ Transfer failed: {}", e);
                accounting.add_record(AccountingRecord {
                    wallet_address: entry.address.clone(),
                    balance,
                    amount_sent: 0,
                    gas_fee: 0,
                    success: false,
                    tx_hash: None,
                    error: Some(e.to_string()),
                });
                accounting.total_balance_remaining += balance;
            }
        }

        println!();

        // Small delay to avoid rate limiting
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
    // Mirror the exact parameters from your generate_account function
    let signer = Signer::from_mnemonic(
        seed_phrase,
        prefix, // e.g., "cosmos"
        denom,  // e.g., "uatom"
        None,   // pass_phrase
        0,      // account_index
        0,      // address_index
    )?;

    Ok(signer.public_address.to_string())
}

async fn verify_destination_has_balance(address: &str) -> Result<u128, Box<dyn Error>> {
    let balance = get_balance(address).await?;
    if balance > 0 {
        Ok(balance)
    } else {
        Err("Destination address has no ATOM balance".into())
    }
}

async fn get_balance(address: &str) -> Result<u128, Box<dyn Error>> {
    // Using public RPC endpoint
    let rpc_url = "https://cosmos-rest.publicnode.com";
    let client = reqwest::Client::new();

    let url = format!("{}/cosmos/bank/v1beta1/balances/{}", rpc_url, address);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(format!("RPC request failed: {}", response.status()).into());
    }

    let json: serde_json::Value = response.json().await?;

    // Find uatom balance
    if let Some(balances) = json["balances"].as_array() {
        for balance in balances {
            if balance["denom"] == DENOM {
                let amount_str = balance["amount"].as_str().unwrap_or("0");
                return Ok(amount_str.parse()?);
            }
        }
    }

    Ok(0)
}

async fn transfer_balance(
    seed_phrase: &str,
    from_address: &str,
    to_address: &str,
    amount: u128,
) -> Result<String, Box<dyn Error>> {
    // 1. Get Signer
    let signer = Signer::from_mnemonic(seed_phrase, "cosmos", "uatom", None, 0, 0)?;

    // 2. Get account info
    let (account_number, sequence) = get_account_info(from_address).await?;

    // 3. Setup message
    let amount_coin = Coin {
        denom: DENOM.parse::<Denom>()?,
        amount,
    };

    let msg_send = MsgSend {
        from_address: from_address.parse()?,
        to_address: to_address.parse()?,
        amount: vec![amount_coin],
    };

    let body = Body::new(vec![msg_send.to_any()?], "", 0u32);

    // Fee
    let fee_amount = 1_000;
    let fee = Fee::from_amount_and_gas(
        Coin {
            denom: DENOM.parse()?,
            amount: fee_amount,
        },
        GAS_LIMIT,
    );

    // 4. Build AuthInfo with proper PublicKey conversion
    let auth_info =
        SignerInfo::single_direct(Some(signer.public_key.into()), sequence).auth_info(fee);

    // 5. Create and sign SignDoc using private_key
    let sign_doc = SignDoc::new(&body, &auth_info, &CHAIN_ID.parse()?, account_number)?;

    let tx_raw = sign_doc.sign(&signer.private_key)?; // ← Fixed: use private_key, not signing_key

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
