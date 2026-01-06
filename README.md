# Cosmos Hub Wallet Sweep Tool

A Rust-based tool for sweeping ATOM and ICS20 tokens from multiple wallets to a single destination address, with comprehensive accounting and reporting.

## Features

✅ **Complete Accounting System**
- Tracks every wallet processed
- Records all balances, transfers, and gas fees
- Generates detailed CSV reports
- Provides real-time console output with formatted summaries

✅ **Security & Validation**
- Derives addresses from seed phrases
- Verifies derived addresses match CSV addresses
- Validates destination address format
- Checks destination has ATOM balance before starting

✅ **Robust Error Handling**
- Continues processing even if individual wallets fail
- Tracks success/failure for each wallet
- Records detailed error messages
- Skips wallets with insufficient balance

✅ **Professional Reporting**
- Real-time console output with progress tracking
- Detailed per-wallet accounting
- Global summary statistics
- Automatic CSV report generation with timestamp
- Transaction hash links to Mintscan explorer

## Installation

### Prerequisites
- Rust 1.70 or higher
- Internet connection (for accessing Cosmos RPC)

### Build
```bash
cd cosmos-sweep
cargo build --release
```

The compiled binary will be at `target/release/cosmos_sweep`

## Usage

```bash
./target/release/cosmos_sweep <csv_file> <destination_address>
```

### Example
```bash
./target/release/cosmos_sweep wallets.csv cosmos1abc123def456ghi789jkl012mno345pqr678stu
```

## CSV Format

The input CSV file should have **no header** and contain two columns:
1. Seed phrase (12 or 24 words)
2. Cosmos address

**Example CSV:**
```csv
word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12,cosmos1abc123...
another seed phrase with twelve words goes here for recovery,cosmos1def456...
```

## Accounting Output

### Console Output

The tool provides detailed real-time output including:

1. **Validation Phase**
   - Destination address validation
   - Destination balance check
   - CSV file loading

2. **Per-Wallet Processing**
   - Address derivation and verification
   - Balance checking
   - Transfer amount calculation
   - Gas fee calculation
   - Transaction status and hash

3. **Final Summary**
   - Total wallets processed
   - Successful/failed/skipped counts
   - Total balance found
   - Total amount sent
   - Total gas fees paid
   - Balance remaining (from failed/skipped wallets)
   - Transfer efficiency percentage
   - Detailed record table

### Example Summary Output
```
╔═══════════════════════════════════════════════════════════════╗
║                    ACCOUNTING SUMMARY                         ║
╚═══════════════════════════════════════════════════════════════╝

📊 WALLET STATISTICS:
   Total Wallets Processed:    10
   ✓ Successful Transfers:     8
   ✗ Failed Transfers:         1
   ⊘ Skipped Wallets:          1

💰 BALANCE SUMMARY:
   Total Balance Found:        10500000 uatom (10.500000 ATOM)
   Total Amount Sent:          10000000 uatom (10.000000 ATOM)
   Total Gas Fees Paid:        400000 uatom (0.400000 ATOM)
   Total Balance Remaining:    100000 uatom (0.100000 ATOM)

📈 TOTALS:
   Total Swept (sent + fees):  10400000 uatom (10.400000 ATOM)
   Transfer Efficiency:        95.24%
```

### CSV Report

A detailed CSV report is automatically generated with the filename format:
```
sweep_report_YYYYMMDD_HHMMSS.csv
```

**Report Contents:**
- Per-wallet records with all transaction details
- Summary section with aggregated statistics
- Both uatom and ATOM denominations
- Transaction hashes for verification
- Error messages for failed transactions

**CSV Columns:**
- wallet_address
- balance_uatom
- balance_atom
- amount_sent_uatom
- amount_sent_atom
- gas_fee_uatom
- gas_fee_atom
- status (success/failed/skipped)
- tx_hash
- error

## Gas Fee Calculation

- **Gas Limit:** 200,000 gas units
- **Gas Price:** 0.00025 ATOM per gas unit (250 uatom)
- **Total Fee per Transaction:** ~0.05 ATOM (50,000 uatom)

The tool automatically reserves gas fees from each wallet's balance before calculating the transfer amount.

## Security Notes

⚠️ **CRITICAL SECURITY WARNINGS:**

1. **Seed Phrase Protection**
   - This tool handles sensitive seed phrases
   - Store CSV files securely
   - Delete CSV files immediately after use
   - Never commit CSV files to version control
   - Use encrypted storage for CSV files

2. **Network Security**
   - Tool connects to public RPC endpoints
   - Consider using your own RPC for production
   - Verify destination address carefully

3. **Testing**
   - Always test with small amounts first
   - Verify destination address multiple times
   - Review the first few transactions before continuing

4. **Backup**
   - Keep backups of seed phrases in secure offline storage
   - Don't rely solely on the CSV file

## Configuration

You can modify these constants in `src/main.rs`:

```rust
const CHAIN_ID: &str = "cosmoshub-4";
const DENOM: &str = "uatom";
const GAS_LIMIT: u64 = 120_000;
const GAS_PRICE: u128 = 1_000; // 0.001 ATOM 
```

## RPC Endpoint

The tool uses the public RPC endpoint:
```
https://cosmos-rpc.publicnode.com
```

For production use, consider:
- Running your own Cosmos node
- Using a paid RPC service
- Implementing retry logic for failed requests

## Troubleshooting

### "Address mismatch" error
- Verify the seed phrase is correct (12 or 24 words)
- Ensure no extra spaces or typos in the CSV
- Check that the derivation path matches your wallet

### "Insufficient balance for fees" warning
- Wallet has less than 0.05 ATOM
- These wallets are skipped automatically

### "Failed to get balance" error
- RPC endpoint may be temporarily unavailable
- Check your internet connection
- The tool will retry after a delay

### "Transaction failed" error
- Check the error message in the output
- Verify the destination address is correct
- Ensure source wallet has sufficient balance

## Rate Limiting

The tool includes a 1-second delay between transactions to avoid rate limiting on public RPC endpoints.

## Transaction Verification

All successful transactions include:
- Transaction hash
- Direct link to Mintscan explorer
- Recorded in the CSV report for future reference

**Mintscan Explorer:**
```
https://www.mintscan.io/cosmos/tx/{TX_HASH}
```

## Build for Different Platforms

### Linux
```bash
cargo build --release
```

### macOS
```bash
cargo build --release
```

### Windows
```bash
cargo build --release
```

Cross-compilation is also possible using `cross`:
```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
```

## Dependencies

- `cosmrs` - Cosmos SDK for Rust
- `tokio` - Async runtime
- `csv` - CSV parsing
- `bip39` - BIP39 mnemonic handling
- `hdpath` - HD wallet path derivation
- `hmac` / `sha2` - Cryptographic functions
- `reqwest` - HTTP client for RPC calls
- `serde_json` - JSON parsing
- `base64` - Base64 encoding
- `chrono` - Timestamp handling

## License

This tool is provided as-is for educational and operational purposes. Use at your own risk.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the accounting report for details
3. Verify all configuration settings

## Disclaimer

⚠️ **USE AT YOUR OWN RISK**

This tool transfers cryptocurrency. The authors are not responsible for:
- Lost funds due to incorrect usage
- Network failures or RPC issues
- Compromised seed phrases
- Any other losses or damages

Always:
- Test thoroughly with small amounts
- Verify all addresses multiple times
- Keep secure backups
- Understand the code before running it