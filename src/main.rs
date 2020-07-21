use std::str::FromStr;

use magical_bitcoin_wallet::blockchain::ElectrumBlockchain;
use magical_bitcoin_wallet::Wallet;

use magical_bitcoin_wallet::bitcoin;
use magical_bitcoin_wallet::electrum_client;
use magical_bitcoin_wallet::sled;

use bitcoin::{util::bip32::ExtendedPrivKey, Address, Network};
use electrum_client::Client;

use bip39::{Language, Mnemonic, Seed};

#[derive(Debug, err_derive::Error)]
#[error(display = "An error occurred.")]
enum WalletError {
    #[error(display = "Bitcoin error: {:?}", _0)]
    Bitcoin(#[error(from)] bitcoin::Error),
    #[error(display = "Electrum error: {:?}", _0)]
    Electrum(#[error(from)] electrum_client::Error),
    #[error(display = "BIP32 error: {:?}", _0)]
    BIP32(#[error(from)] bitcoin::util::bip32::Error),
    #[error(display = "Address error: {:?}", _0)]
    Address(#[error(from)] bitcoin::util::address::Error),
    #[error(display = "Database error: {:?}", _0)]
    Database(#[error(from)] sled::Error),
    #[error(display = "Wallet error: {:?}", _0)]
    Wallet(#[error(from)] magical_bitcoin_wallet::error::Error),

    #[error(display = "Mnemonic error: {}", _0)]
    Mnemonic(String),
}

fn main() -> Result<(), WalletError> {
    let mnemonic = "horse slot opinion obtain pride side input robust mention brush echo push";
    let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English)
        .map_err(|e| WalletError::Mnemonic(format!("{:?}", e)))?;
    let seed = Seed::new(&mnemonic, ""); // "" -> empty bip39 passphrase

    let xprv = ExtendedPrivKey::new_master(Network::Testnet, &seed.as_bytes())?;

    let desc = format!("sh(wpkh({}/49'/0'/0'/0/*))", xprv);
    let change_desc = format!("sh(wpkh({}/49'/0'/0'/1/*))", xprv);

    let client = Client::new("ssl://electrum.blockstream.info:60002", None)?;
    let database = sled::open("magical-db")?.open_tree("default")?;

    let wallet = Wallet::new(
        &desc,
        Some(&change_desc),
        Network::Testnet,
        database,
        ElectrumBlockchain::from(client),
    )?;

    println!("New address: {}", wallet.get_new_address()?);

    println!("Syncing balance...");
    wallet.sync(None, None)?;

    let balance = wallet.get_balance()?;
    println!("Balance: {}", balance);

    if balance > 0 {
        let receiver = Address::from_str("2N3FkBEP35DtdniCP5k5x1vbkmhLVEuddGy")?; // Our first address

        println!("Sending everything to: {}", receiver);

        let (psbt, details) =
            wallet.create_tx(vec![(receiver, 0)], true, 1e3 * 1e-8, None, None, None)?;
        println!(
            "PSBT created, total outgoing amount = {}. Signing now...",
            details.sent
        );

        let (psbt, finalized) = wallet.sign(psbt, None)?;
        assert!(finalized, "Unable to finalize the TX");
        println!("PSBT signed and finalized, extracting the raw tx...");

        let raw_tx = psbt.extract_tx();
        println!("Raw tx extracted, now broadcasting it...");

        let txid = wallet.broadcast(raw_tx)?;
        println!(
            "Tx {txid} sent! Explorer: https://blockstream.info/testnet/tx/{txid}",
            txid = txid
        );
    } else {
        println!("Send some testnet btc to the address above and retry.");
    }

    Ok(())
}
