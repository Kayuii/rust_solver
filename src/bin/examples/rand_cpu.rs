use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::address::Error;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Address;
use bitcoin_wallet::mnemonic::WORDS;
use rayon::prelude::*;
use ring::pbkdf2;
use sha2::{Digest, Sha256};
use std::time::Instant;

struct Addresses {
    p2pkh: Address,
    p2shwpkh: Option<Address>,
    p2wpkh: Option<Address>
  }

fn get_checksum(data: &[u8]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.input(data);
    let hash = hasher.result();
    hash[0] >> 4
}

fn mnemonic_from_int(i: u128) -> String {
    let bytes: [u8; 16] = i.to_le_bytes();
    let checksum: u8 = get_checksum(&bytes);
    let mut current_shift = 117;
    let mut mask: u128 = 2047 << current_shift;
    let mut mnemonic: String = String::from("");
    for _ in 0..11 {
        mnemonic.push_str(WORDS[((i & mask) >> current_shift) as usize]);
        mnemonic.push(' ');
        mask = mask >> 11;
        current_shift -= 11;
    }
    let last_index: usize = (((i & 127) << 4) | (checksum as u128)) as usize;
    mnemonic.push_str(WORDS[last_index]);
    mnemonic
}

fn gen_seed_from_mnemonic(mnemonic: &String, passphrase: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    let iterations: std::num::NonZeroU32 = std::num::NonZeroU32::new(2048).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        iterations,
        passphrase,
        mnemonic.as_bytes(),
        &mut output,
    );
    output
}

fn address_from_seed(seed: [u8; 64], secp: &Secp256k1<All>) {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = "m/49'/0'/0'/0/0".parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_private(&secp, &child_priv);
    let p2pkh = Address::p2pkh(&child_pub.public_key, Network::Bitcoin);
    let p2shwpkh = Address::p2shwpkh(&child_pub.public_key, Network::Bitcoin).ok();
    let p2wpkh = Address::p2wpkh(&child_pub.public_key, Network::Bitcoin).ok();
    println!("p2pkh:    {}", p2pkh);
    println!("p2shwpkh: {}", p2shwpkh.unwrap());
    println!("p2wpkh:   {}", p2wpkh.unwrap());
}

fn check_int(i: u128, secp: &Secp256k1<All>) -> () {
    let passphrase = "mnemonic".as_bytes();
    let mnemonic: String = mnemonic_from_int(i);
    let seed: [u8; 64] = gen_seed_from_mnemonic(&mnemonic, &passphrase);
    let _addr = address_from_seed(seed, &secp);
}

fn main() {
    let secp: Secp256k1<All> = Secp256k1::new();

    rayon::ThreadPoolBuilder::new()
    .num_threads(num_cpus::get())
    .build_global()
    .unwrap();

    let start = 1_000_000_000;
    let end = 1_000_000_100;

    let passphrase = b"mnemonic";

    (start..end).into_par_iter().for_each(|i| {
      let mnemonic = mnemonic_from_int(i);
      println!("{}", mnemonic);
      let seed = gen_seed_from_mnemonic(&mnemonic, passphrase);
      address_from_seed(seed, &secp);
    });

}
