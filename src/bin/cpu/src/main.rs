use bitcoin::util::address::Error;
use ring::pbkdf2;
use std::time::Instant;
use sha2::{Sha256, Digest};
use bitcoin::secp256k1::{Secp256k1, All};
use bitcoin::network::constants::Network;
use bitcoin::Address;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, DerivationPath};
use rayon::prelude::*;
use bitcoin_wallet::mnemonic::WORDS;

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
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iterations, passphrase, mnemonic.as_bytes(), &mut output);
    output
}


fn address_from_seed(seed: [u8; 64], secp: &Secp256k1<All>) -> Result<Address, Error> {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = "m/49'/0'/0'/0/0".parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_private(&secp, &child_priv);
    Address::p2shwpkh(&child_pub.public_key, Network::Bitcoin)
}

fn check_int(i: u128, secp: &Secp256k1<All>) -> () {
    let passphrase = "mnemonic".as_bytes();
    let mnemonic: String = mnemonic_from_int(i);
    let seed: [u8; 64] = gen_seed_from_mnemonic(&mnemonic, &passphrase);
    let _addr = address_from_seed(seed, &secp);
}

fn main() {
    let secp: Secp256k1<All> = Secp256k1::new();
    let known_words = ["army","excuse", "hero", "wolf", "disease", "liberty", "moral", "diagram", "treat", "stove", "absent"];

    let mut start_count: u128 = 0;
    let mut start_shift = 128;
    for word in &known_words {
        start_shift -= 11;
        let idx: u128 = WORDS.binary_search(word).unwrap() as u128;
        start_count = start_count | (idx << start_shift);
    }
    let end_count: u128 = start_count | 2u128.pow(start_shift) - 1;

    println!("start: {:b}", start_count);
    println!("end: {:b}", end_count);
    println!("{} possibilities", end_count - start_count);

    let start = Instant::now();
    (start_count..end_count).into_par_iter().for_each(move |x| check_int(x, &secp));
    println!("elapsed: {} ms", start.elapsed().as_millis());
}
