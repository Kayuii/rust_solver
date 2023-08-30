

__kernel void prems_int_to_address(ulong start_index, __global uchar * res_address, __global uchar * target_mnemonic, __global uchar * found_mnemonic) {
  ulong idx = get_global_id(0);
  idx = start_index + idx;

  ushort init_indices[12] = {1778, 157, 1670, 1283, 66, 1797, 208, 2044, 1127, 1328, 906, 779};
  ushort indices[12] = {0};
  uchar target_address1[20] = {0x27,0x60,0x98,0x93,0x8d,0x48,0xc5,0x5f,0x68,0x42,0x8e,0x48,0x88,0x46,0x27,0x01,0xcb,0x8b,0x52,0x62};
  uchar target_address2[20] = {0xa2,0x1a,0xc0,0xb0,0xa1,0x13,0x04,0x7c,0xea,0x16,0x20,0xd1,0x66,0x3c,0x5e,0xd3,0xbc,0x21,0x9d,0x32};
  //uchar target_address2[20] = {0xed,0x71,0x73,0x26,0x12,0x25,0xe4,0xd6,0x17,0x97,0x9f,0x1b,0x3f,0xfe,0x44,0x81,0x26,0x7c,0xe0,0x70};


  uchar perms[12] = {0};
  nth_permutation(12, idx, perms);
  for(int i=0;i<12;i++){
      indices[i] = init_indices[perms[i]];
  }

  uchar mnemonic[180] = {0};
  uchar mnemonic_length = 11 + word_lengths[indices[0]] + word_lengths[indices[1]] + word_lengths[indices[2]] + word_lengths[indices[3]] + word_lengths[indices[4]] + word_lengths[indices[5]] + word_lengths[indices[6]] + word_lengths[indices[7]] + word_lengths[indices[8]] + word_lengths[indices[9]] + word_lengths[indices[10]] + word_lengths[indices[11]];
  int mnemonic_index = 0;

  for (int i=0; i < 12; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];

    for(int j=0;j<word_length;j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;

  uchar ipad_key[128];
  uchar opad_key[128];
  for(int x=0;x<128;x++){
    ipad_key[x] = 0x36;
    opad_key[x] = 0x5c;
  }

  for(int x=0;x<mnemonic_length;x++){
    ipad_key[x] = ipad_key[x] ^ mnemonic[x];
    opad_key[x] = opad_key[x] ^ mnemonic[x];
  }

  uchar seed[64] = { 0 };
  uchar sha512_result[64] = { 0 };
  uchar key_previous_concat[256] = { 0 };
  uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 };
  for(int x=0;x<128;x++){
    key_previous_concat[x] = ipad_key[x];
  }
  for(int x=0;x<12;x++){
    key_previous_concat[x+128] = salt[x];
  }

  sha512(&key_previous_concat, 140, &sha512_result);
  copy_pad_previous(&opad_key, &sha512_result, &key_previous_concat);
  sha512(&key_previous_concat, 192, &sha512_result);
  xor_seed_with_round(&seed, &sha512_result);

  for(int x=1;x<2048;x++){
    copy_pad_previous(&ipad_key, &sha512_result, &key_previous_concat);
    sha512(&key_previous_concat, 192, &sha512_result);
    copy_pad_previous(&opad_key, &sha512_result, &key_previous_concat);
    sha512(&key_previous_concat, 192, &sha512_result);
    xor_seed_with_round(&seed, &sha512_result);
  }

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;
  extended_public_key_t master_public;

  new_master_from_seed(network, &seed, &master_private);

  bool found_target = false;

  // Root
  uchar hash160_address[20] = { 0 };
  hash160_eyas(&master_private, &hash160_address);

  bool found_target1 = 1;
  for(int j=0;j<20;j++) {
      if(hash160_address[j] != target_address1[j]){
          found_target1 = 0;
      }
  }
  if(found_target1){
      for(int j=0;j<20;j++) {
          res_address[j] = hash160_address[j];
      }
      found_target = true;
  }
  bool found_target2 = 1;
  for(int j=0;j<20;j++) {
      if(hash160_address[j] != target_address2[j]){
          found_target2 = 0;
      }
  }
  if(found_target2){
      for(int j=0;j<20;j++) {
          res_address[j] = hash160_address[j];
      }
      found_target = true;
  }

  // BIP32
  extended_private_key_t target_key_bip32;
  hardened_private_child_from_private(&master_private, &target_key_bip32, 0);

  // Multibit
  extended_private_key_t target_key_multibit;
  normal_private_child_from_private(&target_key_bip32, &target_key_multibit, 0);
  found_target = found_target || hardened_check(&target_key_multibit, &target_address1, &target_address2, res_address);
  found_target = found_target || normal_check(&target_key_multibit, &target_address1, &target_address2, res_address);

  // Bitcoin core
  extended_private_key_t target_key_bitcore;
  hardened_private_child_from_private(&target_key_bip32, &target_key_bitcore, 0);
  if(idx == 1)
  found_target = found_target || hardened_check(&target_key_bitcore, &target_address1, &target_address2, res_address);
  found_target = found_target || normal_check(&target_key_bitcore, &target_address1, &target_address2, res_address);
  //////////////////////////////////////


  // BIP44 Wallets
  extended_private_key_t target_key_bip44;
  hardened_private_child_from_private(&master_private, &target_key_bip44, 44);
  hardened_private_child_from_private(&target_key_bip44, &target_key_bip44, 0);
  hardened_private_child_from_private(&target_key_bip44, &target_key_bip44, 0);

  // Blockchain info
  found_target = found_target || hardened_check(&target_key_bip44, &target_address1, &target_address2, res_address);
  found_target = found_target || normal_check(&target_key_bip44, &target_address1, &target_address2, res_address);

  // BIP44
  normal_private_child_from_private(&target_key_bip44, &target_key_bip44, 0);
  found_target = found_target || hardened_check(&target_key_bip44, &target_address1, &target_address2, res_address);
  found_target = found_target || normal_check(&target_key_bip44, &target_address1, &target_address2, res_address);

  if(found_target) {
  //if(idx == 1) {
    found_mnemonic[0] = 0x01;
    for(int i=0;i<mnemonic_index;i++) {
        target_mnemonic[i] = mnemonic[i];
    }
  }
}
