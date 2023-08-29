static int fact(int y){
    if (y == 0){
        return 1;
    }
    return y * fact(y - 1);
}

static uchar pop(uchar * array, int size, int index){
    uchar value = array[index];
    for (int i = index; i <size-1; i++){
        array[i] = array[i+1];
    }
    return value;
}


static void nth_permutation(int len, ulong index, uchar *array){
    uchar values[12] = {0};
    int size = 12;
    for(int i=0; i<len; i++){
        values[i] = i;
    }
    int c = fact(len);
    index = index % c;
    int q = index;
    uchar result[12] = {0};
    for(int d=1; d<len + 1; d++){
        q = index / d;
        int i = index % d;
        if (0 <= len - d && len - d < len){
            result[len - d] = i;
        }
        if (q == 0){
            break;
        }
    }
    for(int i=0; i<len; i++){
        array[i] = pop(values, size--, result[i]);
    }
}

void hash160_eyas(extended_private_key_t *target_private_key, uchar * hash160_address){
    extended_public_key_t target_public_key;
    public_from_private(target_private_key, &target_public_key);

    hash160_for_public_key(&target_public_key, &hash160_address);
}

bool hardened_check(extended_private_key_t *input_key, uchar * target_address1, uchar * target_address2, uchar * res_address){
    extended_private_key_t target_key;
    for(int i=0; i<20; i++){
        hardened_private_child_from_private(input_key, &target_key, i);
        uchar hash160_address[20] = { 0 };
        hash160_eyas(&target_key, &hash160_address);

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
            return true;
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
            return true;
        }
    }
    return false;
}

bool normal_check(extended_private_key_t *input_key, uchar * target_address1, uchar * target_address2, uchar * res_address){
    extended_private_key_t target_key;
    for(int i=0; i<20; i++){
        normal_private_child_from_private(input_key, &target_key, i);
        uchar hash160_address[20] = { 0 };
        hash160_eyas(&target_key, &hash160_address);

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
            return true;
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
            return true;
        }
    }
    return false;
}
