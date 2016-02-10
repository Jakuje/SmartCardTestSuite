#include "test_suits.h"

static void is_ec_supported_test(void **state) {
    token_info *info = (token_info *) *state;
    if(!CHECK_EC_SUPPORT(info->supported.flags))
        skip();
}

static void initialize_token_with_user_pin_test(void **state) {
    token_info *info = (token_info *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_UTF8CHAR new_pin[] = {"12345"};
    CK_UTF8CHAR wrong_pin[] = {"WrongPin"};
    CK_RV rv;

    if(init_token_with_default_pin(info))
        fail_msg("Could not initialize token with default user PIN\n");


    debug_print("Test of logging in with wrong user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, wrong_pin, sizeof(wrong_pin) - 1);
    if (rv != CKR_PIN_INCORRECT) {
        fail_msg("Expected CKR_PIN_INCORRECT CKR_PIN_INCORRECT was not returned\n");
    }

    debug_print("Test of logging in with created user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, new_pin, sizeof(new_pin) - 1);
    if (rv != CKR_OK) {
        fail_msg("PIN initialization for user failed. Could not log in to token!\n");
    }

}

static void change_user_pin_test(void **state) {
    token_info *info = (token_info *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    CK_UTF8CHAR old_pin[] = {"12345"};
    CK_UTF8CHAR new_pin[] = {"54321"};

    debug_print("Change user PIN from '%s' to '%s'",old_pin, new_pin);
    rv = function_pointer->C_SetPIN(info->session_handle, old_pin, sizeof(old_pin) - 1, new_pin, sizeof(new_pin) - 1);
    if (rv != CKR_OK) {
        fail_msg("Change of user password was not successful\n");
    }

    debug_print("Logging out user");
    rv = function_pointer->C_Logout(info->session_handle);
    if (rv != CKR_OK) {
        fail_msg("Could not log out user!\n");
    }

    debug_print("Test of logging in with old user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, old_pin, sizeof(old_pin) - 1);
    if (rv != CKR_PIN_INCORRECT) {
        fail_msg("User PIN was not correctly changed\n");
    }

    debug_print("Test of logging in with new user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, new_pin, sizeof(new_pin) - 1);
    if (rv != CKR_OK) {
        fail_msg("PIN change failed. Could not log in with new user PIN!\n");
    }


}

static void get_all_mechanisms_test(void **state) {
    token_info *info = (token_info *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_RV rv;
    CK_LONG mechanism_count;
    CK_MECHANISM_TYPE_PTR mechanism_list;


    if(initialize_cryptoki(info)) {
        fail_msg("CRYPTOKI couldn't be initialized\n");
    }


    rv = function_pointer->C_GetMechanismList(info->slot_id, NULL_PTR, &mechanism_count);
    assert_int_not_equal(mechanism_count,0);
    if ((rv == CKR_OK) && (mechanism_count > 0)) {
        mechanism_list = (CK_MECHANISM_TYPE_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE));
        rv = function_pointer->C_GetMechanismList(info->slot_id, mechanism_list, &mechanism_count);
        if (rv != CKR_OK) {
            free(mechanism_list);
            function_pointer->C_Finalize(NULL_PTR);
            fail_msg("Could not get mechanism list!\n");
        }
        assert_non_null(mechanism_list);

        supported_mechanisms supported = { 0 };
        for(int i=0; i< mechanism_count; i++) {
            CK_MECHANISM_INFO mechanism_info;
            CK_MECHANISM_TYPE mechanism_type = mechanism_list[i];
            rv = function_pointer->C_GetMechanismInfo(info->slot_id,mechanism_type,&mechanism_info);

            if(rv != CKR_OK){
                continue;
            }
            get_supported_mechanisms(&supported, mechanism_info, mechanism_type);
        }

        free(mechanism_list);
        assert_int_not_equal(supported.flags, 0);
        info->supported = supported;
    }

    rv = function_pointer->C_Finalize(NULL_PTR);
    if(rv != CKR_OK){
        fail_msg("Could not finalize CRYPTOKI!\n");
    }
}


static void create_hash_md5_short_message_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_DIGEST_MD5(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("34123b38395588f72f49d51d8dd6bd3b");

    CK_MECHANISM digest_mechanism = { CKM_MD5, NULL, 0 };
    CK_BYTE hash[BUFFER_SIZE];
    CK_ULONG hash_length = BUFFER_SIZE;

    if(short_message_digest(info, &digest_mechanism, hash, &hash_length)) {
        fail_msg("Error while creating hash of message\n!");
    }

    assert_int_equal(hash_length, MD5_HASH_LENGTH);
    assert_int_equal(0, memcmp (message_expected_hash, hash, MD5_HASH_LENGTH));
    free(message_expected_hash);
}

static void create_hash_md5_long_message_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_DIGEST_MD5(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("365573858b89fabadaae4a263305c5a3");

    CK_MECHANISM digest_mechanism = { CKM_MD5, NULL, 0};
    CK_BYTE hash[MAX_DIGEST];
    CK_ULONG hash_length = MAX_DIGEST;

    if(long_message_digest(info, &digest_mechanism, hash, &hash_length)) {
        fail_msg("Error while creating hash of message\n!");
    }

    assert_int_equal(hash_length, MD5_HASH_LENGTH);
    assert_int_equal(0, memcmp (message_expected_hash, hash, MD5_HASH_LENGTH));
    free(message_expected_hash);
}

static void create_hash_sha1_short_message_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_DIGEST_SHA1(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("4a331deda41ea92c562b6c7931c423c444155ad4");

    CK_MECHANISM digest_mechanism = { CKM_SHA_1, NULL, 0};
    CK_BYTE hash[BUFFER_SIZE];
    CK_ULONG hash_length = BUFFER_SIZE;

    if(short_message_digest(info, &digest_mechanism, hash, &hash_length))
        fail_msg("Error while creating hash of message\n!");

    assert_int_equal(hash_length, SHA1_HASH_LENGTH);
    assert_int_equal(0, memcmp (message_expected_hash, hash, SHA1_HASH_LENGTH ));
    free(message_expected_hash);

}

static void create_hash_sha1_long_message_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_DIGEST_MD5(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("8001e8a7e1079e611b0945377784ea4d6ad273e7");

    CK_MECHANISM digest_mechanism = { CKM_SHA_1, NULL, 0};
    CK_BYTE hash[MAX_DIGEST];
    CK_ULONG hash_length = MAX_DIGEST;

    if(long_message_digest(info, &digest_mechanism, hash, &hash_length)) {
        fail_msg("Error while creating hash of message\n!");
    }

    assert_int_equal(hash_length, SHA1_HASH_LENGTH);
    assert_int_equal(0, memcmp (message_expected_hash, hash, SHA1_HASH_LENGTH));
    free(message_expected_hash);
}

static void generate_rsa_key_pair_no_key_generated_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_GENERATE_KEY_PAIR(info->supported.flags))
        skip();

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE, public_key = CK_INVALID_HANDLE;
    CK_MECHANISM gen_key_pair_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

    CK_KEY_TYPE key_type = CKK_DES;

    /* Set public key. */
    CK_ATTRIBUTE public_key_template[] = {
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    /* Set private key. */
    CK_ATTRIBUTE private_key_template[] = {
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
    };

    debug_print("Generating key pair....");

    /* Generate Key pair for signing/verifying */
    function_pointer->C_GenerateKeyPair(info->session_handle, &gen_key_pair_mech, public_key_template,
                                          (sizeof (public_key_template) / sizeof (CK_ATTRIBUTE)),
                                          private_key_template,
                                          (sizeof (private_key_template) / sizeof (CK_ATTRIBUTE)),
                                          &public_key, &private_key);

    if(public_key != CK_INVALID_HANDLE && private_key != CK_INVALID_HANDLE)
        fail_msg("No key should be generated!\n");

}

static void generate_rsa_key_pair_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_GENERATE_KEY_PAIR(info->supported.flags))
        skip();

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE, public_key = CK_INVALID_HANDLE;
    CK_MECHANISM gen_key_pair_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};

    CK_BBOOL true_value = TRUE;
    CK_ULONG modulus_bits = 1024;
    CK_BYTE public_exponent[] = { 11 };
    CK_UTF8CHAR public_key_label[] = "My Public Key";
    CK_UTF8CHAR private_key_label[] = "My Private Key";
    CK_BYTE id[] = { 0xa1 };

    /* Set public key. */
    CK_ATTRIBUTE public_key_template[] = {
            {CKA_ID, id, sizeof(id)},
            {CKA_LABEL, public_key_label, sizeof(public_key_label)-1},
            {CKA_VERIFY, &true_value, sizeof (true_value)},
            {CKA_ENCRYPT, &true_value, sizeof (true_value)},
            {CKA_TOKEN, &true_value, sizeof (true_value)},
            {CKA_MODULUS_BITS, &modulus_bits, sizeof (modulus_bits)},
            {CKA_PUBLIC_EXPONENT, public_exponent, sizeof (public_exponent)}
    };

    /* Set private key. */
    CK_ATTRIBUTE private_key_template[] = {
            {CKA_ID, id, sizeof(id)},
            {CKA_LABEL, private_key_label, sizeof(private_key_label)-1},
            {CKA_SIGN, &true_value, sizeof (true_value)},
            {CKA_DECRYPT, &true_value, sizeof (true_value)},
            {CKA_TOKEN, &true_value, sizeof (true_value)},
            {CKA_SENSITIVE, &true_value, sizeof (true_value)},
            {CKA_EXTRACTABLE, &true_value, sizeof (true_value)}
    };

    debug_print("Generating key pair....");

    CK_RV rv;
    /* Generate Key pair for signing/verifying */
    rv = function_pointer->C_GenerateKeyPair(info->session_handle, &gen_key_pair_mech, public_key_template,
                                        (sizeof (public_key_template) / sizeof (CK_ATTRIBUTE)),
                                        private_key_template,
                                        (sizeof (private_key_template) / sizeof (CK_ATTRIBUTE)),
                                        &public_key, &private_key);

    /* Testing if keys are created on token */
    debug_print("Testing if keys are created on token");
    if(rv != CKR_OK)
        fail_msg("Key pair generation failed\n");

    CK_OBJECT_HANDLE stored_private_key, stored_public_key;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, id, sizeof(id) },
    };

    if(find_object_by_template(info, template, &stored_private_key, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find private key.");
    }

    assert_int_equal(private_key, stored_private_key);

    keyClass = CKO_PUBLIC_KEY;
    template[0].pValue = &keyClass;
    template[0].ulValueLen = sizeof(keyClass);

    if(find_object_by_template(info, template, &stored_public_key, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find public key.");
    }

    assert_int_equal(public_key, stored_public_key);
    debug_print("Keys were successfully created on token");


    /* Test if key attributes are correct */
    debug_print("\nTest if key attributes are correct ");
    CK_ULONG template_size;

    /* Create sample message. */
    CK_ATTRIBUTE get_attributes[] = {
            {CKA_MODULUS_BITS, NULL_PTR, 0},
    };

    template_size = sizeof (get_attributes) / sizeof (CK_ATTRIBUTE);

    rv = function_pointer->C_GetAttributeValue(info->session_handle, public_key, get_attributes,
                                            template_size);

    if (rv != CKR_OK) {
        fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
    }

    /* Allocate memory to hold the data we want */
    for (int i = 0; i < template_size; i++) {
        get_attributes[i].pValue = malloc (get_attributes[i].ulValueLen * sizeof(CK_VOID_PTR));

        if (get_attributes[i].pValue == NULL) {
            for (int j = 0; j < i; j++)
                free(get_attributes[j].pValue);
        }
    }

    /* Call again to get actual attributes */
    rv = function_pointer->C_GetAttributeValue(info->session_handle, public_key, get_attributes,
                                            template_size);

    if (rv != CKR_OK) {
        for (int j = 0; j < template_size; j++)
            free(get_attributes[j].pValue);
        fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
    }

    /* Display public key values */
    debug_print("Comparing modulus bits");
    if(modulus_bits != *((CK_ULONG_PTR)(get_attributes[0].pValue))) {
        for (int j = 0; j < template_size; j++)
            free(get_attributes[j].pValue);

        fail_msg("Stored modulus bits are different from input value\n");
    }

    debug_print("All attributes were correctly stored on token");

    for (int i = 0; i < template_size; i++) {
        free(get_attributes[i].pValue);
    }
}

static void sign_message_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_SIGN(info->supported.flags))
        skip();

    CK_RV rv;
    CK_BYTE id[] = {0xa1};
    CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_OBJECT_HANDLE private_key;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, id, sizeof(id) },
    };

    if(find_object_by_template(info, template, &private_key, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find private key.");
    }

    CK_ULONG message_length, sign_length;
    CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;

    CK_BYTE sign[BUFFER_SIZE];
    sign_length = BUFFER_SIZE;
    message_length = strlen(message);

    debug_print("Signing message '%s'",message);

    rv = function_pointer->C_SignInit(info->session_handle, &sign_mechanism, private_key);
    if (rv != CKR_OK) {
        fail_msg("C_SignInit: rv = 0x%.8X\n", rv);
    }

    rv = function_pointer->C_Sign(info->session_handle, message, message_length,
                                  sign, &sign_length);
    if (rv != CKR_OK) {
        fail_msg("C_Sign: rv = 0x%.8X\n", rv);
    }

    debug_print("Comparing signature to '%s'", SHORT_MESSAGE_SIGNATURE);
    FILE *fs;

    CK_ULONG data_length = BUFFER_SIZE;
    char *input_buffer;

    /* Open the input file */
    if ((fs = fopen(SHORT_MESSAGE_SIGNATURE, "r")) == NULL) {
        fail_msg("Could not open file '%s' for reading\n", SHORT_MESSAGE_SIGNATURE);
    }


    fseek(fs, 0, SEEK_END);
    data_length= ftell(fs);
    fseek(fs, 0, SEEK_SET);

    input_buffer = (char*) malloc(data_length + 1);
    fread(input_buffer, data_length, 1, fs);
    input_buffer[data_length] = 0;
    fclose(fs);

    if(data_length != sign_length) {
        free(input_buffer);
        fail_msg("Output signature has different length!\n");
    }

    if(memcmp(input_buffer, sign, data_length) != 0) {
        free(input_buffer);
        fail_msg("Signatures are not same!");
    }

    debug_print("Message was successfully signed with private key!\n");
}

static void verify_signed_message_test(void **state) {
    token_info *info = (token_info *) *state;

    if(!CHECK_VERIFY(info->supported.flags))
        skip();

    CK_RV rv;
    CK_BYTE id[] = {0xa1};
    CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_OBJECT_HANDLE public_key;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, id, sizeof(id) },
    };

    if(find_object_by_template(info, template, &public_key, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find public key.");
    }

    CK_ULONG message_length;
    CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
    message_length = strlen(message);

    FILE *fs;

    CK_ULONG sign_length = BUFFER_SIZE;
    CK_BYTE *sign;

    /* Open the input file */
    if ((fs = fopen(SHORT_MESSAGE_SIGNATURE, "r")) == NULL) {
        fail_msg("Could not open file '%s' for reading\n", SHORT_MESSAGE_SIGNATURE);
    }

    fseek(fs, 0, SEEK_END);
    sign_length= ftell(fs);
    fseek(fs, 0, SEEK_SET);

    sign = (CK_BYTE *) malloc(sign_length + 1);
    fread(sign, sign_length, 1, fs);
    sign[sign_length] = 0;
    fclose(fs);

    debug_print("Verifying message signature");

    rv = function_pointer->C_VerifyInit(info->session_handle, &sign_mechanism, public_key);
    if (rv != CKR_OK) {
        free(sign);
        fail_msg("C_VerifyInit: rv = 0x%.8X\n", rv);
    }

    rv = function_pointer->C_Verify(info->session_handle, (CK_BYTE_PTR)message, message_length, (CK_BYTE_PTR)sign, sign_length);
    if (rv != CKR_OK) {
        free(sign);
        fail_msg("C_Verify: rv = 0x%.8X\n", rv);
    }

    debug_print("Message was successfully verified with public key!\n");
}

int main(int argc, char** argv) {

    if (argc != 2) {
        fprintf(stderr, "You have to specify path to PKCS#11 library.");
        exit(EXIT_FAILURE);
    }

    library_path = malloc(strlen(argv[1]) + 1);
    strcpy(library_path,argv[1]);
    library_path[strlen(argv[1])] = 0;

    const struct CMUnitTest tests_without_initialization[] = {
            cmocka_unit_test(get_all_mechanisms_test),
            cmocka_unit_test(is_ec_supported_test),

            /* User PIN tests */
            cmocka_unit_test_setup_teardown(initialize_token_with_user_pin_test, clear_token_without_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(change_user_pin_test, clear_token_with_user_login_setup, after_test_cleanup),

            /* Message digest tests */
            cmocka_unit_test_setup_teardown(create_hash_md5_short_message_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(create_hash_md5_long_message_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(create_hash_sha1_short_message_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(create_hash_sha1_long_message_test, clear_token_with_user_login_setup, after_test_cleanup),

            /* Key generation tests */
            cmocka_unit_test_setup_teardown(generate_rsa_key_pair_no_key_generated_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(generate_rsa_key_pair_test, clear_token_with_user_login_setup, after_test_cleanup),

            /* Sign and Verify tests */
            cmocka_unit_test_setup_teardown(sign_message_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(verify_signed_message_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),

    };

    return cmocka_run_group_tests(tests_without_initialization, group_setup, group_teardown);

}