#include "test_suits.h"
#include "common.h"
#include <openssl/x509.h>
#include <openssl/rsa.h>

extern int readonly;

static void is_ec_supported_test(void **state) {
    token_info_t *info = (token_info_t *) *state;
    if(!CHECK_EC_SUPPORT(info->supported.flags))
        skip();
}

static void initialize_token_with_user_pin_test(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_UTF8CHAR wrong_pin[] = {"WrongPin"};
    CK_RV rv;

    if(card_info.type == PKCS15) {
        if (init_token_with_default_pin(info))
            fail_msg("Could not initialize token with default user PIN\n");
    }

    debug_print("Test of logging in with wrong user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, wrong_pin, sizeof(wrong_pin) - 1);
    if (rv != CKR_PIN_INCORRECT) {
        fail_msg("Expected CKR_PIN_INCORRECT CKR_PIN_INCORRECT was not returned\n");
    }

    debug_print("Test of logging in with created user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, card_info.pin, card_info.pin_length);
    if (rv != CKR_OK) {
        fail_msg("PIN initialization for user failed. Could not log in to token!\n");
    }

}

static void change_user_pin_test(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    debug_print("Change user PIN from '%s' to '%s'", card_info.pin, card_info.change_pin);
    rv = function_pointer->C_SetPIN(info->session_handle, card_info.pin, card_info.pin_length, card_info.change_pin, card_info.pin_length);
    if (rv != CKR_OK) {
        debug_print("C_SetPIN: rv = 0x%.8X\n", rv);
        fail_msg("Change of user password was not successful\n");
    }

    debug_print("Logging out user");
    rv = function_pointer->C_Logout(info->session_handle);
    if (rv != CKR_OK) {
        fail_msg("Could not log out user!\n");
    }

    debug_print("Test of logging in with old user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, card_info.pin, card_info.pin_length);
    if (rv != CKR_PIN_INCORRECT) {
        fail_msg("User PIN was not correctly changed\n");
    }

    debug_print("Test of logging in with new user PIN");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, card_info.change_pin, card_info.pin_length);
    if (rv != CKR_OK) {
        fail_msg("PIN change failed. Could not log in with new user PIN!\n");
    }


}

static void get_all_mechanisms_test(void **state) {
    token_info_t *info = (token_info_t *) *state;
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

        supported_mechanisms_t supported = {0 };
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
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_DIGEST_MD5(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("34123b38395588f72f49d51d8dd6bd3b", NULL);

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
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_DIGEST_MD5(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("365573858b89fabadaae4a263305c5a3", NULL);

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
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_DIGEST_SHA1(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("4a331deda41ea92c562b6c7931c423c444155ad4", NULL);

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
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_DIGEST_MD5(info->supported.flags))
        skip();

    CK_BYTE *message_expected_hash = hex_string_to_byte_array("8001e8a7e1079e611b0945377784ea4d6ad273e7", NULL);

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
    token_info_t *info = (token_info_t *) *state;

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
    token_info_t *info = (token_info_t *) *state;

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

    /* Set public key. */
    CK_ATTRIBUTE public_key_template[] = {
            {CKA_ID, card_info.id, card_info.id_length},
            {CKA_LABEL, public_key_label, sizeof(public_key_label)-1},
            {CKA_VERIFY, &true_value, sizeof (true_value)},
            {CKA_ENCRYPT, &true_value, sizeof (true_value)},
            {CKA_TOKEN, &true_value, sizeof (true_value)},
            {CKA_MODULUS_BITS, &modulus_bits, sizeof (modulus_bits)},
            {CKA_PUBLIC_EXPONENT, public_exponent, sizeof (public_exponent)}
    };

    /* Set private key. */
    CK_ATTRIBUTE private_key_template[] = {
            {CKA_ID, card_info.id, card_info.id_length},
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
            { CKA_ID, card_info.id, card_info.id_length },
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
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_SIGN(info->supported.flags))
        skip();

    CK_RV rv;
    CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_OBJECT_HANDLE private_key;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, card_info.id, card_info.id_length },
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

	if (readonly) {
	    debug_print("Writing signature to '%s' for later checks", SHORT_MESSAGE_SIGNATURE_PATH);
		write_whole_file(&sign_length, sign, SHORT_MESSAGE_SIGNATURE_PATH);
		return;
	}

    debug_print("Comparing signature to '%s'", SHORT_MESSAGE_SIGNATURE_PATH);

    CK_ULONG data_length;
    CK_BYTE *input_buffer;

    if(read_whole_file(&data_length, &input_buffer, SHORT_MESSAGE_SIGNATURE_PATH))
        fail_msg("Could not read data from file '%s'!\n",SHORT_MESSAGE_SIGNATURE_PATH);


    if(data_length != sign_length) {
        free(input_buffer);
        fail_msg("Output signature has different length!\n");
    }

    if(memcmp(input_buffer, sign, data_length) != 0) {
        free(input_buffer);
        fail_msg("Signatures are not same!");
    }

    free(input_buffer);
    debug_print("Message was successfully signed with private key!\n");
}

static void verify_signed_message_test(void **state) {
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_VERIFY(info->supported.flags))
        skip();

    CK_RV rv;
    CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_OBJECT_HANDLE public_key;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, card_info.id, card_info.id_length },
    };

    if(find_object_by_template(info, template, &public_key, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find public key.");
    }

    CK_ULONG message_length;
    CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
    message_length = strlen(message);

    CK_ULONG sign_length = BUFFER_SIZE;
    CK_BYTE *sign;

    if(read_whole_file(&sign_length, &sign, SHORT_MESSAGE_SIGNATURE_PATH))
        fail_msg("Could not open file '%s'!\n",SHORT_MESSAGE_SIGNATURE_PATH);

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

    free(sign);
    debug_print("Message was successfully verified with public key!\n");
}

static void decrypt_encrypted_message_test(void **state) {
    token_info_t *info = (token_info_t *) *state;

    if(!CHECK_DECRYPT(info->supported.flags))
        skip();

    CK_RV rv;
    CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_OBJECT_HANDLE private_key;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, card_info.id, card_info.id_length },
    };

    if(find_object_by_template(info, template, &private_key, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find private key.");
    }

    CK_ULONG expected_message_length, output_message_length = BUFFER_SIZE;
    CK_BYTE *expected_message = (CK_BYTE *)DECRYPTED_MESSAGE, output_message[BUFFER_SIZE];
    expected_message_length = strlen(expected_message);

    CK_ULONG encrypted_message_length = BUFFER_SIZE;
    CK_BYTE *encrypted_message;

    if(read_whole_file(&encrypted_message_length, &encrypted_message, ENCRYPTED_MESSAGE_PATH))
        fail_msg("Could not open file '%s' for reading\n", ENCRYPTED_MESSAGE_PATH);

    debug_print("Decrypting encrypted message");

    rv = function_pointer->C_DecryptInit(info->session_handle, &sign_mechanism, private_key);
    if (rv != CKR_OK) {
        free(encrypted_message);
        fail_msg("C_DecryptInit: rv = 0x%.8X\n", rv);
    }

    rv = function_pointer->C_Decrypt(info->session_handle, (CK_BYTE_PTR) encrypted_message, encrypted_message_length, (CK_BYTE_PTR) output_message,
                                     &output_message_length);
    if (rv != CKR_OK) {
        free(encrypted_message);
        fail_msg("C_Decrypt: rv = 0x%.8X\n", rv);
    }

    if(expected_message_length != output_message_length) {
        free(encrypted_message);
        fail_msg("Decrypted message doesn't have expected length!\n");
    }

    if(memcmp(expected_message,output_message, expected_message_length) != 0) {
        free(encrypted_message);
        fail_msg("Decrypted message and expected message are different!\n");
    }

    free(encrypted_message);
    debug_print("Message was successfully decrypted!\n");
}

static void find_all_objects_test(void **state) {

    token_info_t *info = (token_info_t *) *state;

    CK_RV rv;
    CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
    CK_ULONG object_count, expected_object_count = OBJ_COUNT, returned_object_count = 0;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    rv = function_pointer->C_FindObjectsInit(info->session_handle, NULL_PTR, 0);

    if(rv != CKR_OK) {
        fail_msg("C_FindObjectsInit: rv = 0x%.8X\n", rv);
    }
    CK_ULONG_PTR object_class = malloc(sizeof(CK_ULONG));

    CK_ATTRIBUTE get_attributes[] = {
            {CKA_CLASS, object_class, sizeof(CK_ULONG)},
    };

    while (1) {
        rv = function_pointer->C_FindObjects(info->session_handle, &object_handle, 1, &object_count);
        if (rv != CKR_OK || object_count == 0)
            break;

        rv = function_pointer->C_GetAttributeValue(info->session_handle, object_handle, get_attributes, sizeof (get_attributes) / sizeof (CK_ATTRIBUTE));

        if (rv != CKR_OK) {
            free(object_class);
            fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
        }

        if(*object_class == CKO_PRIVATE_KEY || *object_class == CKO_PUBLIC_KEY || *object_class == CKO_CERTIFICATE) {
            returned_object_count++;
        }
    }

    free(object_class);
    rv = function_pointer->C_FindObjectsFinal(info->session_handle);
    if(rv != CKR_OK) {
        fail_msg("C_FindObjectsFinal: rv = 0x%.8X\n", rv);
    }

    if(expected_object_count != returned_object_count)
        fail_msg("Only '%d' objects were found on token but expected count was '%d'!\n",returned_object_count, expected_object_count);

    debug_print("All objects were successfully found!");
}

static void find_object_according_to_template_test(void **state) {

    token_info_t *info = (token_info_t *) *state;

    CK_OBJECT_HANDLE certificate_handle = CK_INVALID_HANDLE;

    CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_ID, card_info.id, card_info.id_length},
    };

    if (find_object_by_template(info, template, &certificate_handle, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find certificate.\n");
    }

}

static void find_object_and_read_attributes_test(void **state) {

    token_info_t *info = (token_info_t *) *state;

    CK_RV rv;
    CK_OBJECT_HANDLE certificate_handle = CK_INVALID_HANDLE;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_ID, card_info.id, card_info.id_length},
    };

    if (find_object_by_template(info, template, &certificate_handle, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find certificate.\n");
    }

    debug_print("\nTest if certificate attributes are correct ");
    CK_ULONG template_size;

    /* Create sample message. */
    CK_ATTRIBUTE get_certificate_attributes[] = {
            { CKA_CERTIFICATE_TYPE, NULL_PTR, 0},
            { CKA_LABEL, NULL_PTR, 0},

            /* Specific X.509 certificate attributes */
            { CKA_SUBJECT, NULL_PTR, 0},
            { CKA_ISSUER, NULL_PTR, 0},
            { CKA_SERIAL_NUMBER, NULL_PTR, 0},
    };

    template_size = sizeof (get_certificate_attributes) / sizeof (CK_ATTRIBUTE);

    rv = function_pointer->C_GetAttributeValue(info->session_handle, certificate_handle,
                                               get_certificate_attributes,
                                               template_size);

    if (rv != CKR_OK) {
        fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
    }

    /* Allocate memory to hold the data we want */
    for (int i = 0; i < template_size; i++) {
        get_certificate_attributes[i].pValue = malloc (get_certificate_attributes[i].ulValueLen * sizeof(CK_VOID_PTR));

        if (get_certificate_attributes[i].pValue == NULL) {
            for (int j = 0; j < i; j++)
                free(get_certificate_attributes[j].pValue);
        }
    }

    /* Call again to get actual attributes */
    rv = function_pointer->C_GetAttributeValue(info->session_handle, certificate_handle,
                                               get_certificate_attributes,
                                               template_size);

    char error_message[50] = { 0 };
    CK_BYTE *expected_subject = NULL, *expected_issuer = NULL, *expected_serial_number = NULL;


    if (rv != CKR_OK) {
        sprintf(error_message, "C_GetAttributeValue: rv = 0x%.8X\n", rv);
        goto cleanup;
    }

    debug_print("Comparing certificate type");
    if(CKC_X_509 != *((CK_ULONG_PTR)(get_certificate_attributes[0].pValue))) {
        sprintf(error_message, "Stored certificate is not X.509\n");
        goto cleanup;
    }

    debug_print("Comparing certificate label");
    CK_UTF8CHAR *label = (CK_UTF8CHAR *) get_certificate_attributes[1].pValue;
    CK_UTF8CHAR *expected_label = "Certificate";

    if(memcmp(expected_label,label, strlen(expected_label)) != 0) {
        sprintf(error_message, "Certificate label is different from expected\n");
        goto cleanup;
    }

    debug_print("Comparing certificate subject");
    CK_LONG subject_length = get_certificate_attributes[2].ulValueLen, expected_subject_length;
    expected_subject = hex_string_to_byte_array(CERTIFICATE_SUBJECT_HEX, &expected_subject_length);

    if(expected_subject_length != subject_length) {
        sprintf(error_message, "Length of subject name is not as expected\n");
        goto cleanup;
    }

    if(memcmp(expected_subject,(CK_BYTE *) get_certificate_attributes[2].pValue, subject_length) != 0) {
        sprintf(error_message, "Subjects are not the same!\n");
        goto cleanup;
    }

    debug_print("Comparing certificate issuer");
    CK_LONG issuer_length = get_certificate_attributes[3].ulValueLen, expected_issuer_length;
    expected_issuer = hex_string_to_byte_array(CERTIFICATE_ISSUER_HEX, &expected_issuer_length);

    if(expected_issuer_length != issuer_length) {
        sprintf(error_message, "Length of issuer name is not as expected\n");
        goto cleanup;
    }

    if(memcmp(expected_issuer,(CK_BYTE *) get_certificate_attributes[3].pValue, issuer_length) != 0) {
        sprintf(error_message, "Issuers are not the same!\n");
        goto cleanup;
    }

    debug_print("Comparing certificate serial number");
    CK_LONG serial_number_length = get_certificate_attributes[4].ulValueLen, expected_serial_number_length;
    expected_serial_number = hex_string_to_byte_array(CERTIFICATE_SERIAL_NUMBER, &expected_serial_number_length);

    if(expected_serial_number_length != serial_number_length) {
        sprintf(error_message, "Length of serial number is not as expected\n");
        goto cleanup;
    }

    if(memcmp(expected_serial_number,(CK_BYTE *) get_certificate_attributes[4].pValue, serial_number_length) != 0) {
        sprintf(error_message, "Serial numbers are not the same!\n");
        goto cleanup;
    }

    debug_print("All attributes were correctly stored on token");

cleanup:
    for (int j = 0; j < template_size; j++)
        free(get_certificate_attributes[j].pValue);

    if(expected_subject)
        free(expected_subject);

    if(expected_issuer)
        free(expected_issuer);

    if(expected_serial_number)
        free(expected_serial_number);

    if(strlen(error_message))
        fail_msg("%s",error_message);
}

static void generate_random_data_test(void **state) {

    token_info_t *info = (token_info_t *) *state;

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_LONG seed_length;
    CK_BYTE *seed_data = hex_string_to_byte_array(SEED_DATA, &seed_length);
    CK_BYTE *empty_array = hex_string_to_byte_array(EMPTY_ARRAY, NULL);
    CK_BYTE random_data[RANDOM_DATA_SIZE] = { 0 };
    CK_RV rv;

    char error_message[50] = { 0 };
    /* Seed random token generator */
    rv = function_pointer->C_SeedRandom(info->session_handle, seed_data, seed_length);
    if (rv != CKR_OK && rv != CKR_FUNCTION_NOT_SUPPORTED) {
        sprintf(error_message, "Could not seed random generator!\nC_SeedRandom: rv = 0x%.8x\n",rv);
        goto cleanup;
    }

    if(rv == CKR_FUNCTION_NOT_SUPPORTED) {
        fprintf(stdout, "Seed method is not supported.\n");
    }

    /* Generate random bytes */
    rv = function_pointer->C_GenerateRandom(info->session_handle, random_data, RANDOM_DATA_SIZE);

    if (rv != CKR_OK) {
        sprintf(error_message, "C_GenerateRandom: rv = 0x%.8x\n", rv);
        goto cleanup;
    }

    if(memcmp(empty_array, random_data, RANDOM_DATA_SIZE) == 0) {
        sprintf(error_message, "Random data were not generated!\n");
        goto cleanup;
    }

cleanup:
    free(seed_data);
    free(empty_array);

    if(strlen(error_message))
        fail_msg("%s", error_message);
}

static void create_object_test(void **state) {

    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_RV rv;
    CK_BBOOL true_value = CK_TRUE;
    CK_BBOOL false_value = CK_FALSE;

    CK_OBJECT_HANDLE des_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS dataClass = CKO_DATA;

    CK_UTF8CHAR application[] = {"My Application"};
    CK_UTF8CHAR label[] = { "My data" };
    CK_BYTE dataValue[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    CK_BYTE object_id[] = { 0x32, 0x00, 0x00 };

    CK_ATTRIBUTE data_template[] = {
            {CKA_CLASS, &dataClass, sizeof(dataClass)},
            {CKA_TOKEN, &true_value, sizeof(true_value)},
            {CKA_APPLICATION, application, sizeof(application)-1},
            {CKA_LABEL, label, sizeof(label)-1},
            {CKA_VALUE, dataValue, sizeof(dataValue)},
            {CKA_PRIVATE, &false_value, sizeof(false_value)},
            {CKA_OBJECT_ID, object_id, sizeof(object_id)}
    };


    /* Create a data object */
    rv = function_pointer->C_CreateObject(info->session_handle, data_template, sizeof(data_template) / sizeof(CK_ATTRIBUTE), &des_key_handle);
    if(rv == CKR_FUNCTION_NOT_SUPPORTED) {
        fprintf(stdout, "Function C_CreateObject is not supported!\n");
        skip();
    }

    if (rv != CKR_OK) {
        fail_msg("C_CreateObject: rv = 0x%.8x\n", rv);
    }

    if(des_key_handle == CK_INVALID_HANDLE)
        fail_msg("Object was not created on token!\n");
}

static void destroy_object_test(void **state) {

    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_RV rv;
    CK_OBJECT_HANDLE certificate_handle;
    CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
    CK_ATTRIBUTE template[] = {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_ID, card_info.id, card_info.id_length },
    };

    if(find_object_by_template(info, template, &certificate_handle, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Could not find certificate.\n");
    }

    rv = function_pointer->C_DestroyObject(info->session_handle, certificate_handle);
    if(rv == CKR_FUNCTION_NOT_SUPPORTED) {
        fprintf(stdout, "Function C_DestroyObject is not supported!\n");
        skip();
    }

    if(rv != CKR_OK) {
        fail_msg("Could not destroy object!\nC_DestroyObject: rv = 0x%.8x\n", rv);
    }

    if(!find_object_by_template(info, template, &certificate_handle, sizeof(template) / sizeof(CK_ATTRIBUTE))) {
        fail_msg("Certificate was not deleted from token.\n");
    }
}

char *convert_byte_string(unsigned char *id, unsigned long length)
{
	char *data = malloc(3 * length * sizeof(char) + 1);
	for (int i = 0; i < length; i++)
		sprintf(&data[i*3], "%02X:", id[i]);
	data[length*3-1] = '\0';
	return data;
}

typedef struct {
	char	*key_id;
	CK_ULONG key_id_size;
	char	*id_str;
	X509	*x509;
	RSA		*rsa;
	CK_OBJECT_HANDLE private_handle;
	char 	*sign;
	char	*decrypt;
	char	*key_type;
} test_cert_t;

static void readonly_tests(void **state) {

    token_info_t *info = (token_info_t *) *state;

    CK_RV rv;
    CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_ULONG object_count;

    CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_ID, NULL, 0},
    };
	CK_LONG attributes_count = sizeof(template) / sizeof(CK_ATTRIBUTE);
	CK_ATTRIBUTE attrs[] = {
			//{ CKA_CERTIFICATE_TYPE, NULL_PTR, 0},
			{ CKA_ID, NULL_PTR, 0},
			{ CKA_VALUE, NULL_PTR, 0},
			{ CKA_LABEL, NULL_PTR, 0},
	};
	CK_ATTRIBUTE private_attrs[] = {
            { CKA_SIGN, NULL, 0},
            { CKA_DECRYPT, NULL, 0},
            { CKA_KEY_TYPE, NULL, 0},

			/* Specific X.509 certificate attributes */
			//{ CKA_SUBJECT, NULL_PTR, 0},
			//{ CKA_ISSUER, NULL_PTR, 0},
			//{ CKA_SERIAL_NUMBER, NULL_PTR, 0},
	};
	CK_ULONG template_size = sizeof (attrs) / sizeof (CK_ATTRIBUTE);

	test_cert_t *objects = NULL;
	unsigned int objects_size = 0;

    debug_print("\nSearch for all certificates on the card");
    rv = function_pointer->C_FindObjectsInit(info->session_handle, template, 1); // XXX search only by the first attribute!
    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjectsInit: rv = 0x%.8X\n", rv);
        fail_msg("Could not find certificate.\n");
    }

	while(1) {
		/* clean up for new results openssh ssh-pkcs11.c */
		for (int i = 0; i < template_size; i++) {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = 0;
		}

		// XXX search only by the first attribute!
		rv = function_pointer->C_FindObjects(info->session_handle, &object_handle, 1, &object_count);
		if (object_count == 0)
			break;
		if (rv != CKR_OK) {
			fprintf(stderr, "C_FindObjects: rv = 0x%.8X\n", rv);
 			fail_msg("Could not find certificate.\n");
		}

		rv = function_pointer->C_GetAttributeValue(info->session_handle, object_handle,
												   attrs,
												   template_size);
		if (rv != CKR_OK) {
			fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
		}

		/* Allocate memory to hold the data we want */
		for (int i = 0; i < template_size; i++) {
			if (attrs[i].ulValueLen != 0) 
				attrs[i].pValue = malloc(attrs[i].ulValueLen * sizeof(CK_VOID_PTR));

			if (attrs[i].pValue == NULL) {
				for (int j = 0; j < i; j++)
					free(attrs[j].pValue);
			}
		}

		/* Call again to get actual attributes */
		rv = function_pointer->C_GetAttributeValue(info->session_handle, object_handle,
												   attrs,
												   template_size);

		objects_size = (object_count > objects_size+1 ? object_count : objects_size+1);
		objects = realloc(objects, objects_size*sizeof(test_cert_t));

		if (rv != CKR_OK || objects == NULL) {
			for (int j = 0; j < template_size; j++)
				free(attrs[j].pValue);
			fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
		}

		/* get the type and data, store in some structure */
		int o = objects_size - 1;
		objects[o].key_id = attrs[0].pValue;
		objects[o].key_id_size = attrs[0].ulValueLen;
		objects[o].id_str = convert_byte_string(objects[o].key_id, objects[o].key_id_size);
		// XXX malloc
		objects[o].private_handle = 0;
		if ((objects[o].x509 = X509_new()) == NULL) {
			fail_msg("X509_new");
		} else if(d2i_X509(&(objects[o].x509), (const unsigned char **) &(attrs[1].pValue), attrs[1].ulValueLen) == NULL) {
			fail_msg("d2i_X509");
		}
		/* XXX X509_get_pubkey */
		debug_print(" [ OK %s ] Certificate with label %s loaded successfully",
			objects[o].id_str, attrs[2].pValue);
	}

    rv = function_pointer->C_FindObjectsFinal(info->session_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8X\n", rv);
 		fail_msg("Could not find certificate.\n");
    }


	/* do the same shit with private keys (collect handles based on the collected IDs) */
    debug_print("\nSearch for all private keys respective to the certificates");
	template[0].pValue = &privateClass;
	for (int i = 0; i < objects_size; i++) {
		template[1].pValue = objects[i].key_id;
		template[1].ulValueLen = objects[i].key_id_size;
		rv = function_pointer->C_FindObjectsInit(info->session_handle, template, attributes_count);
		if (rv != CKR_OK) {
			fprintf(stderr, "C_FindObjectsInit: rv = 0x%.8X\n", rv);
			fail_msg("Could not find private key.\n");
		}
		rv = function_pointer->C_FindObjects(info->session_handle, &object_handle, attributes_count, &object_count); //XXX here we search by both attributes
		if (object_count == 0)
			debug_print("Could not find corespoing private key for certificate with ID=%s",
				objects[i].id_str);
		if (rv != CKR_OK) {
			fprintf(stderr, "C_FindObjects: rv = 0x%.8X\n", rv);
 			fail_msg("Could not find private keys.\n");
		}

		rv = function_pointer->C_GetAttributeValue(info->session_handle, object_handle,
												   private_attrs,
												   template_size);
		if (rv != CKR_OK) {
			fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
		}

		/* Allocate memory to hold the data we want */
		for (int i = 0; i < template_size; i++) {
			if (private_attrs[i].ulValueLen != 0) 
				private_attrs[i].pValue = malloc(private_attrs[i].ulValueLen * sizeof(CK_VOID_PTR));

			if (private_attrs[i].pValue == NULL) {
				for (int j = 0; j < i; j++)
					free(private_attrs[j].pValue);
			}
		}

		/* Call again to get actual attributes */
		rv = function_pointer->C_GetAttributeValue(info->session_handle, object_handle,
												   private_attrs,
												   template_size);

		/* store the handle for later */
		objects[i].private_handle = object_handle;
		objects[i].sign = private_attrs[0].pValue;
		objects[i].decrypt = private_attrs[1].pValue;
		objects[i].key_type = private_attrs[2].pValue;

		/* or do all the stuff here ... just for sanity? */
		debug_print(" [ OK %s ] Private key to the certificate found successfully S:%02X D:%02X T:%02X",
			objects[i].id_str, *objects[i].sign, *objects[i].decrypt, *objects[i].key_type);

 		rv = function_pointer->C_FindObjectsFinal(info->session_handle);
		if (rv != CKR_OK) {
	    	fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8X\n", rv);
 			fail_msg("Could not find certificate.\n");
		}
	}

    CK_ULONG sign_length = BUFFER_SIZE;
    CK_BYTE sign[BUFFER_SIZE];
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
	CK_ULONG message_length = strlen(message);
    CK_ULONG dec_message_length = BUFFER_SIZE;
    CK_BYTE dec_message[BUFFER_SIZE];
    debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (int i = 0; i < objects_size; i++) {
		/* do the Sign&Verify and/or Encrypt&Decrypt */
		int used = 0;
		if (*objects[i].sign) {
			// XXX different mechs based on key type
			/*sign_mechanism.mechanism = CKM_RSA_PKCS;
			sign_mechanism.pParameter = NULL;
			sign_mechanism.ulParameterLen = 0;*/
			EVP_PKEY *evp = X509_get_pubkey(objects[i].x509);
			if (evp == NULL) {
				fail_msg("X509_get_pubkey failed.");
			}
			RSA *rsa = RSAPublicKey_dup(evp->pkey.rsa);
			if (rsa == NULL) {
				fail_msg("RSAPublicKey_dup failed");
			}

			debug_print(" [ INFO %s ] Signing message", objects[i].id_str);

			rv = function_pointer->C_SignInit(info->session_handle, &sign_mechanism,
				objects[i].private_handle);
			if (rv == CKR_KEY_TYPE_INCONSISTENT) {
				debug_print(" [ SKIP %s ] Not allowed to sign with this key", objects[i].id_str);
				continue; // XXX skips all the key even for decrypt
			}
			if (rv != CKR_OK) {
				fail_msg("C_SignInit: rv = 0x%.8X\n", rv);
			}

			rv = function_pointer->C_Sign(info->session_handle, message, message_length,
										  sign, &sign_length);
			if (rv != CKR_OK) {
				fail_msg("C_Sign: rv = 0x%.8X\n", rv);
			}

			debug_print(" [ INFO %s ] Verify message sinature", objects[i].id_str);
			int dec_message_length = RSA_public_decrypt(sign_length, sign, dec_message, rsa,
				RSA_PKCS1_PADDING);
			if (dec_message_length < 0) {
				fail_msg("RSA_public_decrypt: rv = 0x%.8X\n", dec_message_length);
			}
			dec_message[dec_message_length] = '\0';
			if (memcmp(dec_message, message, dec_message_length) == 0) {
				debug_print(" [ OK %s ] Signature is valid.", objects[i].id_str);
			} else {
				debug_print(" [ ERROR %s ] Signature is not valid. Recovered text: %s",
					objects[i].id_str, dec_message);
			}
			used = 1;
		}

		if (*objects[i].decrypt) {
			EVP_PKEY *evp = X509_get_pubkey(objects[i].x509);
			if (evp == NULL) {
				fail_msg("X509_get_pubkey failed.");
			}
			RSA *rsa = RSAPublicKey_dup(evp->pkey.rsa);
			if (rsa == NULL) {
				fail_msg("RSAPublicKey_dup failed");
			}

			debug_print(" [ INFO %s ] Encrypt message", objects[i].id_str);
			char *enc_message = malloc(RSA_size(rsa));
			int enc_message_length = RSA_public_encrypt(message_length, message, enc_message, rsa,
				RSA_PKCS1_PADDING);
			if (enc_message_length < 0) {
				fail_msg("RSA_public_encrypt: rv = 0x%.8X\n", enc_message_length);
			}

			debug_print(" [ INFO %s ] Decrypt message", objects[i].id_str);
			rv = function_pointer->C_DecryptInit(info->session_handle, &sign_mechanism,
				objects[i].private_handle);
			if (rv == CKR_KEY_TYPE_INCONSISTENT) {
				debug_print(" [ SKIP %s ] Not allowed to decrypt with this key", objects[i].id_str);
				continue;
			}
			if (rv != CKR_OK) {
				fail_msg("C_DecryptInit: rv = 0x%.8X\n", rv);
			}

			rv = function_pointer->C_Decrypt(info->session_handle, enc_message, enc_message_length,
										  dec_message, &dec_message_length);
			if (rv == CKR_USER_NOT_LOGGED_IN) {
				debug_print(" [ SKIP %s ] Not allowed to decrypt with this key", objects[i].id_str);
				continue;
			}
			if (rv != CKR_OK) {
				fail_msg("C_Decrypt: rv = 0x%.8X\n", rv);
			}

			dec_message[dec_message_length] = '\0';
			if (memcmp(dec_message, message, dec_message_length) == 0) {
				debug_print(" [ OK %s ] Text decrypted successfully.", objects[i].id_str);
			} else {
				debug_print(" [ ERROR %s ] Text decryption failed. Recovered text: %s",
					objects[i].id_str, dec_message);
			}
			used = 1;
		}

		if (!used) {
			debug_print(" [ WARN %s ] Private key with unknown purpose T:%02X",
			objects[i].id_str, *objects[i].key_type);
		}
	}


    debug_print("The functionallity of the keys on the card was verified");
}

int main(int argc, char** argv) {

    char command, card_type[25];
    int args_count = 0;

    while ((command = getopt(argc, argv, "m:t:s:r")) != -1) {
        switch (command) {
            case 'm':
                library_path = strdup(optarg);
                args_count++;
                break;
            case 't':
                strcpy(card_type,optarg);

                if (strcmp(optarg, "PKCS15") == 0)
                    card_info.type = PKCS15;
                else if (strcmp(optarg, "PIV") == 0)
                    card_info.type = PIV;
                else {
                    fprintf(stderr, "Unsupported card type \"%s\"\n", optarg);
                    display_usage();
                    return 1;
                }
                args_count++;
                break;
            case 's':
                card_info.so_pin = strdup(optarg);
                card_info.so_pin_length = strlen(optarg);
                break;
            case 'r':
                readonly = 1;
                break;
            case 'h':
            case '?':
                display_usage();
                return 0;
            default:
                break;
        }
    }

    if(args_count < 2) {
        display_usage();
        return 1;
    }

    if(set_card_info()) {
        fprintf(stderr, "Could not set card info!\n");
        return 1;
    }

    debug_print("Card info:\n\tPIN %s\n\tCHANGE_PIN %s\n\tPIN LENGTH %d\n\tID 0x%02x\n\tID LENGTH %d",
           card_info.pin, card_info.change_pin, card_info.pin_length, card_info.id[0], card_info.id_length);

    const struct CMUnitTest readonly_tests_without_initialization[] = {
            //cmocka_unit_test(get_all_mechanisms_test),
            cmocka_unit_test(is_ec_supported_test),

			/* Complex readonly test of all objects on the card  */
            cmocka_unit_test_setup_teardown(readonly_tests, clear_token_with_user_login_setup, after_test_cleanup),
			};
    const struct CMUnitTest readonly_tests_without_initialization_others[] = {

            /* User PIN tests */
            cmocka_unit_test_setup_teardown(initialize_token_with_user_pin_test, clear_token_without_login_setup, after_test_cleanup),

            /* Sign and Verify tests */
            cmocka_unit_test_setup_teardown(sign_message_test, clear_token_with_user_login_setup, after_test_cleanup),
//            cmocka_unit_test_setup_teardown(verify_signed_message_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup), // TODO C_Verify fails

            /* Decryption tests */
//            cmocka_unit_test_setup_teardown(decrypt_encrypted_message_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup), // we don't know the private key

            /* Find objects tests */
            cmocka_unit_test_setup_teardown(find_all_objects_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(find_object_according_to_template_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(find_object_and_read_attributes_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),

            /* Generate random data tests */
//            cmocka_unit_test_setup_teardown(generate_random_data_test, clear_token_with_user_login_setup, after_test_cleanup),

            /* Create and delete objects tests */
//            cmocka_unit_test_setup_teardown(create_object_test, clear_token_with_user_login_setup, after_test_cleanup),
//            cmocka_unit_test_setup_teardown(destroy_object_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),

    };
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

            /* Decryption tests */
            cmocka_unit_test_setup_teardown(decrypt_encrypted_message_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),

            /* Find objects tests */
            cmocka_unit_test_setup_teardown(find_all_objects_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(find_object_according_to_template_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(find_object_and_read_attributes_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),

            /* Generate random data tests */
            cmocka_unit_test_setup_teardown(generate_random_data_test, clear_token_with_user_login_setup, after_test_cleanup),

            /* Create and delete objects tests */
            cmocka_unit_test_setup_teardown(create_object_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(destroy_object_test, clear_token_with_user_login_and_import_keys_setup, after_test_cleanup),

    };

    if (readonly) {
        return cmocka_run_group_tests(readonly_tests_without_initialization, group_setup, group_teardown);;
    } else {
        return cmocka_run_group_tests(tests_without_initialization, group_setup, group_teardown);;
    }
}

