#include "test_suits.h"
#include "common.h"
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

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

/******************************************************************************
 *****************************************************************************/

char *convert_byte_string(unsigned char *id, unsigned long length)
{
	char *data = malloc(3 * length * sizeof(char) + 1);
	for (int i = 0; i < length; i++)
		sprintf(&data[i*3], "%02X:", id[i]);
	data[length*3-1] = '\0';
	return data;
}

#define VERIFY_SIGN		0x02
#define VERIFY_DECRYPT	0x04

typedef struct {
	CK_MECHANISM_TYPE mech;
	int flags;
} test_mech_t;

typedef struct {
	char	*key_id;
	CK_ULONG key_id_size;
	char	*id_str;
	X509	*x509;
	int		 type;
	union {
		RSA		*rsa;
		EC_KEY	*ec;
	} key;
	CK_OBJECT_HANDLE private_handle;
	CK_BBOOL	sign;
	CK_BBOOL	decrypt;
	CK_BBOOL	verify;
	CK_BBOOL	encrypt;
	CK_KEY_TYPE	key_type;
	CK_BBOOL	always_auth;
	char		*label;
	CK_ULONG 	 bits;
	int			verify_public;
	test_mech_t	*mechs;
	int			num_mechs;
} test_cert_t;

typedef struct {
	unsigned int count;
	test_cert_t *data;
} test_certs_t;

int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
    CK_RV rv;
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
	CK_ULONG message_length = strlen(message);
    CK_BYTE dec_message[BUFFER_SIZE];
	CK_ULONG dec_message_length = BUFFER_SIZE;

	sign_mechanism.mechanism = mech->mech;
	if (o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA key for encryption", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Encrypt message", o->id_str);
	char *enc_message = malloc(RSA_size(o->key.rsa));
	if (enc_message == NULL)
		fail_msg("malloc returned null");

	int enc_message_length = RSA_public_encrypt(message_length, message,
		enc_message, o->key.rsa, RSA_PKCS1_PADDING);
	if (enc_message_length < 0) {
		free(enc_message);
		fail_msg("RSA_public_encrypt: rv = 0x%.8X\n", enc_message_length);
	}

	debug_print(" [ KEY %s ] Decrypt message", o->id_str);
	rv = info->function_pointer->C_DecryptInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [ SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		free(enc_message);
		return 0;
	}
	if (rv != CKR_OK)
		fail_msg("C_DecryptInit: rv = 0x%.8X\n", rv);

	rv = info->function_pointer->C_Decrypt(info->session_handle, enc_message, enc_message_length,
								  dec_message, &dec_message_length);
	free(enc_message);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		debug_print(" [ SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		return 0;
	} else if (rv != CKR_OK)
		fail_msg("C_Decrypt: rv = 0x%.8X\n", rv);

	dec_message[dec_message_length] = '\0';
	if (memcmp(dec_message, message, dec_message_length) == 0
			&& dec_message_length == message_length) {
		debug_print(" [ OK %s ] Text decrypted successfully.", o->id_str);
		mech->flags |= VERIFY_DECRYPT;
	} else {
		debug_print(" [ ERROR %s ] Text decryption failed. Recovered text: %s",
			o->id_str, dec_message);
		return 0;
	}
	return 1;
}

int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
	CK_ULONG message_length)
{
    CK_RV rv;
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
    CK_BYTE *sign = NULL;
    CK_ULONG sign_length = 0;

	if (message_length > strlen(message))
		fail_msg("Truncate is longer than the actuall message");

	sign_mechanism.mechanism = mech->mech;
	if (o->type != EVP_PK_EC && o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA and non-EC key", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Signing message of length %d", o->id_str, message_length);

	rv = info->function_pointer->C_SignInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [ SKIP %s ] Not allowed to sign with this key?", o->id_str);
		return 0;
	} else if (rv == CKR_MECHANISM_INVALID) {
		debug_print(" [ SKIP %s ] Bad mechanism. Not supported?", o->id_str);
		return 0;
	} else if (rv != CKR_OK)
		fail_msg("C_SignInit: rv = 0x%.8X\n", rv);

	if (o->always_auth) {
	    rv = info->function_pointer->C_Login(info->session_handle,
			CKU_CONTEXT_SPECIFIC, card_info.pin, card_info.pin_length);
	    if (rv != CKR_OK) {
			debug_print(" [ SKIP %s ] Re-authentication failed", o->id_str);
	    }
	}

	/* Call C_Sign with NULL argument to find out the real size of signature */
	rv = info->function_pointer->C_Sign(info->session_handle,
		message, message_length, sign, &sign_length);
	if (rv != CKR_OK)
		fail_msg("C_Sign: rv = 0x%.8X\n", rv);

	sign = malloc(sign_length);
	if (sign == NULL)
		fail_msg("malloc failed");

	/* Call C_Sign with allocated buffer to the the actual signature */
	rv = info->function_pointer->C_Sign(info->session_handle,
		message, message_length, sign, &sign_length);
	if (rv != CKR_OK) {
		free(sign);
		fail_msg("C_Sign: rv = 0x%.8X\n", rv);
	}

	debug_print(" [ KEY %s ] Verify message sinature", o->id_str);
	int dec_message_length = 0;
	if (o->type == EVP_PK_RSA) {
		CK_BYTE dec_message[BUFFER_SIZE];
		dec_message_length = RSA_public_decrypt(sign_length, sign,
			dec_message, o->key.rsa, RSA_PKCS1_PADDING);
		free(sign);
		if (dec_message_length < 0)
			fail_msg("RSA_public_decrypt: rv = %d: %s\n", dec_message_length,
				ERR_error_string(ERR_peek_last_error(), NULL));
		dec_message[dec_message_length] = '\0';
		if (memcmp(dec_message, message, dec_message_length) == 0
				&& dec_message_length == message_length) {
			debug_print(" [ OK %s ] Signature is valid.", o->id_str);
			mech->flags |= VERIFY_SIGN;
		 } else {
			debug_print(" [ ERROR %s ] Signature is not valid. Recovered text: %s",
				o->id_str, dec_message);
			return 0;
		}
	} else if (o->type == EVP_PK_EC) {
		ECDSA_SIG *sig = ECDSA_SIG_new();
		if (sig == NULL)
			fail_msg("ECDSA_SIG_new: failed");
		int nlen = sign_length/2;
		BN_bin2bn(&sign[0], nlen, sig->r);
		BN_bin2bn(&sign[nlen], nlen, sig->s);
		free(sign);
		if ((rv = ECDSA_do_verify(message, message_length, sig, o->key.ec)) == 1) {
			debug_print(" [ OK %s ] EC Signature of length %d is valid.",
				o->id_str, message_length);
			mech->flags |= VERIFY_SIGN;
		} else {
			fail_msg("ECDSA_do_verify: rv = %d: %s\n", rv,
				ERR_error_string(ERR_peek_last_error(), NULL));
		}
		ECDSA_SIG_free(sig);
	} else {
		debug_print(" [ KEY %s ] Unknown type. Not verifying", o->id_str);
		return 0;
	}

	return 1;
}

int search_objects(test_certs_t *objects, token_info_t *info,
	CK_ATTRIBUTE filter[], CK_LONG filter_size, CK_ATTRIBUTE template[], CK_LONG template_size,
	int (*callback)(test_certs_t *, CK_ATTRIBUTE[], unsigned int, CK_OBJECT_HANDLE))
{
    CK_RV rv;
    CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_ULONG object_count;
    CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;

	/* FindObjects first
	 *  https://wiki.oasis-open.org/pkcs11/CommonBugs
	 */
    rv = fp->C_FindObjectsInit(info->session_handle, filter, filter_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjectsInit: rv = 0x%.8X\n", rv);
		return -1;
    }

	CK_OBJECT_HANDLE_PTR object_handles = NULL;
	unsigned long i = 0, objects_length = 0;
	while(1) {
		rv = fp->C_FindObjects(info->session_handle, &object_handle, 1, &object_count);
		if (object_count == 0)
			break;
		if (rv != CKR_OK) {
			fprintf(stderr, "C_FindObjects: rv = 0x%.8X\n", rv);
			return -1;
		}
		/*  store handle */
		if (i >= objects_length) {
			objects_length += 4; // do not realloc after each row
			object_handles = realloc(object_handles, objects_length * sizeof(CK_OBJECT_HANDLE_PTR));
			if (object_handles == NULL)
		 		fail_msg("Realloc failed. Need to store object handles.\n");
		}
		object_handles[i++] = object_handle;
	}
	objects_length = i; //terminate list of handles

    rv = fp->C_FindObjectsFinal(info->session_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8X\n", rv);
 		fail_msg("Could not find certificate.\n");
    }

	for (int i = 0;i < objects_length; i++) {
		/* Find attributes one after another to handle errors
		 *  https://wiki.oasis-open.org/pkcs11/CommonBugs
		 */
		for (int j = 0; j < template_size; j++) {
			template[j].pValue = NULL;
			template[j].ulValueLen = 0;

			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
				continue;
			else if (rv != CKR_OK)
				fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);

			/* Allocate memory to hold the data we want */
			if (template[j].ulValueLen != 0) {
				template[j].pValue = malloc(template[j].ulValueLen);
				if (template[j].pValue == NULL)
					fail_msg("malloc failed");
			}
			/* Call again to get actual attribute */
			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv != CKR_OK)
				fail_msg("C_GetAttributeValue: rv = 0x%.8X\n", rv);
		}

		callback(objects, template, template_size, object_handles[i]);
		// XXX check results
		for (int j = 0; j < template_size; j++)
			free(template[j].pValue);
	}
	free(object_handles);
}

/**
 * Allocate place in the structure for every certificte found
 * and store related information
 */
int callback_certificates(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	EVP_PKEY *evp;
	objects->count = objects->count+1;
	objects->data = realloc(objects->data, objects->count*sizeof(test_cert_t));
	const u_char *cp;

	if (objects->data == NULL)
		return -1;

	test_cert_t *o = &(objects->data[objects->count - 1]);

	/* get the type and data, store in some structure */
	o->key_id = malloc(template[0].ulValueLen);
	o->key_id = memcpy(o->key_id, template[0].pValue, template[0].ulValueLen);
	o->key_id_size = template[0].ulValueLen;
	o->id_str = convert_byte_string(o->key_id, o->key_id_size);
	o->private_handle = CK_INVALID_HANDLE;
	o->always_auth = 0;
	o->bits = -1;
	o->label = malloc(template[2].ulValueLen + 1);
	strncpy(o->label, template[2].pValue, template[2].ulValueLen);
	o->label[template[2].ulValueLen] = '\0';
	o->verify_public = 0;
	o->mechs = NULL;
	o->type = -1;
	cp = template[1].pValue;
	if ((o->x509 = X509_new()) == NULL) {
		fail_msg("X509_new");
	} else if (d2i_X509(&(o->x509), (const unsigned char **) &cp,
			template[1].ulValueLen) == NULL) {
		fail_msg("d2i_X509");
	} else if ((evp = X509_get_pubkey(o->x509)) == NULL) {
		fail_msg("X509_get_pubkey failed.");
	}
	if (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		if ((o->key.rsa = RSAPublicKey_dup(evp->pkey.rsa)) == NULL)
			fail_msg("RSAPublicKey_dup failed");
		o->type = EVP_PK_RSA;
		o->bits = EVP_PKEY_bits(evp);

		o->num_mechs = 1; // the only mechanism for RSA
		o->mechs = malloc(sizeof(test_mech_t));
		if (o->mechs == NULL)
			fail_msg("malloc failed for mechs");
		o->mechs[0].mech = CKM_RSA_PKCS;
		o->mechs[0].flags = 0;
	} else if (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		if ((o->key.ec = EC_KEY_dup(evp->pkey.ec)) == NULL)
			fail_msg("EC_KEY_dup failed");
		o->type = EVP_PK_EC;
		o->bits = EVP_PKEY_bits(evp);

		o->num_mechs = 1; // XXX CKM_ECDSA_SHA1 is not supported on Test PIV cards
		o->mechs = malloc(2*sizeof(test_mech_t));
		if (o->mechs == NULL)
			fail_msg("malloc failed for mechs");
		o->mechs[0].mech = CKM_ECDSA;
		o->mechs[0].flags = 0;
		o->mechs[1].mech = CKM_ECDSA_SHA1;
		o->mechs[1].flags = 0;
	} else {
		fprintf(stderr, "[ WARN %s ]evp->type =  0x%.4X (not RSA, EC)\n", o->id_str, evp->type);
	}
	EVP_PKEY_free(evp);

	debug_print(" [ OK %s ] Certificate with label %s loaded successfully",
		o->id_str, o->label);
	return 1;
}

/**
 * Pair found private keys on the card with existing certificates
 */
int callback_private_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	unsigned int i = 0;
	char *key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
	while (i < objects->count && objects->data[i].key_id_size == template[3].ulValueLen && 
		memcmp(objects->data[i].key_id, template[3].pValue, template[3].ulValueLen) != 0)
		i++;

	if (i == objects->count) {
    	fprintf(stderr, "Can't find certificate for private key with ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	if (objects->data[i].private_handle != CK_INVALID_HANDLE) {
    	fprintf(stderr, "Object already filled? ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	free(key_id);

	objects->data[i].private_handle = object_handle;
	objects->data[i].sign = (template[0].ulValueLen != (CK_BBOOL) -1)
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	objects->data[i].decrypt = (template[1].ulValueLen != (CK_BBOOL) -1)
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;
	objects->data[i].key_type = (template[2].ulValueLen != (CK_ULONG) -1)
		? *((CK_KEY_TYPE *) template[2].pValue) : -1;
	objects->data[i].always_auth = (template[2].ulValueLen != (CK_BBOOL) -1)
		? *((CK_BBOOL *) template[2].pValue) : CK_FALSE;

	debug_print(" [ OK %s ] Private key to the certificate found successfully S:%d D:%d T:%02X",
		objects->data[i].id_str, objects->data[i].sign, objects->data[i].decrypt,
		objects->data[i].key_type);
}

/**
 * Pair found public keys on the card with existing certificates
 */
int callback_public_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	unsigned int i = 0;
	char *key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
	while (i < objects->count && objects->data[i].key_id_size == template[3].ulValueLen && 
		memcmp(objects->data[i].key_id, template[3].pValue, template[3].ulValueLen) != 0)
		i++;

	if (i == objects->count) {
    	fprintf(stderr, "Can't find certificate for public key with ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	if (objects->data[i].verify_public != 0) {
    	fprintf(stderr, "Object already filled? ID %s\n", key_id);
		free(key_id);
		return -1;
	}
	free(key_id);

	objects->data[i].verify = (template[0].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	objects->data[i].encrypt = (template[1].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;

	/* check if we get the same public key as from the certificate */
	if (objects->data[i].key_type == CKK_RSA) {
		objects->data[i].bits = (template[6].ulValueLen != (CK_ULONG) -1)
			? *((CK_ULONG *)template[6].pValue) : -1;
		RSA *rsa = RSA_new();
		rsa->n = BN_bin2bn(template[4].pValue, template[4].ulValueLen, NULL);
		rsa->e = BN_bin2bn(template[5].pValue, template[5].ulValueLen, NULL);
		if (BN_cmp(objects->data[i].key.rsa->n, rsa->n) != 0 ||
			BN_cmp(objects->data[i].key.rsa->e, rsa->e) != 0) {
    		fprintf(stderr, " [ WARN %s ] Got different public key then the from the certificate ID\n",
				objects->data[i].id_str);
			return -1;
		}
		RSA_free(rsa);
		objects->data[i].verify_public = 1;
	} else if (objects->data[i].key_type == CKK_EC) {
		fprintf(stderr, " [ WARN %s] EC public key check skipped so far\n",
			objects->data[i].id_str);

		EC_KEY *ec = EC_KEY_new();
		int nid = NID_X9_62_prime256v1; /* 0x11 */
		//int nid =  NID_secp384r1;		/* 0x14 */
		EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(nid);
		EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
		EC_POINT *ecpoint = EC_POINT_new(ecgroup);

		EC_KEY_set_public_key(ec, ecpoint);
		return -1;
	} else {
    	fprintf(stderr, " [ WARN %s] non-RSA, non-EC key\n", objects->data[i].id_str);
		return -1;
	}

	debug_print(" [ OK %s ] Public key to the certificate found successfully V:%d E:%d T:%02X",
		objects->data[i].id_str, objects->data[i].verify, objects->data[i].encrypt,
		objects->data[i].key_type);
}

static void search_for_all_objects(test_certs_t *objects, token_info_t *info) {
    CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
    CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE filter[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
    };
	CK_ATTRIBUTE attrs[] = {
			{ CKA_ID, NULL_PTR, 0},
			{ CKA_VALUE, NULL_PTR, 0},
			{ CKA_LABEL, NULL_PTR, 0},
			{ CKA_CERTIFICATE_TYPE, NULL_PTR, 0},

			/* Specific X.509 certificate attributes */
			//{ CKA_SUBJECT, NULL_PTR, 0},
			//{ CKA_ISSUER, NULL_PTR, 0},
			//{ CKA_SERIAL_NUMBER, NULL_PTR, 0},
			//{ CKA_ALLOWED_MECHANISMS, NULL_PTR, 0},
	};
	CK_ULONG attrs_size = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE private_attrs[] = {
            { CKA_SIGN, NULL, 0}, // CK_BBOOL
            { CKA_DECRYPT, NULL, 0}, // CK_BBOOL
            { CKA_KEY_TYPE, NULL, 0}, // CKK_
			{ CKA_ID, NULL, 0},
			{ CKA_ALWAYS_AUTHENTICATE, NULL, 0}, // CK_BBOOL
	};
	CK_ULONG private_attrs_size = sizeof (private_attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE public_attrs[] = {
            { CKA_VERIFY, NULL, 0}, // CK_BBOOL
            { CKA_ENCRYPT, NULL, 0}, // CK_BBOOL
            { CKA_KEY_TYPE, NULL, 0},
			{ CKA_ID, NULL, 0},
			{ CKA_MODULUS, NULL, 0},
			{ CKA_PUBLIC_EXPONENT, NULL, 0},
			{ CKA_MODULUS_BITS, NULL, 0},
			{ CKA_EC_PARAMS, NULL, 0},
			{ CKA_EC_POINT, NULL, 0},
	};
	CK_ULONG public_attrs_size = sizeof (public_attrs) / sizeof (CK_ATTRIBUTE);

    debug_print("\nSearch for all certificates on the card");
	search_objects(objects, info, filter, 1, // XXX size = 1
		attrs, attrs_size, callback_certificates);


	/* do the same thing with private keys (collect handles based on the collected IDs) */
    debug_print("\nSearch for all private keys respective to the certificates");
	filter[0].pValue = &privateClass;
	// search for all and pair on the fly
	search_objects(objects, info, filter, 1,
		private_attrs, private_attrs_size, callback_private_keys);

    debug_print("\nSearch for all public keys respective to the certificates");
	filter[0].pValue = &publicClass;
	search_objects(objects, info, filter, 1,
		public_attrs, public_attrs_size, callback_public_keys);
}

static void clean_all_objects(test_certs_t *objects) {
	for (int i = 0; i < objects->count; i++) {
		free(objects->data[i].key_id);
		free(objects->data[i].id_str);
		free(objects->data[i].label);
		free(objects->data[i].mechs);
		X509_free(objects->data[i].x509);
		if (objects->data[i].key_type == CKK_RSA)
			RSA_free(objects->data[i].key.rsa);
		else
			EC_KEY_free(objects->data[i].key.ec);
	}
	free(objects->data);
}

static void readonly_tests(void **state) {

    token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	int used;
    debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (int i = 0; i < objects.count; i++) {
		used = 0;
		/* do the Sign&Verify and/or Encrypt&Decrypt */
		/* XXX some keys do not have appropriate flags, but we can use them */
		//if (objects.data[i].sign && objects.data[i].verify)
			for (int j = 0; j < objects.data[i].num_mechs; j++)
				used |= sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]), 32);

		//if (objects.data[i].encrypt && objects.data[i].decrypt)
			for (int j = 0; j < objects.data[i].num_mechs; j++)
				used |= encrypt_decrypt_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]));

		if (!used) {
			debug_print(" [ WARN %s ] Private key with unknown purpose T:%02X",
			objects.data[i].id_str, objects.data[i].key_type);
		}
	}

	/* print summary */
	printf("[KEY ID] [TYPE] [SIZE] [PUBLIC] [SIGN&VERIFY] [ENC&DECRYPT] [LABEL]\n");
	for (int i = 0; i < objects.count; i++) {
		printf("[%-6s] [%s] [%4d] [ %s ] [%s%s] [%s%s] [%s]\n",
			objects.data[i].id_str,
			objects.data[i].key_type == CKK_RSA ? "RSA " :
				objects.data[i].key_type == CKK_EC ? " EC " : " ?? ",
			objects.data[i].bits != -1 ? objects.data[i].bits : 0,
			objects.data[i].verify_public == 1 ? " ./ " : "    ",
			objects.data[i].sign ? "[./] " : "[  ] ",
			objects.data[i].verify ? " [./] " : " [  ] ",
			objects.data[i].encrypt ? "[./] " : "[  ] ",
			objects.data[i].decrypt ? " [./] " : " [  ] ",
			objects.data[i].label);
		for (int j = 0; j < objects.data[i].num_mechs; j++)
			printf("         [ %-18s ] [   %s    ] [   %s    ]\n",
				get_mechanism_name(objects.data[i].mechs[j].mech),
				objects.data[i].mechs[j].flags & VERIFY_SIGN ? "[./]" : "    ",
				objects.data[i].mechs[j].flags & VERIFY_DECRYPT ? "[./]" : "    ");
		printf("\n");
	}
	printf(" Public == Cert ----------^       ^  ^  ^       ^  ^  ^\n");
	printf(" Sign Attribute ------------------'  |  |       |  |  '---- Decrypt Attribute\n");
	printf(" Sign&Verify functionality ----------'  |       |  '------- Enc&Dec functionality\n");
	printf(" Verify Attribute ----------------------'       '---------- Encrypt functionaliy\n");

	clean_all_objects(&objects);
}

static void ec_sign_size_test(void **state) {

    token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

    debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (int i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type == CKK_EC)
			// for (int j = 0; j < objects.data[i].num_mechs; j++) // XXX single mechanism
			for (int l = 30; l < 35; l++)
				sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[0]), l);
	}

	clean_all_objects(&objects);
}

static void supported_mechanisms_test(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    CK_RV rv;
    CK_LONG mechanism_count;
    CK_MECHANISM_TYPE_PTR mechanism_list;
    CK_MECHANISM_INFO_PTR mechanism_info;

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

        mechanism_info = (CK_MECHANISM_INFO_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_INFO));

        for(int i=0; i< mechanism_count; i++) {
            CK_MECHANISM_TYPE mechanism_type = mechanism_list[i];
            rv = function_pointer->C_GetMechanismInfo(info->slot_id,
				mechanism_type, &mechanism_info[i]);

            if(rv != CKR_OK){
                continue;
            }
        }

		printf("[    MECHANISM    ] [ KEY SIZE ] [  FLAGS   ]\n");
		printf("[                 ] [ MIN][ MAX] [          ]\n");
        for(int i = 0; i < mechanism_count; i++) {
			printf("[%-17s] [%4lu][%4lu] [%10s]", get_mechanism_name(mechanism_list[i]),
				mechanism_info[i].ulMinKeySize, mechanism_info[i].ulMaxKeySize,
				get_mechanism_flag_name(mechanism_info[i].flags));
			for (CK_FLAGS j = 1; j <= CKF_EC_COMPRESS; j = j<<1)
				if ((mechanism_info[i].flags & j) != 0)
					printf(" %s", get_mechanism_flag_name(j));
			printf("\n");
		}
        free(mechanism_list);
        free(mechanism_info);
    }

    rv = function_pointer->C_Finalize(NULL_PTR);
    if(rv != CKR_OK){
        fail_msg("Could not finalize CRYPTOKI!\n");
    }
}

int main(int argc, char** argv) {

    char command, card_type[25];
    int args_count = 0;

	init_card_info();

    while ((command = getopt(argc, argv, "m:t:p:s:r")) != -1) {
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
            case 'p':
                card_info.pin = strdup(optarg);
                card_info.pin_length = strlen(optarg);
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
            cmocka_unit_test(supported_mechanisms_test),

			/* Regression test Sign&Verify with various data lengths */
            cmocka_unit_test_setup_teardown(ec_sign_size_test,
				clear_token_with_user_login_setup, after_test_cleanup),

			/* Complex readonly test of all objects on the card  */
            cmocka_unit_test_setup_teardown(readonly_tests,
				clear_token_with_user_login_setup, after_test_cleanup),
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

