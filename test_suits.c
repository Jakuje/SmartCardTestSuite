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


    rv = function_pointer->C_GetMechanismList(info->slot_id, NULL_PTR, &mechanism_count);
    assert_int_not_equal(mechanism_count,0);
    if ((rv == CKR_OK) && (mechanism_count > 0)) {
        mechanism_list = (CK_MECHANISM_TYPE_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE));
        rv = function_pointer->C_GetMechanismList(info->slot_id, mechanism_list, &mechanism_count);
        if (rv != CKR_OK) {
            free(mechanism_list);
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
//            cmocka_unit_test(is_ec_supported_test),
//            cmocka_unit_test_setup_teardown(initialize_token_with_user_pin_test, clear_token_without_login_setup, after_test_cleanup),
//            cmocka_unit_test_setup_teardown(change_user_pin_test, clear_token_with_user_login_setup, after_test_cleanup),
//            cmocka_unit_test_setup_teardown(create_hash_md5_short_message_test, clear_token_with_user_login_setup, after_test_cleanup),
//            cmocka_unit_test_setup_teardown(create_hash_md5_long_message_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(create_hash_sha1_short_message_test, clear_token_with_user_login_setup, after_test_cleanup),
            cmocka_unit_test_setup_teardown(create_hash_sha1_long_message_test, clear_token_with_user_login_setup, after_test_cleanup),

    };

    return cmocka_run_group_tests(tests_without_initialization, group_setup, group_teardown);

}