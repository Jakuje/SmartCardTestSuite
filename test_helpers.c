#include "test_helpers.h"
#include "common.h"

int readonly = 0;

int open_session(token_info_t *info) {
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    rv = function_pointer->C_OpenSession(info->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
                                         &info->session_handle);

    if(rv != CKR_OK)
        return 1;

    debug_print("Session was successfully created");
    return 0;
}

int clear_token() {

    int error = 0;

    if (readonly)
        //skip();
        return 0;

    debug_print("Clearing token");

    if (card_info.type == PIV) {
        system("yubico-piv-tool -a verify-pin -P 4711 > /dev/null 2>&1");
        system("yubico-piv-tool -a verify-pin -P 4711 > /dev/null 2>&1");
        system("yubico-piv-tool -a verify-pin -P 4711 > /dev/null 2>&1");
        system("yubico-piv-tool -a verify-pin -P 4711 > /dev/null 2>&1");
        system("yubico-piv-tool -a change-puk -P 4711 -N 67567 > /dev/null 2>&1");
        system("yubico-piv-tool -a change-puk -P 4711 -N 67567 > /dev/null 2>&1");
        system("yubico-piv-tool -a change-puk -P 4711 -N 67567 > /dev/null 2>&1");
        system("yubico-piv-tool -a change-puk -P 4711 -N 67567 > /dev/null 2>&1");
        error |= system("yubico-piv-tool -a reset > /dev/null 2>&1");
    }

    if(card_info.type == PKCS15) {
        error |= system("pkcs15-init -ET > /dev/null 2>&1");
        error |= system("pkcs15-init -CT --no-so-pin > /dev/null 2>&1");
    }

    if(error) {
        fprintf(stderr,"Could not clear token!\n");
        return error;
    }

    return 0;
}

int import_keys() {

    int error;

	if (readonly)
        //skip();
        return 0;

    if(card_info.type == PIV) {
        debug_print("Importing private key");
        error = system("yubico-piv-tool -a import-key -s 9a -i ../resources/private_key.pem > /dev/null 2>&1");

        if (error) {
            fprintf(stderr, "Could not import private key!\n");
            return error;
        }

        debug_print("Importing public key and certificate");

        error = system("yubico-piv-tool -a import-certificate -s 9a -K DER -i ../resources/cert.der > /dev/null 2>&1");

        if (error) {
            fprintf(stderr, "Could not import public key!\n");
            return error;
        }
    }

    if(card_info.type == PKCS15) {
        debug_print("Importing private key");
        error = system(
                "pkcs11-tool -l --pin 12345 --write-object ../resources/private_key.key --type privkey --id a1 --label \"My Private Key\" --usage-sign --usage-decrypt > /dev/null 2>&1");

        if (error) {
            fprintf(stderr, "Could not import private key!\n");
            return error;
        }

        debug_print("Importing public key");
        error = system(
                "pkcs11-tool -l --pin 12345 --write-object ../resources/public_key.key --type pubkey --id a1 --label \"My Public Key\" --usage-sign --usage-decrypt > /dev/null 2>&1");

        if (error) {
            fprintf(stderr, "Could not import public key!\n");
            return error;
        }

        debug_print("Importing certificate");
        error = system(
                "pkcs11-tool -l --pin 12345 --write-object ../resources/cert.der --type cert --id a1 > /dev/null 2>&1");

        if (error) {
            fprintf(stderr, "Could not import public key!\n");
            return error;
        }
    }

    return 0;
}

int init_token_with_default_pin(token_info_t *info) {

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    if (readonly)
        //skip();
        return 0;

    debug_print("Logging in as SO user");
    rv = function_pointer->C_Login(info->session_handle, CKU_SO, card_info.so_pin, card_info.so_pin_length);
    if (rv != CKR_OK) {
        fprintf(stderr,"Could not log in to token as SO user!\n");
        return 1;
    }

    debug_print("Initialization of user PIN. Session handle is: %d. New PIN is: %s", info->session_handle, card_info.pin);
    rv = function_pointer->C_InitPIN(info->session_handle, card_info.pin, card_info.pin_length);
    if (rv != CKR_OK) {
        fprintf(stderr,"Could not init user PIN!\n");
        return 1;
    }

    debug_print("Logging out SO user");
    rv = function_pointer->C_Logout(info->session_handle);
    if (rv != CKR_OK) {
        fprintf(stderr,"Could not log out SO user!\n");
        return 1;
    }

    return 0;
}

int group_setup(void **state)
{

    if(clear_token())
        fail_msg("Could not clear token!\n");

    token_info_t * info = malloc(sizeof(token_info_t));

    assert_non_null(info);

    if (load_pkcs11_module(info, library_path)) {
        free(info);
        fail_msg("Could not load module!\n");
    }

    *state = info;
    return 0;
}

int group_teardown(void **state) {

    debug_print("Clearing state after group tests!");
    token_info_t *info = (token_info_t *) *state;
    if(info && info->function_pointer)
        info->function_pointer->C_Finalize(NULL_PTR);

    free(info);
    free(library_path);

    clear_card_info();
    close_pkcs11_module();

    return 0;
}

int clear_token_without_login_setup(void **state) {

    token_info_t *info = (token_info_t *) *state;

    if(clear_token())
        fail_msg("Could not clear token!\n");

    if(initialize_cryptoki(info)) {
        fail_msg("CRYPTOKI couldn't be initialized\n");
    }

    if(open_session(info))
        fail_msg("Could not open session to token!\n");

    return 0;
}

int clear_token_with_user_login_setup(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    if(prepare_token(info))
        fail_msg("Could not prepare token.\n");


    debug_print("Logging in to the token!");
    rv = function_pointer->C_Login(info->session_handle, CKU_USER, card_info.pin, card_info.pin_length);

    if(rv != CKR_OK)
        fail_msg("Could not login to token with user PIN '%s'\n", card_info.pin);

    return 0;
}

int clear_token_with_user_login_and_import_keys_setup(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    if(prepare_token(info))
        fail_msg("Could not prepare token.\n");

    if(import_keys())
        fail_msg("Could not import keys to token!\n");

    /* Must close sessions and finalize CRYPTOKI and initialize it again because otherwise imported keys won't be found */
    debug_print("Closing all sessions");
    function_pointer->C_CloseAllSessions(info->slot_id);
    function_pointer->C_Finalize(NULL_PTR);

    if(initialize_cryptoki(info)) {
        fail_msg("CRYPTOKI couldn't be initialized\n");
    }

    if(open_session(info)) {
        fail_msg("Could not open session to token!\n");
    }

    rv = function_pointer->C_Login(info->session_handle, CKU_USER, card_info.pin, card_info.pin_length);

    if(rv != CKR_OK)
        fail_msg("Could not login to token with user PIN '%s'\n", card_info.pin);

    return 0;
}

int prepare_token(token_info_t *info) {
    if(clear_token()) {
        debug_print("Could not clear token!");
        return 1;
    }

    if(initialize_cryptoki(info)) {
        debug_print("CRYPTOKI couldn't be initialized");
        return 1;
    }

    if(open_session(info)) {
        debug_print("Could not open session to token!");
        return 1;
    }

    if(card_info.type == PKCS15) {
        debug_print("Init token with default PIN and log in as user");
        if (init_token_with_default_pin(info)) {
            debug_print("Could not initialize token with default user PIN");
            return 1;
        }
    }

    return 0;
}

int after_test_cleanup(void **state) {

    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    debug_print("Logging out from token");
    function_pointer->C_Logout(info->session_handle);

    info->session_handle = 0;
    debug_print("Closing all sessions");
    function_pointer->C_CloseAllSessions(info->slot_id);
    debug_print("Finalize CRYPTOKI");
    function_pointer->C_Finalize(NULL_PTR);

//    debug_print("Clearing token");
//    if(clear_token())
//        fail_msg("Could not clear token!\n");
}

CK_BYTE* hex_string_to_byte_array(char* hex_string, CK_LONG *hex_array_length) {

    int length = strlen(hex_string) / 2;
    CK_BYTE *hex_array = (CK_BYTE*) malloc(length * sizeof(CK_BYTE));
    if(!hex_array)
        return NULL;

    for(int i = 0; i < length; i++) {
        sscanf(hex_string+2*i, "%2X", &hex_array[i]);
    }

    if(hex_array_length)
        *hex_array_length = length;

    return hex_array;
}

int short_message_digest(const token_info_t *info, CK_MECHANISM *digest_mechanism,
                         CK_BYTE *hash, CK_ULONG *hash_length) {
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;


    debug_print("Creating hash of message '%s'", SHORT_MESSAGE_TO_HASH);

    rv = function_pointer->C_DigestInit(info->session_handle, digest_mechanism);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not init digest algorithm.\n");
        return 1;
    }

    rv = function_pointer->C_Digest(info->session_handle, SHORT_MESSAGE_TO_HASH, strlen(SHORT_MESSAGE_TO_HASH), hash, hash_length);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not create hash of message.\n");
        return 1;
    }

    debug_print("Hash of message '%s'\n\t has length %d", SHORT_MESSAGE_TO_HASH, (*hash_length));
    return 0;
}

int long_message_digest(const token_info_t *info, CK_MECHANISM *digest_mechanism, CK_BYTE *hash, CK_ULONG *hash_length) {

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;
    FILE *fs;

    CK_ULONG data_length = BUFFER_SIZE;
    char input_buffer[BUFFER_SIZE];

    /* Open the input file */
    if ((fs = fopen(LONG_MESSAGE_TO_HASH_PATH, "r")) == NULL) {
        fprintf(stderr, "Could not open file '%s' for reading\n", LONG_MESSAGE_TO_HASH_PATH);
        return 1;
    }

    debug_print("Creating hash of message in file '%s'", LONG_MESSAGE_TO_HASH_PATH);

    rv = function_pointer->C_DigestInit(info->session_handle, digest_mechanism);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not init digest algorithm.\n");
        fclose(fs);
        return 1;
    }


    /* Read in the data and create digest of this portion */
    while (!feof(fs) && (data_length = fread(input_buffer, 1, BUFFER_SIZE, fs)) > 0) {
        rv = function_pointer->C_DigestUpdate(info->session_handle, (CK_BYTE_PTR) input_buffer, data_length);

        if (rv  != CKR_OK) {
            fprintf(stderr, "Error while calling DigestUpdate function\n");
            fclose(fs);
            return 1;
        }
    }

    /* Get complete digest */
    rv = function_pointer->C_DigestFinal(info->session_handle, hash, hash_length);

    if (rv != CKR_OK) {
        fprintf(stderr, "Could not finish digest!\n");
        fclose(fs);
        return 1;
    }

    fclose(fs);
    debug_print("Hash of message in file '%s'\n\t has length %d", LONG_MESSAGE_TO_HASH_PATH, (*hash_length));
    return 0;
}

int initialize_cryptoki(token_info_t *info) {

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    rv = function_pointer->C_Initialize(NULL_PTR);
    if(rv != CKR_OK){
        fprintf(stderr,"Could not initialize CRYPTOKI!\n");
        return 1;
    }

    if(get_slot_with_card(info)) {
        function_pointer->C_Finalize(NULL_PTR);
        fprintf(stderr,"There is no card present in reader.\n");
        return 1;
    }

    return 0;
}

int find_object_by_template(const token_info_t * info, CK_ATTRIBUTE *template, CK_OBJECT_HANDLE *object, CK_LONG attributes_count) {
    CK_RV rv;
    CK_ULONG object_count;

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    rv = function_pointer->C_FindObjectsInit(info->session_handle, template, attributes_count);

    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjectsInit: rv = 0x%.8X\n", rv);
        return 1;
    }

    rv = function_pointer->C_FindObjects(info->session_handle, object, attributes_count, &object_count);

    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjects: rv = 0x%.8X\n", rv);
        return 1;
    }

    rv = function_pointer->C_FindObjectsFinal(info->session_handle);

    if (rv != CKR_OK) {
        fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8X\n", rv);
        return 1;
    }

    return (*object) == CK_INVALID_HANDLE;
}

int read_whole_file(CK_ULONG *data_length, CK_BYTE **input_buffer, char *file_path) {

    FILE *fs;

    /* Open the input file */
    if ((fs = fopen(file_path, "r")) == NULL) {
        fprintf(stderr, "Could not open file '%s' for reading\n", file_path);
        return 1;
    }


    fseek(fs, 0, SEEK_END);
    (*data_length) = ftell(fs);
    fseek(fs, 0, SEEK_SET);

    *input_buffer = (char*) malloc(*data_length);
    fread(*input_buffer, *data_length, 1, fs);
    fclose(fs);

    return 0;
}

int write_whole_file(CK_ULONG *data_length, CK_BYTE *input_buffer, char *file_path) {

    FILE *fs;

    /* Open the output file */
    if ((fs = fopen(file_path, "w")) == NULL) {
        fprintf(stderr, "Could not open file '%s' for writing\n", file_path);
        return 1;
    }

    fwrite(input_buffer, *data_length, 1, fs);
    fclose(fs);

    return 0;
}

const char *get_mechanism_name(int mech_id)
{
	char *out = malloc(11);
	switch (mech_id) {
		case CKM_RSA_PKCS:
			return "CKM_RSA_PKCS";
		case CKM_ECDSA:
			return "CKM_ECDSA";
		case CKM_ECDSA_SHA1:
			return "CKM_ECDSA_SHA1";
		case CKM_ECDH1_DERIVE:
			return "CKM_ECDH1_DERIVE";
		default:
			sprintf(out, "0x%.8X", mech_id);
			return out;
	}
}

const char *get_mechanism_flag_name(int mech_id)
{
	char *out = malloc(11);
	switch (mech_id) {
		case CKF_HW:
			return "CKF_HW";
		case CKF_ENCRYPT:
			return "CKF_ENCRYPT";
		case CKF_DECRYPT:
			return "CKF_DECRYPT";
		case CKF_DIGEST:
			return "CKF_DIGEST";
		case CKF_SIGN:
			return "CKF_SIGN";
		case CKF_SIGN_RECOVER:
			return "CKF_SIGN_RECOVER";
		case CKF_VERIFY:
			return "CKF_VERIFY";
		case CKF_VERIFY_RECOVER:
			return "CKF_VERIFY_RECOVER";
		case CKF_GENERATE:
			return "CKF_GENERATE";
		case CKF_GENERATE_KEY_PAIR:
			return "CKF_GENERATE_KEY_PAIR";
		case CKF_WRAP:
			return "CKF_WRAP";
		case CKF_UNWRAP:
			return "CKF_UNWRAP";
		case CKF_DERIVE:
			return "CKF_DERIVE";
		case CKF_EC_F_P:
			return "CKF_EC_F_P";
		case CKF_EC_F_2M:
			return "CKF_EC_F_2M";
		case CKF_EC_NAMEDCURVE:
			return "CKF_EC_NAMEDCURVE";
		case CKF_EC_UNCOMPRESS:
			return "CKF_EC_UNCOMPRESS";
		case CKF_EC_COMPRESS:
			return "CKF_EC_COMPRESS";
		default:
			sprintf(out, "0x%.8X", mech_id);
			return out;
	}
}
