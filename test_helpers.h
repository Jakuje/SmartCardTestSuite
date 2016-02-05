#ifndef SMARTCARDTESTSUIT_TEST_HELPERS_H
#define SMARTCARDTESTSUIT_TEST_HELPERS_H

#include "common.h"
#include "loader.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

char* library_path;

CK_BYTE* hex_string_to_byte_array(char* hex_string);

int initialize_cryptoki(token_info *info);
int clear_token();
int open_session(token_info *info);

int group_setup(void **state);
int group_teardown(void **state);

int after_test_cleanup(void **state);
int clear_token_with_user_login_setup(void **state);
int clear_token_without_login_setup(void **state);
int init_token_with_default_pin(token_info *info);
int short_message_digest(const token_info *info, CK_MECHANISM *digest_mechanism, CK_BYTE *hash, CK_ULONG *hash_length);
int long_message_digest(const token_info *info, CK_MECHANISM *digest_mechanism, CK_BYTE *hash, CK_ULONG *hash_length);

#endif //SMARTCARDTESTSUIT_TEST_HELPERS_H
