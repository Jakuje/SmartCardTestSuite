#ifndef SMARTCARDTESTSUIT_TEST_HELPERS_H
#define SMARTCARDTESTSUIT_TEST_HELPERS_H

#include "loader.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

char* library_path;

CK_BYTE* hex_string_to_byte_array(char* hex_string, CK_LONG *hex_array_length);

int clear_token();
int open_session(token_info_t *info);
int initialize_cryptoki(token_info_t *info);
int prepare_token(token_info_t *info);

int group_setup(void **state);
int group_teardown(void **state);

int after_test_cleanup(void **state);
int clear_token_with_user_login_setup(void **state);
int clear_token_without_login_setup(void **state);
int clear_token_with_user_login_and_import_keys_setup(void **state);
int init_token_with_default_pin(token_info_t *info);

int short_message_digest(const token_info_t *info, CK_MECHANISM *digest_mechanism, CK_BYTE *hash, CK_ULONG *hash_length);
int long_message_digest(const token_info_t *info, CK_MECHANISM *digest_mechanism, CK_BYTE *hash, CK_ULONG *hash_length);

int find_object_by_template(const token_info_t * info, CK_ATTRIBUTE *template, CK_OBJECT_HANDLE *object, CK_LONG attributes_count);
int read_whole_file(CK_ULONG *data_length, CK_BYTE **input_buffer, char *file_path);

#endif //SMARTCARDTESTSUIT_TEST_HELPERS_H
