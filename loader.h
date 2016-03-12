#ifndef SMARTCARDTESTSUIT_LOADER_H
#define SMARTCARDTESTSUIT_LOADER_H

#include <dlfcn.h>
#include "common.h"

#define ENCRYPT            0x00000001
#define DECRYPT            0x00000002
#define DIGEST_MD5         0x00000004
#define DIGEST_SHA1        0x00000008
#define SIGN               0x00000010
#define VERIFY             0x00000020
#define GENERATE           0x00000040
#define GENERATE_KEY_PAIR  0x00000080
#define EC_SUPPORT         0x00000100

#define BIT_SET(a,b) ((a) |= (b))
#define BIT_CHECK(a,b) ((a) & (b))

#define SET_ENCRYPT(a) (BIT_SET((a), ENCRYPT))
#define SET_DECRYPT(a) (BIT_SET((a), DECRYPT))
#define SET_DIGEST_MD5(a) (BIT_SET((a), DIGEST_MD5))
#define SET_DIGEST_SHA1(a) (BIT_SET((a), DIGEST_SHA1))
#define SET_SIGN(a) (BIT_SET((a), SIGN))
#define SET_VERIFY(a) (BIT_SET((a), VERIFY))
#define SET_GENERATE(a) (BIT_SET((a), GENERATE))
#define SET_GENERATE_KEY_PAIR(a) (BIT_SET((a), GENERATE_KEY_PAIR))
#define SET_EC_SUPPORT(a) (BIT_SET((a), EC_SUPPORT))

#define CHECK_ENCRYPT(a) (BIT_CHECK((a), ENCRYPT))
#define CHECK_DECRYPT(a) (BIT_CHECK((a), DECRYPT))
#define CHECK_DIGEST_MD5(a) (BIT_CHECK((a), DIGEST_MD5))
#define CHECK_DIGEST_SHA1(a) (BIT_CHECK((a), DIGEST_SHA1))
#define CHECK_SIGN(a) (BIT_CHECK((a), SIGN))
#define CHECK_VERIFY(a) (BIT_CHECK((a), VERIFY))
#define CHECK_GENERATE(a) (BIT_CHECK((a), GENERATE))
#define CHECK_GENERATE_KEY_PAIR(a) (BIT_CHECK((a), GENERATE_KEY_PAIR))
#define CHECK_EC_SUPPORT(a) (BIT_CHECK((a), EC_SUPPORT))

static void *pkcs11_so;

void get_supported_mechanisms(supported_mechanisms_t *supported, CK_MECHANISM_INFO mechanism_info,
                              CK_MECHANISM_TYPE mechanism_type);
int load_pkcs11_module(token_info_t * info, const char* path_to_pkcs11_library);
int get_slot_with_card(token_info_t * info);
void close_pkcs11_module();


#endif //SMARTCARDTESTSUIT_LOADER_H
