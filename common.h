#ifndef SMARTCARDTESTSUIT_COMMON_H
#define SMARTCARDTESTSUIT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "pkcs11.h"

#ifdef NDEBUG
    #define debug_print(fmt, ...) \
                do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
    #define debug_print(fmt, ...)
#endif

#define BUFFER_SIZE       4096
#define MAX_DIGEST          64
#define MD5_HASH_LENGTH     16
#define SHA1_HASH_LENGTH    20

#define SHORT_MESSAGE_TO_HASH "This is test message for digest.\n"
#define LONG_MESSAGE_TO_HASH_PATH "/home/mstrharsky/diplomka/resources/message_to_hash.txt"
//#define LONG_MESSAGE_TO_HASH_PATH "/home/mstrharsky/diplomka/resources/short.txt"

#define SHORT_MESSAGE_TO_SIGN "Simple message for signing & verifying.\n"
#define SHORT_MESSAGE_SIGNATURE "/home/mstrharsky/diplomka/resources/message_to_sign.signature"


typedef struct {
    CK_FLAGS flags;
} supported_mechanisms;

typedef struct {
    CK_FUNCTION_LIST_PTR function_pointer;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    supported_mechanisms supported;

} token_info;

#endif //SMARTCARDTESTSUIT_COMMON_H
