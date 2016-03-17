#include "common.h"

void display_usage() {
    fprintf(stdout,
            " usage:\n"
                    "    ./SmartCardTestSuite -m module_path -t [PKCS15, PIV] [-s so_pin]\n"
                    "       -m  module_path:   path to tested module (e.g. /usr/lib64/opensc-pkcs11.so)\n"
                    "       -s  so_pin:        Security Officer PIN to token\n"
                    "       -t  card_type:     card type, supported are PKCS15 and PIV\n"
                    "\n");
}

int set_card_info() {

    CK_UTF8CHAR pin[10], change_pin[10];
    CK_BYTE id[] = { 0 };

    switch(card_info.type) {
        case PKCS15:
            strcpy(pin, "12345");
            strcpy(change_pin, "54321");
            id[0] = 0xa1;
            break;
        case PIV:
            strcpy(pin, "123456");
            strcpy(change_pin, "654321");
            id[0] = 0x01;
            break;
        default:
            return 1;
    }

    card_info.pin_length = strlen(pin);
    card_info.id_length = sizeof(id);

    card_info.pin = strdup(pin);
    card_info.change_pin = strdup(change_pin);
    card_info.id[0] = id[0];

    if(!card_info.pin || !card_info.change_pin)
        return 1;

    return 0;
}

void clear_card_info() {
    if(card_info.pin)
        free(card_info.pin);

    if(card_info.change_pin)
        free(card_info.change_pin);

    if(card_info.so_pin)
        free(card_info.so_pin);
}