#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/lorawan.h"

//#define DEBUG
#define KEY_SIZE 16
#define MSG_MAX 64

static void print_usage()
{
    char prog[] = "decoder";
    printf("usage: %s for lorawan messages", prog);
    printf("\n-b <band>                 us868, us915");
    printf("\n-a <string>               appskey if data message");
    printf("\n-n <string>               netwskey if macmd");
    printf("\n-m <string>               msg to be decoded");
    printf("\n-h                        print this page");
    printf("\n");
}

static void convert_to_hex(uint8_t *output, char *input, int len)
{
    int i;
    unsigned int val;
    for (i=0; i<len; i++) {
        sscanf(input + 2*i, "%02X", &val);
        output[i] = (uint8_t) val;
#ifdef DEBUF
        printf("0x%X ", output[i]);
#endif
    }

#ifdef DEBUF
    printf ("\n");
#endif
}

int main(int argc, char **argv)
{
    int i, ret;
    int band;
    int len = 0;
    uint8_t *msg= NULL;

    parse_key_t pkey;
    memset(&pkey, 0, sizeof(pkey));

    while ((i = getopt (argc, argv, "hn:a:m:b:")) != -1) {
		switch (i) {
        case 'h':
            print_usage();
            return 0;
            break;
        case 'n':
            if (strlen(optarg) == 2*KEY_SIZE) {
                pkey.nwkskey = malloc(KEY_SIZE);
                if (pkey.nwkskey == NULL) {
                    printf ("appskey memory allocation failed\n");
                    goto clean;
                }
                convert_to_hex(pkey.nwkskey, optarg, KEY_SIZE);
                pkey.flag.bits.nwkskey = 1;
            }
            else {
                printf ("Error : nwkskey wrong key size\n");
                goto clean;
            }
            break;
        case 'a':
            if (strlen(optarg) == 2*KEY_SIZE) {
                pkey.appskey = malloc(KEY_SIZE);
                if (pkey.appskey == NULL) {
                    printf ("appskey memory allocation failed\n");
                    goto clean;
                }
                convert_to_hex(pkey.appskey, optarg, KEY_SIZE);
                pkey.flag.bits.appskey = 1;
            }
            else {
                printf ("Error : appskey wrong key size\n");
                goto clean;
            }
            break;
        case 'm':
            if (strlen(optarg)%2 == 0) {
                len = strlen(optarg)/2;
                msg = malloc(len);
                if (msg == NULL) {
                    printf ("msg memory allocation failed\n");
                    goto clean;
                }
                convert_to_hex(msg, optarg, len);
            }
            else {
                printf ("Error : msg too long\n");
                goto clean;
            }
            break;
        case 'b':
            if((band = get_band(optarg)) < 0){
                printf("Band error\n");
                goto clean;
            }
            set_band(band);
            break;
        default:
            printf("PARAMETER ERROR\n");
            goto clean;
		}
	}

    if (len == 0 || (!pkey.flag.bits.appskey && !pkey.flag.bits.nwkskey)) {
        printf ("missing parameter\n");
        print_usage();
        return -1;
    }

    ret = parse_message(msg, len, &pkey);
    if(ret < 0){
        printf("DATA MESSAGE PARSE error(%d)\n", ret);
    }

clean: 
    if (msg) {
        free(msg);
    }
    
    if (pkey.nwkskey){
        free (pkey.nwkskey);
    }

    if (pkey.appskey){
        free (pkey.appskey);
    }
    return 0;
}

