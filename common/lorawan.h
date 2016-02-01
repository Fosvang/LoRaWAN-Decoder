#ifndef __LORAWAN_H
#define __LORAWAN_H

#include <stdint.h>
#include "defines.h"

#if defined(__CC_ARM) || defined(__GNUC__)
    #define PACKED  __attribute__( ( __packed__ ) )
#else
    #warning Not supported compiler type
#endif

#define LORA_KEY_LEN                  (16)
#define LORA_MIC_LEN                  (4)
#define LORA_BAND_MAX_NUM             (5)

#define LORA_DR(sf, bw)               ( (uint8_t)( (sf) | ((bw)<<4) ))
#define LORA_DR_RFU                   (0xFF)
#define LORA_POW_RFU                  (-128)

/* Channel Mask Control */
#define LORA_CMC(from, to)            ( (uint8_t)( (from) | ((to)<<8) ))
#define LORA_CMC_RFU                  (0xFFFF)
#define LORA_CMC_ALL_ON               (0xFFFE)
#define LORA_CMC_ALL_125KHZ_ON        (0xFFFD)
#define LORA_CMC_ALL_125KHZ_OFF       (0xFFFC)

typedef union{
    uint8_t         data;
    struct{
        uint8_t     major           : 2;
        uint8_t     rfu             : 3;
        uint8_t     mtype           : 3;
    } bits;
}PACKED mhdr_t;

typedef union{
    uint8_t         data;
    struct{
        uint8_t     foptslen        : 4;
        uint8_t     bit5            : 1;  /* fpending for dp and classB for up*/
        uint8_t     ack             : 1;  
        uint8_t     adrackreq       : 1;
        uint8_t     adr             : 1;
    } bits;
}PACKED fctrl_t;

typedef union{
    uint32_t        data;
    uint8_t         buf[4];
    struct{
        uint32_t    nwkid          : 7;
        uint32_t    nwkaddr        : 25;
    }bits;
}PACKED devaddr_t;

typedef union{
    uint32_t        data;
    uint8_t         buf[4];
}PACKED mic_t;

typedef struct{
    mhdr_t          mhdr;
    uint32_t        devaddr;
    fctrl_t         fctrl;
    uint16_t        fcnt;
    uint8_t         *fopts;
    uint8_t         fport;
    mic_t           mic;
} lora_t;

typedef struct{
    uint8_t         *aeskey;
    uint8_t         *in;
    uint16_t        len;
    devaddr_t       devaddr;
    lora_link_t     link;
    uint32_t        fcnt32;
} skey_t;

typedef struct{
    union{
        uint8_t     data;
        struct{
            uint8_t nwkskey         : 1;
            uint8_t appskey         : 1;
        }bits;
    }flag;
    uint8_t         *nwkskey;
    uint8_t         *appskey;
} parse_key_t;

typedef struct{
    uint8_t         buf[256];
    int16_t         len;
} buffer_t;

typedef union{
    uint8_t         data;
    struct{
        uint8_t     sf              : 4;
        uint8_t     bw              : 2;
    }bits;
} dr_t;

union {
    uint8_t         data;
    struct{
        int8_t      margin           :6;
    }bits;
} dev_sta_margin;


inline const char *maccmd_str(uint8_t mtype, uint8_t cmd)
{
    if( (mtype == LORA_MTYPE_MSG_UP) || (mtype == LORA_MTYPE_CMSG_UP) ){
        switch(cmd){
            // Class A
        case LORA_MCMD_LCHK_REQ:
            return "LinkCheckReq";
        case LORA_MCMD_LADR_ANS:
            return "LinkADRAns";
        case LORA_MCMD_DCAP_ANS:
            return "DutyCycleAns";
        case LORA_MCMD_DN2P_ANS:
            return "RXParamSetupAns";
        case LORA_MCMD_DEVS_ANS:
            return "DevStatusAns";
        case LORA_MCMD_SNCH_ANS:
            return "NewChannelAns";
        case LORA_MCMD_RXTS_ANS:
            return "RXTimingSetupAns";
            //Class B
        case LORA_MCMD_PING_IND:
            break;
        case LORA_MCMD_PING_ANS:
            break;
        case LORA_MCMD_BCNI_REQ:
            break;
        }
    }else if( (mtype == LORA_MTYPE_MSG_DOWN) || (mtype == LORA_MTYPE_CMSG_DOWN) ){
        switch(cmd){
            // Class A
        case LORA_MCMD_LCHK_ANS:
            return "LinkCheckAns";
        case LORA_MCMD_LADR_REQ:
            return "LinkADRReq";
        case LORA_MCMD_DCAP_REQ:
            return "DutyCycleReq";
        case LORA_MCMD_DN2P_REQ:
            return "RXParamSetupReq";
        case LORA_MCMD_DEVS_REQ:
            return "DevStatusReq";
        case LORA_MCMD_SNCH_REQ:
            return "NewChannelReq";
        case LORA_MCMD_RXTS_REQ:
            return "RXTimingSetupReq";
            //Class B
        case LORA_MCMD_PING_SET:
            break;
        case LORA_MCMD_BCNI_ANS:
            break;
        }
    }
    return NULL;
}

/*
 * Parse and validate MSG
 */
int parse_message(uint8_t *buf, int len, parse_key_t *pkey);
int parse_maccmd(uint8_t mac_header, uint8_t *opts, int len);

/*
 * Band Definition
 */
int get_band(char *band);
int set_band(lora_band_t band);

/*
 * Get Output Buffer
 */
int get_dmsg(uint8_t *buf, int max_len);

/*
 * Crypto functions 
 */
int  encrypt(uint8_t *out, skey_t *key);
void calculate_mic(mic_t* mic, skey_t *key);

#endif // __LORAWAN_H

