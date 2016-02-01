#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "lorawan.h"
#include "aes.h"
#include "cmac.h"
#include "print.h"

#define LORA_FLAG_BUF_OK                  (1<<0)

lora_band_t band = LORA_BAND_EU868;

uint32_t flag = 0;
buffer_t lora_buf;

static int payload_len, payload_index;
static int port;

typedef int (*mtype_func_p) (uint8_t *buf, int len, parse_key_t *pkey);

const uint8_t dr_tab[][16] = {
    /* EU868 */
    {
        LORA_DR(SF12, BW125),    // DR0
        LORA_DR(SF11, BW125),    // DR1
        LORA_DR(SF10, BW125),    // DR2
        LORA_DR(SF9, BW125),     // DR3
        LORA_DR(SF8, BW125),     // DR4
        LORA_DR(SF7, BW125),     // DR5
        LORA_DR(SF7, BW250),     // DR7
        LORA_DR(FSK, BW125),     // DR8
        LORA_DR_RFU,             // DR9
        LORA_DR_RFU,             // DR10
        LORA_DR_RFU,             // DR11
        LORA_DR_RFU,             // DR12
        LORA_DR_RFU,             // DR13
        LORA_DR_RFU,             // DR14
        LORA_DR_RFU,             // DR15
    },
    /* US915 */
    {
        LORA_DR(SF10, BW125),    // DR0
        LORA_DR(SF9, BW125),     // DR1
        LORA_DR(SF8, BW125),     // DR2
        LORA_DR(SF7, BW125),     // DR3
        LORA_DR(SF8, BW500),     // DR4
        LORA_DR_RFU,             // DR5
        LORA_DR_RFU,             // DR6
        LORA_DR_RFU,             // DR7
        LORA_DR(SF12, BW500),    // DR8
        LORA_DR(SF11, BW500),    // DR9
        LORA_DR(SF10, BW500),    // DR10
        LORA_DR(SF9, BW500),     // DR11
        LORA_DR(SF8, BW500),     // DR12
        LORA_DR(SF7, BW500),     // DR13
        LORA_DR_RFU,             // DR14
        LORA_DR_RFU,             // DR15
    },
};

const int8_t pow_tab[][16] = {
    /* EU868 */
    {
        20,
        14,
        11,
        8,
        5,
        2,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
    },
    /* US915 */
    {
        30,
        28,
        26,
        24,
        22,
        20,
        18,
        16,
        14,
        12,
        10,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
        LORA_POW_RFU,
    },
};

const uint16_t chmaskcntl_tab[][8]={
    {
        LORA_CMC(0, 15),
        LORA_CMC_RFU,
        LORA_CMC_RFU,
        LORA_CMC_RFU,
        LORA_CMC_RFU,
        LORA_CMC_RFU,
        LORA_CMC_ALL_ON,
        LORA_CMC_RFU,
    },
    {
        LORA_CMC(0, 15),
        LORA_CMC(16, 31),
        LORA_CMC(32, 47),
        LORA_CMC(48, 63),
        LORA_CMC(64, 71),
        LORA_CMC_RFU,
        LORA_CMC_ALL_125KHZ_ON,
        LORA_CMC_ALL_125KHZ_OFF,
    }
};

/*
 * Log Function
 */
static void log_data(uint8_t *buf, int len)
{
    int i;

    uint8_t * str = malloc(len+1);
    str[len] = '\0';

    printf("DATA(HEX): ");
    puthbuf(buf, len);
    printf("\n");
    for(i=0; i<len; i++){
        str[i] = buf[i];
        if(buf[i]<' ' || buf[i]>'~'){
            break;
        }
    }
    if(i==len){
        printf("DATA(STR): %s\n", str);
    }
    free(str);
}

/*
 * Print No Payload
 */
void no_payload(void)
{
    printf("No MAC command payload\n");
}

/*
 *Mic Calculation
 */ 
uint8_t *write_dw(uint8_t *output, uint32_t input)
{
	uint8_t* ptr = output;

	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input), input >>= 8;
	*(ptr++) = (uint8_t)(input);

	return ptr;
}

void calculate_mic(mic_t* mic, skey_t *key)
{
    uint8_t b0[LORA_KEY_LEN];
    memset(b0, 0 , LORA_KEY_LEN);
    b0[0] = 0x49;
    b0[5] = key->link;

    write_dw(b0+6, key->devaddr.data);
    write_dw(b0+10, key->fcnt32);
    b0[15] = (uint8_t)key->len;

	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, b0, LORA_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LORA_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LORA_MIC_LEN);
}

/*
 * Encrypt/Decrypt calculation
 */
void block_xor(uint8_t const l[], uint8_t const r[], uint8_t out[], uint16_t bytes)
{
	uint8_t const* lptr = l;
	uint8_t const* rptr = r;
	uint8_t* optr = out;
	uint8_t const* const end = out + bytes;

	for (;optr < end; lptr++, rptr++, optr++)
		*optr = *lptr ^ *rptr;
}

int encrypt(uint8_t *out, skey_t *key)
{
    if (key->len == 0)
		return -1;

	uint8_t A[LORA_KEY_LEN];

	uint16_t const over_hang_bytes = key->len%LORA_KEY_LEN;
    int blocks = key->len/LORA_KEY_LEN + 1;

	memset(A, 0, LORA_KEY_LEN);

	A[0] = 0x01; //encryption flags
	A[5] = key->link;

	write_dw(A+6, key->devaddr.data);
	write_dw(A+10, key->fcnt32);

	uint8_t const* blockInput = key->in;
	uint8_t* blockOutput = out;
	uint16_t i;
	for(i = 1; i <= blocks; i++, blockInput += LORA_KEY_LEN, blockOutput += LORA_KEY_LEN){
		A[15] = (uint8_t)(i);

		aes_context aesContext;
		aes_set_key(key->aeskey, LORA_KEY_LEN, &aesContext);

		uint8_t S[LORA_KEY_LEN];
		aes_encrypt(A, S, &aesContext);

		uint16_t bytes_to_encrypt;
		if ((i < blocks) || (over_hang_bytes == 0))
			bytes_to_encrypt = LORA_KEY_LEN;
		else
			bytes_to_encrypt = over_hang_bytes;

		block_xor(S, blockInput, blockOutput, bytes_to_encrypt);
	}
	return key->len;
}

/*
 *  Parsing Joing Request Message
 */
static int mtype_join_request(uint8_t *msg, int len, parse_key_t *pkey) 
{
    printf ("JoinReq: Not Implemented\n");
    return 0;
}

/*
 *  Parsing Joing Answer Message
 */
static int mtype_join_answer(uint8_t *msg, int len, parse_key_t *pkey) 
{
    printf ("JoinAns: Not Implemented\n");
    return 0;
}

/*
 * Validate MIC value
 */
static int validate_mic(mic_t *calc_mic, skey_t *key, parse_key_t *pkey, uint8_t *msg, int len)
{
    mic_t pkt_mic;
    fctrl_t fct;

    // extract mic from payload
    memcpy(pkt_mic.buf, msg+len-4, 4);

    // calculate new mic
    key->aeskey = pkey->nwkskey;
    key->in = msg;
    key->len = len-4;
    memcpy(key->devaddr.buf, msg+LORA_DATA_OFF_DEVADDR, 4);
    key->fcnt32 = ((uint32_t)msg[LORA_DATA_OFF_FCNT+1]<<8) + msg[LORA_DATA_OFF_FCNT];
    calculate_mic(calc_mic, key);

    if(calc_mic->data != pkt_mic.data) {
        return LORA_ERR_MIC;
    }

    printf("VALID MIC %02X %02X %02X %02X\n", pkt_mic.buf[0], pkt_mic.buf[1], pkt_mic.buf[2], pkt_mic.buf[3]);
    printf("DEVADDR   %02X:%02X:%02X:%02X\n", key->devaddr.buf[3], key->devaddr.buf[2], key->devaddr.buf[1], key->devaddr.buf[0]);

    fct.data = msg[LORA_DATA_OFF_FCTRL];
    printf("ADR       %d\n", fct.bits.adr);
    printf("ADRACKREQ %d\n", fct.bits.adrackreq);
    printf("ACK       %d\n", fct.bits.ack);
    return LORA_OK;
}

/*
 *  Parsing Upload Message
 */
static int mtype_upload_msg(uint8_t *msg, int len, parse_key_t *pkey) 
{
    uint8_t out[255];

    mic_t calc_mic;
    fctrl_t fct;

    skey_t key;
    memset(&key, 0, sizeof(key));
    key.link = LORA_UPLINK;
    
    int ret;
    ret = validate_mic(&calc_mic, &key, pkey, msg, len);
    if (ret != LORA_OK) {
        printf("INVALID MIC\n");
        return ret;
    }

    fct.data = msg[LORA_DATA_OFF_FCTRL];
    if(fct.bits.bit5){
        printf("Class B\n");
    }

    if(len > (8 + 4 + fct.bits.foptslen)){
        /* Message Decrypt */
        port = msg[LORA_DATA_OFF_FOPTS + fct.bits.foptslen];
        if (port == 0) {
            key.aeskey = pkey->nwkskey;
        }
        else {
            key.aeskey = pkey->appskey;
        }

        payload_index = LORA_DATA_OFF_FOPTS + fct.bits.foptslen + 1;
        payload_len  = len - 4 - payload_index;
        key.in = msg + payload_index;
        key.len = payload_len;
        payload_len = encrypt(out, &key);

        if (payload_len <= 0) {
            return LORA_ERR_DECRYPT;
        }

        /* copy decrypted payload to lora_buf */
        memcpy(lora_buf.buf, msg, payload_index);                  // payload_index equals length of MHDR+FHDR+FPOR
        memcpy(lora_buf.buf + payload_index, out, payload_len);    // payload
        memcpy(lora_buf.buf + len - 4, calc_mic.buf, 4);           // mic
        lora_buf.len = len;
    }
    else {
        port = -1;
        printf("No FRMPayload Header\n");
    }

    if(port >= 0) {
        printf("PORT      %d\n", port);
    }
    else {
        printf("PORT      NONE\n");
    }
    printf("FCNT      %d [0x%X]\n", key.fcnt32, key.fcnt32);
    return LORA_OK;
}

/*
 *  Parsing Confirmed Upload Message
 */
static int mtype_confirmed_upload_msg(uint8_t *buf, int len, parse_key_t *pkey)
{
    return mtype_upload_msg(buf, len, pkey); 
}

/*
 *  Parsing Upload Message
 */
static int mtype_download_msg(uint8_t *msg, int len, parse_key_t *pkey)
{
    mic_t calc_mic;
    fctrl_t fct;

    skey_t key;
    memset(&key, 0, sizeof(key));
    key.link = LORA_DOWNLINK;

    int ret;
    ret = validate_mic(&calc_mic, &key, pkey, msg, len);
    if (ret != LORA_OK) {
        printf("INVALID MIC\n");
        return ret;
    }

    fct.data = msg[LORA_DATA_OFF_FCTRL];
    if(fct.bits.bit5) {
        printf("FPENDING  ON\n");
    }

    if (len > (8 + 4 + fct.bits.foptslen)) {
        // Message Decrypt
        port = msg[LORA_DATA_OFF_FOPTS + fct.bits.foptslen];
        if(port == 0){
            key.aeskey = pkey->nwkskey;
        }else{
            key.aeskey = pkey->appskey;
        }

        payload_index = LORA_DATA_OFF_FOPTS + fct.bits.foptslen + 1;
        payload_len  = len - 4 - payload_index;
        key.in = msg + payload_index;
        key.len = payload_len;
        uint8_t *out = malloc(key.len);
        payload_len = encrypt(out, &key);
        if(payload_len<=0){
            free(out);
            return LORA_ERR_DECRYPT;
        }

        /** copy decrypted payload to lora_buf */
        memcpy(lora_buf.buf, msg, payload_index);                   // until port, payload_index equals length of MHDR+FHDR+FPOR
        memcpy(lora_buf.buf + payload_index, out, payload_len);     // payload
        memcpy(lora_buf.buf + len - 4, calc_mic.buf, 4);            // mic
        lora_buf.len = len;
        free(out);
    }
    else {
        port = -1;
        memcpy(lora_buf.buf, msg, len);
        printf("No FRMPayload Header\n");
    }

    if(port >= 0) {
        printf("PORT      %d\n", port);
    }
    else {
        printf("PORT      NONE\n");
    }
    printf("FCNT      %d [0x%X]\n", key.fcnt32, key.fcnt32);
    return LORA_OK;
}

/*
 *  Parsing Confirmed Upload Message
 */
static int mtype_confirmed_download_msg(uint8_t *buf, int len, parse_key_t *pkey)
{
    return mtype_download_msg(buf, len , pkey);
}

static int mtype_rfu(uint8_t *msg, int len, parse_key_t *pkeyi)
{
    return LORA_OK;
}

static int mtype_proprietary(uint8_t *msg, int len, parse_key_t *pkey)
{
    return LORA_OK;
}

const mtype_func_p mtype_func[8] = {
    mtype_join_request,
    mtype_join_answer,
    mtype_upload_msg,
    mtype_download_msg,
    mtype_confirmed_upload_msg,
    mtype_confirmed_download_msg,
    mtype_rfu,
    mtype_proprietary,
};

const char *mtype_str[] = {
    "JOIN REQUEST",
    "JOIN ANSWER",
    "UNCONFIRMED DATA UP",
    "UNCONFIRMED DATA DOWN",
    "CONFIRMED DATA UP",
    "CONFIRMED DATA DOWN",
    "RFU",
    "PROPRIETARY",
};

/*
 * Band Setter
 */
int set_band(lora_band_t pband)
{
    if(pband > LORA_BAND_CUSTOM) {
        return LORA_ERR_BAND;
    }
    band = pband;
    return LORA_OK;
}

/*
 * Convert Band String to Enum value
 */ 
int get_band(char *sband)
{
    if (strncmp(sband, "eu868", strlen(sband)) == 0) {
        return LORA_BAND_EU868;
    }
    else if (strncmp(sband, "us915", strlen(sband)) == 0) {
        return LORA_BAND_US915;
    }
    else if (strncmp(sband, "cn780", strlen(sband)) == 0) {
        return LORA_BAND_CN780;
    }
    else if (strncmp(sband, "eu433", strlen(sband)) == 0) {
        return LORA_BAND_EU433;
    }
    else if (strncmp(sband, "custom", strlen(sband)) == 0) {
        return LORA_BAND_CUSTOM;
    }
    printf ("Band %s not support\n", sband);
    return LORA_ERR_BAND;
}

/*
 * Retrieve the output message
 */
int get_dmsg(uint8_t *buf, int max_len)
{
    if(0 == (flag & LORA_FLAG_BUF_OK) ) {
        return LORA_ERR_NOT_AVALAIBLE;
    }

    if(max_len < lora_buf.len) {
        return -1;
    }
    memcpy(buf, lora_buf.buf, lora_buf.len);
    return lora_buf.len;
}

/*
 * Main Parsing Function
 */
int parse_message(uint8_t *buf, int len, parse_key_t *pkey)
{
    int ret;
    mhdr_t mhdr;

    flag &= ~(LORA_FLAG_BUF_OK);
    mhdr.data = buf[LORA_MHDR];

    printf("MSG ");
    puthbuf(buf, len);
    printf("\n");

    if(mhdr.bits.major == LORA_VERSION_MAJOR_R1) {
        printf("LoRaWAN R1\n");
    }
    else{
        printf("LoRaWAN Unknown Version\n");
    }

    if(mhdr.bits.mtype >= LORA_MTYPE_PROPRIETARY){
        return LORA_ERR_CMD_UNKNOWN;
    }

    printf("%s\n", mtype_str[mhdr.bits.mtype]);
    ret = mtype_func[mhdr.bits.mtype](buf, len, pkey);

    if(ret == LORA_OK){
        fctrl_t fct;
        fct.data = buf[LORA_DATA_OFF_FCTRL];
        if(fct.bits.foptslen != 0 && port == 0) {
            return LORA_ERR_FOPTS_PORT0;
        }
        else if(fct.bits.foptslen != 0 && port != 0) {
            if(parse_maccmd(buf[LORA_MHDR], buf+LORA_DATA_OFF_FOPTS, fct.bits.foptslen) < 0) {
                return LORA_ERR_MACCMD;
            }
            if(port > 0) {
                log_data(lora_buf.buf + payload_index, payload_len);
            }
        }
        else if(port == 0) {
            if(parse_maccmd(buf[LORA_MHDR], lora_buf.buf + payload_index, payload_len) < 0){
                return LORA_ERR_MACCMD;
            }
        }
        else if(port > 0) {
            log_data(lora_buf.buf + payload_index, payload_len);
        }
        flag |= LORA_FLAG_BUF_OK;
    }
    return ret;
}

static int check_maccmd_validity(uint8_t mac_header, uint8_t *opts,  int len) 
{
    int i = 0;
    mhdr_t mhdr;
    mhdr.data = mac_header;

    // traverse all possible commands, 
    // if any of them is invalid terminate and return error
    while(i < len) 
    {
        if ((mhdr.bits.mtype == LORA_MTYPE_MSG_UP) || 
            (mhdr.bits.mtype == LORA_MTYPE_CMSG_UP)) {
            switch(opts[i]) 
            {
                // Class A
                case LORA_MCMD_LCHK_REQ:
                    if((len-i+1) < LORA_MCMD_LCHK_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_LCHK_REQ_LEN;
                break;
                case LORA_MCMD_LADR_ANS:
                    if((len-i+1) < LORA_MCMD_LADR_ANS_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_LADR_ANS_LEN;
                    break;
                case LORA_MCMD_DCAP_ANS:
                    if((len-i+1) < LORA_MCMD_DCAP_ANS_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_DCAP_ANS_LEN;
                    break;
                case LORA_MCMD_DN2P_ANS:
                    if((len-i+1) < LORA_MCMD_DN2P_ANS_LEN){
                    return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_DN2P_ANS_LEN;
                    break;
                case LORA_MCMD_DEVS_ANS:
                    if((len-i+1) < LORA_MCMD_DEVS_ANS_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_DEVS_ANS_LEN;
                    break;
                case LORA_MCMD_SNCH_ANS:
                    if((len-i+1) < LORA_MCMD_SNCH_ANS_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_SNCH_ANS_LEN;
                    break;
                case LORA_MCMD_RXTS_ANS:
                    if((len-i+1) < LORA_MCMD_RXTS_ANS_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_RXTS_ANS_LEN;
                    break;
                //Class B
                case LORA_MCMD_PING_IND:
                    if((len-i+1) < 1){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=1;
                    break;
                case LORA_MCMD_PING_ANS:
                    if((len-i+1) < 1){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=1;
                    break;
                case LORA_MCMD_BCNI_REQ:
                    if((len-i+1) < 1){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=1;
                    break;
                default:
                    return LORA_ERR_MACCMD_LEN;
                }
            }
            else if((mhdr.bits.mtype == LORA_MTYPE_MSG_DOWN) ||
                    (mhdr.bits.mtype == LORA_MTYPE_CMSG_DOWN)) {
                switch(opts[i]){
                // Class A
                case LORA_MCMD_LCHK_ANS:
                    if((len-i+1) < LORA_MCMD_LCHK_ANS_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_LCHK_ANS_LEN;
                    break;
                case LORA_MCMD_LADR_REQ:
                    if((len-i+1) < LORA_MCMD_LADR_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_LADR_REQ_LEN;
                    break;
                case LORA_MCMD_DCAP_REQ:
                    if((len-i+1) < LORA_MCMD_DCAP_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_DCAP_REQ_LEN;
                    break;
                case LORA_MCMD_DN2P_REQ:
                    if((len-i+1) < LORA_MCMD_DN2P_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_DN2P_REQ_LEN;
                    break;
                case LORA_MCMD_DEVS_REQ:
                    if((len-i+1) < LORA_MCMD_DEVS_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_DEVS_REQ_LEN;
                    break;
                case LORA_MCMD_SNCH_REQ:
                    if((len-i+1) < LORA_MCMD_SNCH_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_SNCH_REQ_LEN;
                    break;
                case LORA_MCMD_RXTS_REQ:
                    if((len-i+1) < LORA_MCMD_RXTS_REQ_LEN){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=LORA_MCMD_RXTS_REQ_LEN;
                    break;
                    //Class B
                case LORA_MCMD_PING_SET:
                    if((len-i+1) < 1){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=1;
                    break;
                case LORA_MCMD_BCNI_ANS:
                    if((len-i+1) < 1){
                        return LORA_ERR_MACCMD_LEN;
                    }
                    i+=1;
                    break;
                default:
                    return LORA_ERR_MACCMD_LEN;
            }
        }
        else {
            return LORA_ERR_MACCMD;
        }
    }
    return LORA_OK;
}

int parse_maccmd(uint8_t mac_header, uint8_t *opts, int len)
{
    uint32_t freq;
    uint16_t chmask, chmaskcntl;
    uint8_t dr, power, rx1drofst, rx2dr;
    
    int ret;
    ret = check_maccmd_validity(mac_header, opts, len);
    if (ret !=  LORA_OK) {
        printf ("MACCMD   INVALID\n");
        return ret; 
    }

    printf("MACCMD    ");
    puthbuf(opts, len);
    printf("\n");

    mhdr_t mhdr;
    mhdr.data = mac_header;

    int i=0;
    while(i < len) {
        printf("MACCMD    %s\n", maccmd_str(mhdr.bits.mtype, opts[i]));
        if ((mhdr.bits.mtype == LORA_MTYPE_MSG_UP) || 
            (mhdr.bits.mtype == LORA_MTYPE_CMSG_UP)) {
            switch(opts[i])
            {
                // Class A
                case LORA_MCMD_LCHK_REQ:
                    i+=LORA_MCMD_LCHK_REQ_LEN;
                    no_payload();
                    break;
                case LORA_MCMD_DCAP_ANS:
                    i+=LORA_MCMD_DCAP_ANS_LEN;
                    no_payload();
                    break;
                case LORA_MCMD_RXTS_ANS:
                    i+=LORA_MCMD_RXTS_ANS_LEN;
                    no_payload();
                    break;
                case LORA_MCMD_LADR_ANS:
                    printf("Status    0x%02X\n", opts[i+1]);
                    printf("Chmask    %s\n", (opts[i+1]&0x01)?"ACK":"NACK");
                    printf("Data rate %s\n", (opts[i+1]&0x02)?"ACK":"NACK");
                    printf("Power     %s\n", (opts[i+1]&0x04)?"ACK":"NACK");
                    i+=LORA_MCMD_LADR_ANS_LEN;
                    break;
                case LORA_MCMD_DN2P_ANS:
                    printf("Status    0x%02X\n", opts[i+1]);
                    printf("Channel   %s\n", (opts[i+1]&0x01)?"ACK":"NACK");
                    printf("RXWIN2    %s\n", (opts[i+1]&0x02)?"ACK":"NACK");
                    printf("RX1DRoffset %s\n", (opts[i+1]&0x04)?"ACK":"NACK");
                    i+=LORA_MCMD_DN2P_ANS_LEN;
                    break;
                case LORA_MCMD_DEVS_ANS:
                    if (opts[i+1] == 0) {
                        printf("Battery    %d (External Powered)\n", opts[i+1]);
                    }
                    else if (opts[i+1] == 255){
                        printf("Battery    %d (Unknown)\n", opts[i+1]);
                    }
                    else {
                        printf("Battery    %d (%.1f%%)\n", opts[i+1], 1.0*opts[i+1]/255);
                    }
                    dev_sta_margin.data = opts[i+2];
                    printf("Margin    %d\n", dev_sta_margin.bits.margin);
                    i+=LORA_MCMD_DEVS_ANS_LEN;
                    break;
                case LORA_MCMD_SNCH_ANS:
                    printf("Status    0x%02X\n", opts[i+1]);
                    printf("Channel   %s\n", (opts[i+1]&0x01)?"ACK":"NACK");
                    printf("DataRate  %s\n", (opts[i+1]&0x02)?"ACK":"NACK");
                    i+=LORA_MCMD_SNCH_ANS_LEN;
                    break;
                //Class B
                case LORA_MCMD_PING_IND:
                case LORA_MCMD_PING_ANS:
                case LORA_MCMD_BCNI_REQ:
                    i+=1;
                    no_payload();
                    break;
                }
        }
        else if ((mhdr.bits.mtype == LORA_MTYPE_MSG_DOWN) || 
                  (mhdr.bits.mtype == LORA_MTYPE_CMSG_DOWN) ) {
            switch(opts[i])
            {
                // Class A
                case LORA_MCMD_LCHK_ANS:
                    if(opts[i+1] == 255){
                        printf("Margin  %d (RFU)\n", opts[i+1]);
                    }else{
                        printf("Margin  %ddB\n", opts[i+1]);
                    }
                    printf("GwCnt    %d\n", opts[i+2]);
                    i+=LORA_MCMD_LCHK_ANS_LEN;
                    break;
                case LORA_MCMD_LADR_REQ:
                    dr = dr_tab[band][opts[i+1]>>4];
                    power = pow_tab[band][opts[i+1]&0x0F];
                    chmaskcntl = chmaskcntl_tab[band][(opts[i+4]>>4)&0x07];
                    chmask = opts[i+2] + (((uint16_t)opts[i+3])<<8);

                    if(power == LORA_POW_RFU){
                        printf("TXPower   %d (RFU)\n", opts[i+1]&0x0F);
                    }
                    else{
                        printf("TXPower   %d (%ddBm)\n", opts[i+1]&0x0F, power);
                    }

                    if(dr == LORA_DR_RFU){
                        printf("DataRate  DR%d (RFU)\n", opts[i+1]>>4);
                    }
                    else if( (dr&0x0F) == FSK){
                        printf("DataRate  DR%d (FSK)\n", opts[i+1]>>4);
                    }
                    else{
                        printf("DataRate  DR%d (SF%d/BW%dKHz)\n", opts[i+1]>>4, dr&0x0F, (int)(125*pow(2,dr>>4)));
                    }
                    printf("ChMask    0x%04X\n", chmask);
                    printf("NbRep     %d\n", opts[i+4]&0x0F);

                    switch(chmaskcntl)
                    {
                        case LORA_CMC_RFU:
                            printf("ChMaskCntl %d (RFU)\n", (opts[i+4]>>4)&0x07);
                            break;
                       case LORA_CMC_ALL_ON:
                            printf("ChMaskCntl %d (EU868 All on)\n", (opts[i+4]>>4)&0x07);
                            break;
                        case LORA_CMC_ALL_125KHZ_ON:
                            printf("ChMaskCntl %d, All 125KHz channels on, chmask applies to 64 ~ 71\n", (opts[i+4]>>4)&0x07);
                            break;
                        case LORA_CMC_ALL_125KHZ_OFF:
                            printf("ChMaskCntl %d, All 125KHz channels off, chmask applies to 64 ~ 71\n", (opts[i+4]>>4)&0x07);
                            break;
                        default:
                            printf("ChMaskCntl %d, chmask applies to %d ~ %d\n", (opts[i+4]>>4)&0x07, chmaskcntl&0x00FF, chmaskcntl>>8);
                            break;
                    }
                    i += LORA_MCMD_LADR_REQ_LEN;
                    break;
                case LORA_MCMD_DCAP_REQ:
                    if (opts[i+1] == 255) {
                        printf("MaxDCycle  %d(Off)\n", opts[i+1]);
                    }
                    else if(opts[i+1]<16) {
                        printf("MaxDCycle  %d (%.2f%%)\n", opts[i+1], 100.0/pow(2,opts[i+1]));
                    }
                    else {
                        printf("MaxDCycle  %d(RFU)\n", opts[i+1]);
                    }
                    i+=LORA_MCMD_DCAP_REQ_LEN;
                    break;
                case LORA_MCMD_DN2P_REQ:
                    rx1drofst = (opts[i+1]>>4) & 0x07;
                    rx2dr = dr_tab[band][opts[i+1] & 0x0F];
                    freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                    freq *= 100;
                    printf("RX1DROffset %d\n", rx1drofst);

                    if(rx2dr == LORA_DR_RFU) {
                        printf("RX2DataRate  DR%d (RFU)\n", opts[i+1] & 0x0F);
                    }
                    else if ((rx2dr&0x0F) == FSK) {
                        printf("RX2DataRate  DR%d (FSK)\n", opts[i+1] & 0x0F);
                    }
                    else {
                        printf("RX2DataRate  DR%d (SF%d/BW%dKHz)\n", opts[i+1] & 0x0F, rx2dr&0x0F, (int)(125*pow(2,rx2dr>>4)));
                    }
                    if(freq < 100000000){
                        printf("Freq      %d (RFU <100MHz)\n", freq);
                    }
                    else{
                        printf("Freq: %d\n", freq);
                    }
                    i+=LORA_MCMD_DN2P_REQ_LEN;
                    break;
                case LORA_MCMD_DEVS_REQ:
                    i+=LORA_MCMD_DEVS_REQ_LEN;
                    no_payload();
                    break;
                case LORA_MCMD_SNCH_REQ:
                    freq = (opts[i+2]) | ((uint32_t)opts[i+3]<<8) | ((uint32_t)opts[i+4]<<16);
                    freq *= 100;
                    printf("ChIndex   %d\n", opts[i+1]);
                    if(freq < 100000000){
                        printf("Freq      %d (RFU <100MHz)\n", freq);
                    }
                    else{
                        printf("Freq      %d\n", freq);
                    }
                    printf("DrRange   0x%02X (DR%d ~ DR%d)\n", opts[i+5], opts[i+5]&0x0F, opts[i+5]>>4);
                    i+=LORA_MCMD_SNCH_REQ_LEN;
                    break;
                case LORA_MCMD_RXTS_REQ:
                    if((opts[i+1]&0x0F) == 0){
                        printf("Del       %ds\n", (opts[i+1]&0x0F)+1);
                    }
                    else {
                        printf("Del        %ds\n", opts[i+1]&0x0F);
                    }
                    i+=LORA_MCMD_RXTS_REQ_LEN;
                    break;
                //Class B
                case LORA_MCMD_PING_SET:
                case LORA_MCMD_BCNI_ANS:
                    i+=1;
                    no_payload();
                    break;
            }
        }
    }
    return LORA_OK;
}


