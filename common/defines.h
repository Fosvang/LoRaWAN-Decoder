#ifndef __DEFINES_H
#define __DEFINES_H

#define LORA_VERSION_MAJOR_R1       (0x00)
#define LORA_MHDR                   (0x00)

enum{
    LORA_OK                   =  0,
    LORA_ERR_CMD_UNKNOWN      = -1,
    LORA_ERR_PL_LEN           = -2,
    LORA_ERR_MIC              = -3,
    LORA_ERR_DECRYPT          = -4,
    LORA_ERR_MACCMD           = -5,
    LORA_ERR_MACCMD_LEN       = -6,
    LORA_ERR_FOPTS_PORT0      = -7,
    LORA_ERR_MALLOC           = -8,
    LORA_ERR_NOT_AVALAIBLE    = -9,
    LORA_ERR_BAND             = -10,
};

typedef enum{
    LORA_MTYPE_JOIN_REQUEST   = 0x00,
    LORA_MTYPE_JOIN_ACCEPT    = 0x01,
    LORA_MTYPE_MSG_UP         = 0x02,
    LORA_MTYPE_MSG_DOWN       = 0x03,
    LORA_MTYPE_CMSG_UP        = 0x04,
    LORA_MTYPE_CMSG_DOWN      = 0x05,
    LORA_MTYPE_RFU            = 0x06,
    LORA_MTYPE_PROPRIETARY    = 0x07
} cmd_type_t;

enum {
    LORA_DATA_OFF_DEVADDR     = 1,
    LORA_DATA_OFF_FCTRL       = 5,
    LORA_DATA_OFF_FCNT        = 6,
    LORA_DATA_OFF_FOPTS       = 8,
};


enum {
    // Class A
    LORA_MCMD_LCHK_REQ = 0x02, // link check request : -
    LORA_MCMD_LADR_ANS = 0x03, // link ADR answer    : u1:7-3:RFU, 3/2/1: pow/DR/Ch ACK
    LORA_MCMD_DCAP_ANS = 0x04, // duty cycle answer  : -
    LORA_MCMD_DN2P_ANS = 0x05, // 2nd DN slot status : u1:7-2:RFU  1/0:datarate/channel ack
    LORA_MCMD_DEVS_ANS = 0x06, // device status ans  : u1:battery 0,1-254,255=?, u1:7-6:RFU,5-0:margin(-32..31)
    LORA_MCMD_SNCH_ANS = 0x07, // set new channel    : u1: 7-2=RFU, 1/0:DR/freq ACK
    LORA_MCMD_RXTS_ANS = 0x08, // RX timing setup    :
    // Class B
    LORA_MCMD_PING_IND = 0x10, // pingability indic  : u1: 7=RFU, 6-4:interval, 3-0:datarate
    LORA_MCMD_PING_ANS = 0x11, // ack ping freq      : u1: 7-1:RFU, 0:freq ok
    LORA_MCMD_BCNI_REQ = 0x12, // next beacon start  :
};

enum {
    // Class A
    LORA_MCMD_LCHK_REQ_LEN = 1, // link check request : -
    LORA_MCMD_LADR_ANS_LEN = 2, // link ADR answer    : u1:7-3:RFU, 3/2/1: pow/DR/Ch ACK
    LORA_MCMD_DCAP_ANS_LEN = 1, // duty cycle answer  : -
    LORA_MCMD_DN2P_ANS_LEN = 2, // 2nd DN slot status : u1:7-2:RFU  1/0:datarate/channel ack
    LORA_MCMD_DEVS_ANS_LEN = 3, // device status ans  : u1:battery 0,1-254,255=?, u1:7-6:RFU,5-0:margin(-32..31)
    LORA_MCMD_SNCH_ANS_LEN = 2, // set new channel    : u1: 7-2=RFU, 1/0:DR/freq ACK
    LORA_MCMD_RXTS_ANS_LEN = 1,
    // Class B
    LORA_MCMD_PING_IND_LEN = 1, // pingability indic  : u1: 7=RFU, 6-4:interval, 3-0:datarate
    LORA_MCMD_PING_ANS_LEN = 1, // ack ping freq      : u1: 7-1:RFU, 0:freq ok
    LORA_MCMD_BCNI_REQ_LEN = 1, // next beacon start  : -
};

enum {
    // Class A
    LORA_MCMD_LCHK_ANS = 0x02, // link check answer  : u1:margin 0-254,255=unknown margin / u1:gwcnt
    LORA_MCMD_LADR_REQ = 0x03, // link ADR request   : u1:DR/TXPow, u2:chmask, u1:chpage/repeat
    LORA_MCMD_DCAP_REQ = 0x04, // duty cycle cap     : u1:255 dead [7-4]:RFU, [3-0]:cap 2^-k
    LORA_MCMD_DN2P_REQ = 0x05, // 2nd DN window param: u1:7-4:RFU/3-0:datarate, u3:freq
    LORA_MCMD_DEVS_REQ = 0x06, // device status req  : -
    LORA_MCMD_SNCH_REQ = 0x07, // set new channel    : u1:chidx, u3:freq, u1:DRrange
    LORA_MCMD_RXTS_REQ = 0x08, // RX timing setup    :
    // Class B
    LORA_MCMD_PING_SET = 0x11, // set ping freq      : u3: freq
    LORA_MCMD_BCNI_ANS = 0x12, // next beacon start  : u2: delay(in TUNIT millis), u1:channel
};

enum {
    // Class A
    LORA_MCMD_LCHK_ANS_LEN = 3, // link check answer  : u1:margin 0-254,255=unknown margin / u1:gwcnt
    LORA_MCMD_LADR_REQ_LEN = 5, // link ADR request   : u1:DR/TXPow, u2:chmask, u1:chpage/repeat
    LORA_MCMD_DCAP_REQ_LEN = 2, // duty cycle cap     : u1:255 dead [7-4]:RFU, [3-0]:cap 2^-k
    LORA_MCMD_DN2P_REQ_LEN = 5, // 2nd DN window param: u1:7-4:RFU/3-0:datarate, u3:freq
    LORA_MCMD_DEVS_REQ_LEN = 1, // device status req  : -
    LORA_MCMD_SNCH_REQ_LEN = 6, // set new channel    : u1:chidx, u3:freq, u1:DRrange
    LORA_MCMD_RXTS_REQ_LEN = 2, // RX timing setup    :
    // Class B
    LORA_MCMD_PING_SET_LEN = 1, // set ping freq      : u3: freq
    LORA_MCMD_BCNI_ANS_LEN = 1, // next beacon start  : u2: delay(in TUNIT millis), u1:channel
};

typedef enum {
    LORA_BAND_EU868=0,
    LORA_BAND_US915,
    LORA_BAND_CN780,
    LORA_BAND_EU433,
    LORA_BAND_CUSTOM,
} lora_band_t;

typedef enum{
    LORA_UPLINK     = 0,
    LORA_DOWNLINK   = 1,
} lora_link_t;

enum{
    BW125 = 0,      // 125*1 125*pow(2,n)
    BW250 = 1,      // 125*2
    BW500 = 2,      // 125*4
};

enum{
    FSK = 0,
    SF5 = 5,
    SF6 = 6,
    SF7 = 7,
    SF8 = 8,
    SF9 = 9,
    SF10 = 10,
    SF11 = 11,
    SF12 = 12,
};

#endif // __DEFINES_H
