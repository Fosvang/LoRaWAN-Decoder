from Crypto.Cipher import AES
from io import StringIO

from struct import *
from lora_frame import *

import os, sys, math
import cmac

def aes128_cmac(key, text):
    """ aes128 cmac hash calculation
    Args:
        key: 16B encryption key 
        text: text to be used for digest calculation
    Returns: calculated digest 
    """
    cipher = cmac.new(key, ciphermod=AES)
    cipher.update(text)
    return cipher.digest()

def aes128_encrypt(key, text):
    """ aes128 encryption in cbc mode
    Args:
        key: 16B encryption key 
        text: text to encrypt
    Returns: encrypted text
    """
    IV = 16 * b'0'
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    return cipher.encrypt(text)

def getHundredHz(buf):
    """ convert frequency in hundred HZ
    Args:
        buf: 4B frequency value from MacCommand
    Returns: frequency in hundred HZ
    """
    freq = buf[0] + (buf[1]<<8) + (buf[2]<<16)
    return freq/10000.0

class JoinReq(LoRaFrame):
    """ LoRa data class handling encryption and decoding of Join-Request
    """
    def __init__(self,  AppKey) :
        """ JoinReq class constructor
        Args: 
            AppKey: LoRa AppKey
        Returns: None
        """
        super().__init__()
        self._appkey = AppKey
        self._deveui   = bytearray()
        self._joineui  = bytearray()
        self._devnounce = bytearray()
        self._output   = StringIO() 

    def decode_frame(self, buf) :
        """ decrypt and decode frame payload and verify MIC 
        Args: None
        Returns: None
        """
        self.decode_headers(buf)
        self._joineui  = buf[1:9]
        self._deveui   = buf[9:17]
        self._devnounce = buf[17:19]
        self._deveui   = bytearray(reversed(self._deveui))
        self._joineui  = bytearray(reversed(self._joineui))

        cmac = aes128_cmac(self._appkey, buf[:len(buf)-4])
        mic = cmac[:4]
        if self._mic != mic :
            self._micok = False
        else :
            self._micok = True

        self._output.write('JoinEUI : {}'.format(binascii.hexlify(self._joineui)))
        self._output.write('\nDevEUI : {}'.format(binascii.hexlify(self._deveui)))
        self._output.write('\nDevNonce : {}'.format(binascii.hexlify(self._devnounce)))
        self._output.write('\nMIC : {}'.format(binascii.hexlify(self._mic)))
        self._output.write('\nMICOK : {}'.format(self._micok))


class JoinAccept(LoRaFrame):
    """ LoRa data class handling encryption and decoding of Join-Response
    """
    def __init__(self, AppKey):
        """ JoinAccept class constructor
        Args: 
            AppKey: LoRa AppKey
        Returns: None
        """
        super().__init__()
        self._appkey = AppKey
        self._netid    = bytearray()
        self._cflist   = bytearray()
        self._devaddr  = bytearray()
        self._appnounce = bytearray()
        self._rxdelay    = 0
        self._dlsettings = 0
        self._output     = StringIO() 

    def decode_frame(self, buf):
        """ decrypt and decode frame payload and verify MIC 
        Args: None
        Returns: None
        """
        self.decode_headers(buf)
        self._appnounce = buf[1:4]
        self._netid    = buf[4:7]
        self._devaddr  = buf[7:11]
        self._dlsettings = buf[11]
        self._rxdelay    = buf[12]
        self._cflist     = buf[13:len(buf)-4]

        buf2 = bytearray()
        buf2.append(buf[0])
        if sys.version_info[0] == 2:
            buf = str(buf)
            buf2 = str(buf2)

        buf2 += aes128_encrypt(self._appkey, buf[1:17])
        if len(buf) == 32 :
            buf2 += aes128_encrypt(self._appkey, buf[17:])

        self._mic = buf2[len(buf2)-4:]
        cmac = aes128_cmac(self._appkey, buf2[:len(buf2)-4])
        mic = cmac[:4]
        # compare mic
        if self._mic != mic:
            self._micok = False
        else :
            self._micok = True

        self._output.write('AppNonce   : {}'.format(binascii.hexlify(self._appnounce)))
        self._output.write('\nNetID      : {}'.format(binascii.hexlify(self._netid)))
        self._output.write('\nDevAddr    : {}'.format(binascii.hexlify(self._devaddr)))
        self._output.write('\nDLSettings : {}'.format(self._dlsettings))
        self._output.write('\nRxDelay    : {}'.format(self._rxdelay))
        self._output.write('\nCFList     : {}'.format(binascii.hexlify(self._cflist)))
        self._output.write('\nMIC        : {}'.format(binascii.hexlify(self._mic)))
        self._output.write('\nMICOK      : {}'.format(self._micok))


class LoRaData(LoRaFrame):
    """ LoRa data class handling encryption and decoding of MACPayload
    """
    def __init__(self, NwkSKey, AppSKey):
        """ LoRaData class constructor
        Args: 
            NwkSKey: LoRa NwkSKey
            AppSKey: LoRa AppSKey
        Returns: None
        """
        super().__init__()
        self._fcnt = 0
        self._fport = 0
        self._mtype = 0
        self._fctrl = 0
        self._devaddr = 0
        self._nwkskey = NwkSKey
        self._appskey = AppSKey
        self._nwkskey = binascii.unhexlify(NwkSKey)
        self._appskey = binascii.unhexlify(AppSKey)
        self._fopts   = bytearray()
        self._payload = bytearray()
        self._fport_present = False
        self._decrypted = bytearray()
        self._output = StringIO()

    def getDevAddr(self):
        """ Getter for device address
        Args: 
            devaddr: device address
        Returns: None
        """
        return '{:08x}'.format(self._devaddr)

    def cmac(self):
        """ aes128 cmac hash calculation
        Args: None
        Returns: calculated digest 
        """
        B0 = bytearray()
        B0.append(0x49)
        B0.append(0)
        B0.append(0)
        B0.append(0)
        #B0.append(0)
        B0.append(not self._up)
        # DevAddr
        B0.append(self._raw[1])
        B0.append(self._raw[2])
        B0.append(self._raw[3])
        B0.append(self._raw[4])
        # FCntUp
        B0.append(self._raw[6])
        B0.append(self._raw[7])
        B0.append(0)
        B0.append(0)
        B0.append(0)
        B0.append(len(self._raw) - 4)
        MICidx = len(self._raw) - 4
        B0 += self._raw[:MICidx]
        return aes128_cmac(self._nwkskey, B0)

    def mic_verify(self):
        """ mic verification 
        Args: None
        Returns: frame mic
        """
        cmac = self.cmac()
        mic = cmac[:4]
        if self._mic != mic:
            self._micok = False
        else :
            self._micok = True
        return self._micok

    def decrypt(self, key):
        """ lorawan10 aes decryption
        Args: 
            key: lora key
        Returns: None
        """
        if len(self._payload) == 0:
            return

        S = bytearray()
        Ai = bytearray()
        Ai.append(0x01)
        Ai.append(0x00)
        Ai.append(0x00)
        Ai.append(0x00)
        Ai.append(0x00)
        Ai.append(not self._up)
        # DevAddr
        Ai.append(self._raw[1])
        Ai.append(self._raw[2])
        Ai.append(self._raw[3])
        Ai.append(self._raw[4])
        # FCntUp
        Ai.append(self._raw[6])
        Ai.append(self._raw[7])
        Ai.append(0x00)
        Ai.append(0x00)
        Ai.append(0x00)
        Ai.append(0x00) # create Ai[15]

        k = int(math.ceil(len(self._payload) / 16.0))
        for i in range(k) :
            Ai[15] = i+1
            Si = aes128_encrypt(key, bytes(Ai))
            S += Si

        # (pld | pad16)
        pld = bytearray()
        pld += self._payload
        for i in range(k*16 - len(self._payload)) :
            pld.append(0x0)

        # (pld | pad16) xor S
        for i in range(len(pld)) :
            pld[i] = pld[i] ^ S[i]

        self._decrypted = pld[:len(self._payload)]

    def encrypt(self, key):
        """ lorawan10 aes encryption
        Args: 
            key: lora key
        Returns: None
        """
        self.decrypt(key)

    def decode_frame(self, buf) :
        """ decrypt and decode frame payload and verify MIC 
        Args: None
        Returns: None
        """
        self._buffer = buf
        self.decode_headers(self._buffer)
        self._devaddr = buf[1] + (buf[2]<<8) + (buf[3]<<16) + (buf[4]<<24)
        self._fctrl = buf[5]
        self._fcnt = buf[6] + (buf[7]<<8)
        i = 8
        FOptsLen = self._fctrl & 0xf
        if FOptsLen > 0 :
            self._fopts = buf[i:i+FOptsLen]
            i += FOptsLen

        if len(buf)-i > 4 :
            self._fport_present = True
            self._fport = buf[i]
            i += 1
            self._payload = buf[i:len(buf)-4]

        self.mic_verify()
        if self._fport_present and (self._fport == 0) :
            self.decrypt(self._nwkskey)
        else:
            self.encrypt(self._appskey)

        self._output.write("LoRa Payload Decoding")
        self._output.write('\nraw      : {}'.format(binascii.hexlify(self._raw)))
        self._output.write('\nMIC      : {}'.format(binascii.hexlify(self._mic)))
        self._output.write('\nMICOK    : {}'.format(self._micok))
        self._output.write('\nDevAddr  : {}'.format(self.getDevAddr()))
        self._output.write('\nFCtrl    : {}'.format(self._fctrl))
        self._output.write('\nFCnt     : {}'.format(self._fcnt))

        if self._fport_present :
            self._output.write('\nFPort    : {}'.format(self._fport))
        else :
            self._output.write('\nFPort    : {}')

        self._output.write('\nFOpts    : {}'.format(binascii.hexlify(self._fopts)))
        self._output.write('\nPayload  : {}'.format(binascii.hexlify(self._payload)))
        self._output.write('\ndecryptedPayload : {}'.format(binascii.hexlify(self._decrypted)))

    def decode_any_mac_commands(self) :
        """ decoding mac commands in FOpts or in the payload
        Args: None
        Returns: None
        """
        if self._fport_present and (self._fport == 0) :
            self.decode_mac_commands(self._decrypted)
        else :
            self.decode_mac_commands(self._fopts)

    def decode_mac_commands(self, buf) :
        """ decoding Mac Commands
        Args: 
            buf: input buffer
        Returns: None
        """
        if self._up :
            self.decode_commands_up(buf)
        else :
            self.decode_commands_down(buf)

    def decode_commands_up(self, buf):
        """ decoding Uplink Mac Commands
        Args: 
            buf: input buffer
        Returns: None
        """
        i = 0
        while i < len(buf) :
            cmd = buf[i]
            i += 1
            if cmd == 0x01 :
                self._output.write('\nResetInd LoRaWANversion:{}'.format(buf[i] & 0xf))
                i += 1
            elif cmd == 0x02 :
                self._output.write('\nLinkCheckReq')
            elif cmd == 0x03 :
                self._output.write('\nLinkADRAns Status:{:02x}'.format(buf[i]))
                i += 1
            elif cmd == 0x04 :
                self._output.write('\nDutyCycleAns')
            elif cmd == 0x05 :
                self._output.write('\nRXParamSetupAns Status:{:02x}'.format(buf[i]))
                i += 1
            elif cmd == 0x06 :
                self._output.write('\nDevStatusAns Battery:{} Margin:{}'.format(buf[i], buf[i+1]))
                i += 2
            elif cmd == 0x07 :
                self._output.write('\nNewChannelAns Status:{}'.format(buf[i]))
                i += 1
            elif cmd == 0x08 :
                self._output.write('\nRxtimingSetupAns')
            elif cmd == 0x09 :
                self._output.write('\nTxParamSetupAns')
            elif cmd == 0x0a :
                self._output.write('\nDlChannelAns Status:{}'.format(buf[i]))
                i += 1
            elif cmd == 0x0b :
                version = buf[i] & 0xf
                self._output.write('\nRekeyInd Dev LoRaWANversion:{}'.format(version))
                i += 1
            elif cmd == 0x0c :
                self._output.write('\nADRParamSetupAns')
            elif cmd == 0x0d :
                self._output.write('\nDeviceTimeReq')
            elif cmd == 0x0e :
                self._output.write('\n0xe ???')
            elif cmd == 0x0f :
                self._output.write('\nRejoinParamSetupAns')
                i += 1
            elif cmd == 0x10 :
                self._output.write('\nPingSlotInfoReq Periodicity:{}'.format(buf[i]&0x7))
                i += 1
            elif cmd == 0x11 :
                self._output.write('\nPingSlotChannelAns Status:{}'.format(buf[i]))
                i += 1
            elif cmd == 0x12 :
                self._output.write('\nBeaconTimingReq deprecated')
            elif cmd == 0x13 :
                self._output.write('\nBeaconFreqAns Status:{}'.format(buf[i]))
                i += 1

    def decode_commands_down(self, buf):
        """ decoding Downlink Mac Commands
        Args: 
            buf: input buffer
        Returns: None
        """
        i = 0
        while i < len(buf) :
            cmd = buf[i]
            i += 1
            if cmd == 0x01 :
                self._output.write('\nResetConf LoRaWANversion:{}'.format(buf[i] & 0xf))
                i += 1
            elif cmd == 0x02 :
                self._output.write('\nLinkCheckAns Margin:{} GwCnt:{}'.format(buf[i], buf[i+1]))
                i += 2
            elif cmd == 0x03 :
                DataRate = buf[i] >> 4
                TxPower = buf[i] & 0xf
                ChMask = buf[i+1:i+3]
                ChMaskCntl = (buf[i+3] >> 4) & 0x7
                NbTrans = buf[i+3] & 0xf
                self._output.write('\nLinkADRReq DataRate:{} TxPower:{} ChMask:{} ChMaskCntl:{} NbTrans:{}'.format(DataRate, TxPower, ChMask, ChMaskCntl, NbTrans))
                i += 4
            elif cmd == 0x04 :
                self._output.write('\nDutyCycleReq MaxDCycle:{}'.format(buf[i]&0xf))
                i += 1
            elif cmd == 0x05 :
                RX1DRoffset = (buf[i]>>4) & 0x7
                RX2DataRate = buf[i] & 0xf
                freq = getHundredHz(buf[i+1:i+4])
                self._output.write('\nRXParamSetupReq RX1DRoffset:{} RX2DataRate:{} Freq:{}'.format(RX1DRoffset, RX2DataRate, freq))
                i += 4
            elif cmd == 0x06 :
                self._output.write('\nDevStatusReq')
            elif cmd == 0x07 :
                freq = getHundredHz(buf[i+1:i+4])
                self._output.write('\nNewChannelReq ChIndex:{} Freq:{} DrRange:{:02x}'.format(buf[i], freq, buf[i+4]))
                i += 5
            elif cmd == 0x08 :
                self._output.write('\nRxtimingSetupReq Delay:{}'.format(buf[i]&0xf))
                i += 1
            elif cmd == 0x09 :
                DownlinkDwellTime = (buf[i] >> 5) & 0x1
                UplinkDwellTime = (buf[i] >> 4) & 0x1
                MaxEIRP = buf[i] & 0xf
                self._output.write('\nTxParamSetupReq DownlinkDwellTime:{} UplinkDwellTime:{} MaxEIRP:{}'.format(DownlinkDwellTime, UplinkDwellTime, MaxEIRP))
                i += 1
            elif cmd == 0x0a :
                freq = getHundredHz(buf[i+1:i+4])
                self._output.write('\nDlChannelReq ChIndex:{} Freq:{} DrRange:{:02x}'.format(buf[i], freq, buf[i+4]))
                i += 5
            elif cmd == 0x0b :
                version = buf[i] & 0xf
                self._output.write('\nRekeyConf Serv LoRaWANversion:{}'.format(version))
                i += 1
            elif cmd == 0x0c :
                self._output.write('\nADRParamSetupReq')
                i += 1
            elif cmd == 0x0d :
                self._output.write('\nDeviceTimeAns')
                i += 5
            elif cmd == 0x0e :
                self._output.write('\nForceRejoinReq')
                i += 2
            elif cmd == 0x0f :
                self._output.write('\nRejoinParamSetupReq')
                i += 1
            elif cmd == 0x10 :
                self._output.write('\nPingSlotInfoAns')
            elif cmd == 0x11 :
                freq = getHundredHz(buf[i:i+3])
                DataRate = buf[3] & 0xf
                self._output.write('\nPingSlotChannelReq Frequency:{} DataRate:{}'.format(freq, DataRate))
                i += 4
            elif cmd == 0x12 :
                self._output.write('\nBeaconTimingAns deprecated')
            elif cmd == 0x13 :
                freq = getHundredHz(buf[i:i+3])
                self._output.write('\nBeaconFreqReq Frequency:{}'.format(freq))
                i += 3

