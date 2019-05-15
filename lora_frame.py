from enum import *
import binascii

class LoRaFrameType(IntEnum):
    JoinRequest         = 0
    JoinAccept          = 1
    UnconfirmedDataUp   = 2
    UnconfirmedDataDown = 3
    ConfirmedDataUp     = 4
    ConfirmedDataDown   = 5
    RejoinRequest       = 6

class LoRaFrame:
    """ LoRa frame class decoding the MHDR and MIC
    """
    def __init__(self) :
        """ LoRaFrame class constructor
        Args: None
        Returns: None
        """
        self._up = True
        self._mtype = 0
        self._major = 0
        self._raw = bytearray()
        self._mic = bytearray()
        self._micok = False
        self._buffer = None

    def decode(self, buf):
        """ prepare the buffer and decode headers
        Args: 
            buf: lora frame
        Returns: None
        """
        if buf[:2] == "0x":
            buf = buf[2:]
        self._buffer = binascii.unhexlify(buf)
        self.decode_headers(self._buffer)

    def decode_headers(self, buf):
        """ decoding MHDR and MIC lora frame given
        Args: None
        Returns: None
        """
        self._raw = buf
        self._mhdr = buf[0]
        self._major = self._mhdr & 3
        self._mtype = (self._mhdr >> 5) & 7
        if (self._mtype == LoRaFrameType.UnconfirmedDataUp or 
                self._mtype == LoRaFrameType.ConfirmedDataUp):
            self._up = True
        else :
            self._up = False
        idx = len(buf)-4
        self._mic = buf[idx:]

