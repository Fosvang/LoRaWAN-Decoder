#!/usr/bin/env python3
from lora_data import *
from lora_frame import *

if __name__ == "__main__":
    """ Main function
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="Decoder",
        description="LoRaWAN Frame Decoder",
        epilog="(c) Youssef 2018"
    )

    parser.add_argument("-n", "--nwkskey", help="NwkSKey encryption key", required=True)
    parser.add_argument("-a", "--appskey", help="AppSKey encryption key", required=True)
    parser.add_argument("-p", "--payload", help="Payload to be decrypted and decoded", required=True)
    parser.add_argument("-k", "--appkey", help="AppKey key for JoinReq and JoinAccept", required=False)

    try:
        options = parser.parse_args(sys.argv[1:])
        frame = LoRaFrame()
        frame.decode(options.payload)

        if frame._mtype == LoRaFrameType.JoinRequest:
            lora = JoinReq(options.appkey)
        elif frame._mtype == LoRaFrameType.JoinAccept:
            lora = JoinAccept(options.appkey)
        else :
            lora = LoRaData(options.nwkskey, options.appskey)

        lora.decode_frame(frame._buffer)
        lora.decode_any_mac_commands()
        print (lora._output.getvalue())

    except Exception as e:
        print('Execution failed.  Exit')
        print(repr(e))
        sys.exit(1)

    sys.exit(0)

