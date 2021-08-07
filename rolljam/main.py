import os
import sys
from threading import Thread
from jamming_only  import jam
from recieve_raw  import receive
from transmit_hackrf import transmit
if __name__ == "__main__":

    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print("Warning: failed to XInitThreads()")

    # 
    # jam()
    # receive()
    transmit()