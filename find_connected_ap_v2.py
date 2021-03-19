from scapy.all import *
import numpy
import argparse
from functools import partial 

stations = set(("")) # note the double round-brackets
def wrapper(ap_bssid):
    def ap_mac(pkt):
        if pkt.haslayer(Dot11):
            addresses = (pkt.addr1,pkt.addr3)
            if ap_bssid.lower() in addresses and "ff:ff:ff:ff:ff:ff" not in addresses and None not in addresses :
                stations.add(pkt.addr2)
                os.system("clear")
                print(numpy.array(list(stations)))
        else: pass
    return ap_mac

if __name__ == "__main__":
    # interface name, check using iwconfig
    parser = argparse.ArgumentParser(description="A python script for for finding all clients bssid that connected to specified ap")
    parser.add_argument("ap_bssid", help="Access point bssid")

    args, unknown = parser.parse_known_args()
    ap_bssid = args.ap_bssid

    interface = "wlan0mon"
    
    sniff(prn=wrapper(ap_bssid),iface=interface)
  

    # start sniffing
   

# In our case the full command is:

# airodump-ng -d 50:C7:BF:DC:4C:E8 -c 11 wlan0mo