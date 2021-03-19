from scapy.all import *
import numpy
import argparse
from functools import partial 

stations = set(("")) # note the double round-brackets
def wrapper(bssid):
    def ap_mac(pkt):
        if pkt.haslayer(Dot11):
            addresses = (pkt.addr1,pkt.addr3)
            if bssid.lower() in addresses and "ff:ff:ff:ff:ff:ff" not in addresses and None not in addresses :
                stations.add(pkt.addr2)
                # print(a[:,0])
                os.system("clear")
                print(numpy.array(list(stations)))
        else: pass
    return ap_mac

if __name__ == "__main__":
    # interface name, check using iwconfig
    # parser = argparse.ArgumentParser(description="A python script for sending deauthentication frames")
    # parser.add_argument("target", help="Target MAC address to deauthenticate.")

    # args = parser.parse_args()
    # target = args.target

    interface = "wlan0mon"
    try:
        sniff(prn=wrapper("14:AE:DB:32:0A:8A"),iface=interface)
    except KeyboardInterrupt:
        print(stations) 
        sys.exit()

    # start sniffing
   

# In our case the full command is:

# airodump-ng -d 50:C7:BF:DC:4C:E8 -c 11 wlan0mo