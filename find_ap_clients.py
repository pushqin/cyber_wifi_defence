from scapy.all import *
import numpy
import argparse
from functools import partial

spacing = "{:<20} {:<20}"


class find_ap_clients:

    def __init__(self, interface="wlan0mon"):

        self.stations = {}  # note the double round-brackets
        self.interface = interface

    def sniffAction(self, ap_bssid):
        print(spacing.format("TARGET_BSSID", "AP_SSID"))
        sniff(prn=self.wrapper(ap_bssid), iface=self.interface)

    def wrapper(self, ap_bssid):
        def ap_mac(pkt):
            if pkt.haslayer(Dot11):
                addr1, addr2, addr3 = pkt.addr1, pkt.addr2, pkt.addr3
                sanitizedAddr1 = addr1.upper() if addr1 is not None else ''
                sanitizedAddr2 = addr2.upper() if addr2 is not None else ''
                sanitizedAddr3 = addr3.upper() if addr3 is not None else ''

                addresses = (sanitizedAddr1, sanitizedAddr3)

                if ap_bssid in addresses and "FF:FF:FF:FF:FF:FF" not in addresses and '' not in addresses:
                    # self.stations.add(sanitizedAddr2)
                    # os.system("clear")
                    if sanitizedAddr2 not in self.stations:
                        self.stations[sanitizedAddr2] = [sanitizedAddr1]
                        print(spacing.format(sanitizedAddr2, sanitizedAddr1))
            else:
                pass
        return ap_mac


# if __name__ == "__main__":
#     # interface name, check using iwconfig
#     parser = argparse.ArgumentParser(
#         description="A python script for for finding all clients bssid that connected to specified ap")
#     parser.add_argument("ap_bssid", help="Access point bssid")

#     args, unknown = parser.parse_known_args()
#     ap_bssid = args.ap_bssid

#     interface = "wlan0mon"

#     sniff(prn=wrapper(ap_bssid), iface=interface)

    # start sniffing


# In our case the full command is:

# airodump-ng -d 50:C7:BF:DC:4C:E8 -c 11 wlan0mo
