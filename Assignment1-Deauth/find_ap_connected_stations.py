import time
from scapy.all import Dot11,AsyncSniffer

spacing = "{:<20} {:<20}"


class FindAccessPointConnectedStations:

    def __init__(self, iface="wlan0mon"):
        
        """
        c'tor

        Parameters
        ----------
        iface : str,optional
           Interface to use, must be in monitor mode (default 'wlan0mon')
        """

        self.stations = {}  # note the double round-brackets
        self.iface = iface

    def sniffAction(self, ap_bssid, timeout):

        """
        sniffs to find all stations connected to this specific access point 

        Parameters
        ----------
        ap_bssid : str
            Gateway BSSID address that target is authenticated with
        timeout : decimal
            max sniffing time
        """

        print(spacing.format("CONNECTED_STATION_BSSID", "ACCESS_POINT_BSSID"))
        sniffer_thread = AsyncSniffer(prn=self.wrapper(ap_bssid), iface=self.iface)
        sniffer_thread.start()
        time.sleep(timeout)
        sniffer_thread.stop()

    def wrapper(self, ap_bssid):

        """
        wraps the callback function and provides it with the ap_bssid
        
        Parameters
        ----------
        ap_bssid : str
            Gateway BSSID address that target is authenticated with
        """

        def callback(pkt):

            """
            performs for every packet the sniffer finds.
            analyzes the packet to find new stations connected to the access point. 

            Parameters
            ----------
            pkt : packet object
                packet for analysis
            """

            if pkt.haslayer(Dot11):
                addr1, addr2, addr3 = pkt.addr1, pkt.addr2, pkt.addr3
                # Sanitze and upper all inputs
                sanitizedAddr1 = addr1.upper() if addr1 is not None else ''
                sanitizedAddr2 = addr2.upper() if addr2 is not None else ''
                sanitizedAddr3 = addr3.upper() if addr3 is not None else ''

                addresses = (sanitizedAddr1, sanitizedAddr3)
                remove_values = ("FF:FF:FF:FF:FF:FF","")
                
                if ap_bssid in addresses and ap_bssid == sanitizedAddr3 and not any(t in addresses for t in remove_values):
                    if sanitizedAddr2 not in self.stations:
                        self.stations[sanitizedAddr2] = sanitizedAddr3
                        print(spacing.format(sanitizedAddr2, sanitizedAddr3))
            else:
                pass
        return callback
