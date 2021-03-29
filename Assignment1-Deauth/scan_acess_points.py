import time
import os
from threading import Thread
from scapy.all import Dot11Beacon,Dot11,Dot11Elt,AsyncSniffer

spacing = "{:<20} {:<40} {:<10} {:<10} {:<10}"

class ScanAccessPoints:

    def __init__(self, iface="wlan0mon"):

        """
        c'tor

        Parameters
        ----------
        iface : str,optional
           Interface to use, must be in monitor mode (default 'wlan0mon')
        """

        self.access_points = {}
        self.iface = iface

    def change_channel(self, total_time, interval):

        """
        changes wifi channel after certain amount of time
        performed in parallel to the sniffing

        Parameters
        ----------
        total_time : decimal
            The desired amount of time to search for an access point
        interval : decimal
            Time per channel
        """

        ch = 1
        for i in range(1, int(total_time/interval)):
            os.system(f"iwconfig {self.iface} channel {ch}")
            # switch channel from 1 to 14 each time defined in interval
            ch = ch % 14 + 1
            time.sleep(interval)

    def sniffAction(self, timeout):

        """
        sniffs to find access points.
        
        Parameters
        ----------
        timeout : decimal
            max sniffing time
        """

        print(spacing.format("BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"))
        sniffer_thread = AsyncSniffer(prn=self.callback, iface=self.iface)
        sniffer_thread.start()

        channel_changer = Thread(target=self.change_channel, args=(timeout, 0.5))
        channel_changer.daemon = True
        channel_changer.start()

        time.sleep(timeout)
        sniffer_thread.stop()

    def callback(self, pkt):

        """
        performs for every packet the sniffer finds.
        analyzes the packet to find new saccess points. 

        Parameters
        ----------
        pkt : packet object
            packet for analysis
        """

        if pkt.haslayer(Dot11Beacon):
            # extract the MAC address of the network
            bssid = pkt[Dot11].addr2.upper()
            # get the name of it
            ssid = pkt[Dot11Elt].info.decode()
            try:
                dbm_signal = pkt.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = pkt[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
            if bssid not in self.access_points:
                self.access_points[bssid] = [ssid, dbm_signal, channel, crypto]
                print(spacing.format(bssid, ssid,
                                     dbm_signal, channel, list(crypto)[0]))
