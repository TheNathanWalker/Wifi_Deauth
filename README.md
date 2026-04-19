# Wifi_Deauth
Wifi Deauthentication

# Summary
This script is a Wi-Fi deauthentication tool used for security testing. It operates in a Linux environment with a compatible wireless adapter in monitor mode, leveraging Scapy to detect and disrupt specified APs and their clients. It must only be used in authorized, controlled environments due to its disruptive nature.

# Legal
This script is provided for academic and educational purposes only. It is intended solely for testing and research on wireless networks that you own or have explicit permission to assess.

Do not use this script against any network or device without proper authorization. Unauthorized use of Wifii deauthentication tools is illegal in many jurisdictions and may result in severe legal consequences.

By using this script, you agree to comply with all applicable local, state, federal, and international laws and regulations. The creator of this script assumes no responsibility for misuse, damage, or legal consequences resulting from its use.

Use this tool at your own risk, and only in environments where you have permission to perform penetration testing or security research

# Configuration (deauth.json)

The tool is configured via the `deauth.json` file. All parameters must be properly set before running the script.

## Global Parameters

- **interface** (string): The wireless network interface name (e.g., `"wlan0"`, `"wlan0mon"`). This interface must be in monitor mode before running the script.

- **deauth_duration** (integer): Duration in seconds to send deauthentication packets per target after monitoring completes.

- **monitor_duration** (integer): Duration in seconds to passively monitor each target network and log connected clients before performing deauthentication.

- **debug** (boolean): Enable debug logging. When `true`, logs detailed information including channel switches and packet-level details. When `false`, logs only major events.

- **log_file** (string): Path to the log file where all events will be recorded (e.g., `"deauth.log"`).

- **verify_timeout** (integer): Seconds to listen for beacon frames on each channel during the AP verification phase.

- **max_retries** (integer): Maximum number of retry attempts to verify an AP's presence before skipping it.

## Targets Array

The `targets` array contains one or more access points to test. Each target has the following fields:

- **ssid** (string): The network name (SSID) of the target access point. Used for identification in logs.

- **bssid** (string): The MAC address of the target access point in colon-separated format (e.g., `"aa:bb:cc:dd:ee:ff"`). Must be lowercase or will be converted to lowercase for matching.

- **channels** (array of integers): List of WiFi channels where the AP may be broadcasting. The script will verify the AP's presence on these channels before monitoring/deauth. Common 2.4GHz channels: 1-14. Common 5GHz channels: 36, 40, 44, 48, 149, 153, 157, 161, 165.

## Example Configuration

```json
{
    "interface": "wlan0mon",
    "deauth_duration": 60,
    "monitor_duration": 30,
    "debug": true,
    "log_file": "deauth.log",
    "verify_timeout": 5,
    "max_retries": 3,
    "targets": [
        {
            "ssid": "TestNetwork-2.4GHz",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "channels": [6, 11]
        },
        {
            "ssid": "TestNetwork-5GHz",
            "bssid": "11:22:33:44:55:66",
            "channels": [149, 153]
        }
    ]
}
```

## Operation Flow

For each target in the configuration:

1. **Verification**: Scans specified channels to confirm the AP is active. If the AP is not detected after `max_retries` attempts, the target is skipped.

2. **Monitoring**: Passively listens for `monitor_duration` seconds, logging all connected clients discovered on the network.

3. **Deauthentication**: Only executed if clients were detected during monitoring. Sends deauth packets for `deauth_duration` seconds on verified channels. If no clients are found, this phase is skipped.

All activity is logged to the file specified in `log_file`
