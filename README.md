# ARP-Spoofing-based-Parental-Control

## Overview
ARP-Spoofing-based-Parental-Control is a Python-based project that enables you to perform ARP spoofing on devices in your network to implement parental control by filtering traffic based on a user-defined whitelist or blacklist. This project utilizes the `scapy`, `requests`, `scapy_http`, and `netfilterqueue` libraries to achieve its functionality.

## Requirements
Make sure you have the following libraries installed before running the script:
- `scapy`
- `requests`
- `scapy_http`
- `netfilterqueue`

You can install these libraries using pip:
```bash
pip install scapy requests scapy_http netfilterqueue
```

## Usage
To run the script, execute it with Python 3:
```bash
python3 main.py [-h] [-b BLACKLIST] [-w WHITELIST] [-c COUNT]
```

### Arguments
- `-b`, `--blacklist`: File with hostnames/IP to blacklist. (Default: None)
- `-w`, `--whitelist`: File with hostnames/IP to whitelist. (Default: None)
- `-c`, `--count`: Number of devices to spoof. (Default: 1)

**Note**: You must provide either a blacklist file or a whitelist file for the script to function correctly.

### Functionality
The script performs the following actions:

1. Enables IP forwarding to allow traffic redirection.
2. Scans the network to discover the IP and MAC addresses of devices using ARP requests and responses.
3. Prompts the user to select the devices they want to spoof.
4. Performs ARP spoofing on the selected devices to make them think the script is the router and vice versa.
5. Implements traffic filtering based on the provided blacklist or whitelist:
   - If a blacklist is provided, it drops packets from or to blacklisted IP addresses.
   - If a whitelist is provided, it drops packets not from or to whitelisted IP addresses.
6. Continuously monitors and filters traffic based on the user-defined rules.
7. The script can be terminated by pressing `Ctrl+C`.

**Note**: This script is intended for educational purposes or for use in controlled environments. Do not use it for malicious purposes.

## Example
To perform ARP spoofing on a network and filter traffic based on a blacklist, run the following command:

```bash
python3 main.py -b blacklist.txt -c 2
```

Replace `blacklist.txt` with the path to the file containing the blacklist.
