# py-arp-spoof
![Static Badge](http://ForTheBadge.com/images/badges/made-with-python.svg)
![Static Badge](http://ForTheBadge.com/images/badges/built-with-love.svg)
![Static Badge](https://badgen.net/badge/routers_suffered_during_development/0/green?icon=awesome)

A simple and efficient Python script for ARP spoofing on Linux.  This script utilizes the `scapy` library for packet manipulation and requires root privileges for operation.

> [!CAUTION]
> **Disclaimer:** This tool is intended for educational and ethical hacking purposes only.  Using this script for unauthorized access or malicious activities is illegal and unethical.  I am not responsible for any misuse of this tool.

## Features

• **Simple and easy to use:**  The script is designed with a straightforward interface, making it easy to understand and utilize.

• **Efficient:**  Leverages `scapy` for optimal performance and minimal resource consumption.

• **Clear output:** Provides clear and concise output to the console, indicating progress and any errors encountered.

• **Supports both uni- and bidirectionally spoofing:** Offers flexibility to spoof either the client's ARP table or the gateway's ARP table too (requires specifying gateway IP address).

• **Security evasion:**  Allows running in silent mode, minimizing the number of packets being sent.


## Requirements

• **Python 3.x:** This script requires Python 3.x to run.

• **Scapy:** Install Scapy using `pip install scapy`

• **Rich:** Install Rich using `pip install rich`

## Installation

1. By setup.py...:
```sh
sudo ./setup.sh
source .venv/bin/activate
```
2. ...or Manually: 
```sh
git clone https://github.com/kirill050/py-arp-spoof.git
cd py-arp-spoof
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirments.txt
```   
## Usage
> [!NOTE]
> Before running the script, ensure you have root privileges (using sudo).  

The script accepts the following arguments:

• -i <interface>:  The network interface to use. **Required.**

• -g <gateway_ip>: (Optional) The IP address of the gateway.  If specified, the script will spoof bidirectionally, thus intercepting packets coming from outside the network as well.

• -w <filename.pcap>: (Optional) File for recording intercepted packets.  Result will be at captured_traffic.pcap.

• -v <bool>: (Optional) Enabling detailed logging (<b>True</b>/False).

• -q <bool>: (Optional) Enabling a more inconspicuous network interaction mode (True/<b>False</b>).

**Example:**

To intercept all traffic circulated at net with gateway 192.168.1.1 visible through interface wlan12 and save result at Desktop/test.pcap:

```sh
sudo python3 arp_spoof.py -i wlan12 -g 192.168.1.1 -w ~/Desktop/test.pcap
````
To spoof unidirectionally and quietly(only from the client to the external network):
```sh
sudo python3 arp_spoof.py -i eth0 -q True
```

**Stopping the script:**  Press Ctrl+C to stop the ARP spoofing.
