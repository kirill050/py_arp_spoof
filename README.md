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

```sh
sudo python3 setup.py install
```
> [!IMPORTANT]
> If an error occurs during the installation of a new version of the utility, please try deleting the directory mentioned in the example.
> The numbers in the directory name may vary depending on the installed version of Python.
```shell
sudo rm -rf /usr/local/lib/python3.12/dist-packages/setuptools-65.5.1-py3.12.egg
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

• --rotate_output_len <int>: (Optional) Enabling log rotating mode and specifying max size of them (Number of Mbytes).

**Example:**

To intercept all traffic circulated at net with gateway 192.168.1.1 visible through interface wlan12 and save result at Desktop/test.pcap:

```sh
sudo py_arp_spoof -i wlan12 -g 192.168.1.1 -w ~/Desktop/test.pcap
````
To spoof unidirectionally and quietly(only from the client to the external network):
```sh
sudo py_arp_spoof -i eth0 -q True
```
To run in background and stay running after ssh_logout
```sh
sudo nohup py_arp_spoof -i eth0 g 192.168.1.1 -w ~/Desktop/test.pcap &
```
**Stopping the script:**  Press "q" or "Q" or Ctrl+C to stop the ARP spoofing.
