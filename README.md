# TCP_SYN_Flood_Detection


This README provides instructions on how to run the Detector code.

## Table of Contents

 [TCP_SYN_Flood_Detection](#TCP_SYN_Flood_Detection)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Installation Steps](#installation-steps)
  - [Running the code](#running-the-code)
  - [Limitations](#limitations)
  - [References](#References)

## Installation

### Prerequisites

Before installing Scapy, make sure you have the following prerequisites:

1. **Python**: Scapy requires Python 3.x. Make sure you have Python installed on your system. You can download Python from the official website: [Python Downloads](https://www.python.org/downloads/).

2. **Pip**: Pip is the package manager for Python. It's usually included with Python, so you should have it available. You can check if Pip is installed by running `pip --version` in your terminal/command prompt.

### Installation Steps

1. From your terminal or command prompt, install Scapy using pip by running the following command:
```
pip install scapy.
```
This will download and install Scapy and its dependencies.

2. Once the installation is complete, you can clone our code using the command:
```
git clone https://github.com/HadiElNawfal/TCP_SYN_Flood_Detection
```

## Running the code

1. Run `python Detector.py -h` to see the help page

2. The usage would be: `python Detector.py -t [IP]`

The script will detect:
1.  SYN Flood attacks that are coming from single IP address as source
2.  SYN Flood attacks that are coming from randomly spoofed IP on subnet (doesn't have to be assigned)
3.  SYN Flood attack that are coming from spoofed real IP (hosts that are on the subnet)

## Limitations

1. No Interface Specification:
The sniff() function does not specify a network interface (iface), which may result in unexpected behavior on multi-interface systems (e.g. sniffing only loopback by default).
2. Single Host Focus:
The code only detects attacks targeting one IP (--target). SYN floods affecting multiple targets simultaneously will go unnoticed.
3. Only SYN Detection:
It detects only TCP SYN floods, and ignores ACK floods, FIN/RST floods, and Layer 7 (application-level) floods

## References
[Tcp Syn Flood Attack Detection and Prevention System using
Adaptive Thresholding Method](https://doi.org/10.1051/itmconf/20213701016) for adaptive threshold formula
