# FragEva6-Guard: High-Performance IPv6 Fragment Evasion Threat Detection Method Based on eBPF and XDP
We have developed FragEva6-Guard, a high-performance and flexible framework based on eBPF and XDP, designed for detecting and mitigating IPv6 fragment evasion threats. Using this framework, you can implement custom parsing programs for other IPv6 extension header threats.
This project implements an XDP-based solution to prevent IPv6 fragmentation attacks and includes a baseline program for comparison.

## Dependencies

### System Requirements
- Linux operating system with XDP support
- Clang compiler
- Python 3

### Python Libraries
- scapy
- netfilterqueue

### C Libraries
- linux/bpf.h
- bpf/bpf_helpers.h
- linux/if_ether.h
- linux/ipv6.h

## Installation
1. Install the required system packages:
   sudo apt-get update
   sudo apt-get install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
2. Install the required Python libraries:
   pip3 install scapy netfilterqueue

## Running the Program
### FragEva6-Guard (XDP Program)

1. Clone the repository and navigate to the project directory.

2. Make the initialization script executable:
   chmod +x init.sh
3. Run the initialization script:
   bash ./init.sh
Note: Replace 'ens33' in the script with your network interface name if different.

### Baseline Program
1. Run the baseline program:
   python3 baseline.py
   
## Notes

- The XDP program (FragEva6-Guard) is written in C and compiled using Clang.
- The baseline program is written in Python and uses Scapy for packet manipulation.
- Ensure you have the necessary permissions to run these programs, as they require root access for network operations.
- The XDP program attaches to a specific network interface. Make sure to use the correct interface name in the initialization script.
