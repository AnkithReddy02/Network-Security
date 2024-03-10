import argparse
from scapy.all import sniff, ARP

import subprocess

def get_current_arp_cache():
    """
    Retrieves the current ARP cache entries of the host system (for macOS).
    """
    arp_cache = {}
    output = subprocess.check_output(['arp', '-a']).decode('utf-8')
    lines = output.splitlines()

    for line in lines:
        parts = line.split()
        if "at" in parts:  # Check if the line contains the MAC address
            ip_index = parts.index("at") - 1  # Index of the IP address is one less than the "at" keyword
            ip = parts[ip_index].strip('()')  # Remove parentheses from the IP address
            mac_index = parts.index("at") + 1  # Index of the MAC address is one more than the "at" keyword
            mac = parts[mac_index].strip('[]')
            arp_cache[ip] = mac
    return arp_cache


def arpwatch(interface):
    """
    Monitors ARP traffic on the specified interface and detects ARP cache poisoning attacks.
    """
    current_arp_cache = get_current_arp_cache()

    def arp_monitor_callback(pkt):
        if ARP in pkt and pkt[ARP].op in (1, 2):  # ARP who-has or ARP is-at
            arp_src_ip = pkt[ARP].psrc
            arp_src_mac = pkt[ARP].hwsrc
            if arp_src_ip in current_arp_cache and current_arp_cache[arp_src_ip] != arp_src_mac:
                print(f"{arp_src_ip} changed from {current_arp_cache[arp_src_ip]} to {arp_src_mac}")
                current_arp_cache[arp_src_ip] = arp_src_mac

    print(f"ARP monitoring started on interface {interface}")
    sniff(iface=interface, filter="arp", prn=arp_monitor_callback, store=0)

def main():
    parser = argparse.ArgumentParser(description="ARP cache poisoning detector")
    parser.add_argument("-i", "--interface", help="Live capture from the network device <interface> (e.g., eth0)")
    args = parser.parse_args()

    interface = args.interface if args.interface else "eth0"

    try:
        arpwatch(interface)
    except KeyboardInterrupt:
        print("ARP monitoring stopped")

if __name__ == "__main__":
    main()
