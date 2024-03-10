from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP
import argparse
from datetime import datetime

'''
Sources:

1. https://stackoverflow.com/a/21926971
2. https://tls13.xargs.org/#client-key-exchange-generation

'''
def parse_tls_extensions(data, start_pos):
    """
    Parse TLS extensions from the given data starting at the specified position.
    """
    extensions = {}
    ext_pos = start_pos

    while ext_pos < len(data):
        ext_type = int.from_bytes(data[ext_pos:ext_pos + 2], byteorder='big')
        ext_length = int.from_bytes(data[ext_pos + 2:ext_pos + 4], byteorder='big')
        
        if ext_type == 0x00:  # Server Name Indication (SNI) extension
            sni_length = int.from_bytes(data[ext_pos + 7:ext_pos + 9], byteorder='big')
            sni = data[ext_pos + 9:ext_pos + 9 + sni_length].decode()
            extensions['sni'] = sni
        
        ext_pos += 4 + ext_length
    
    return extensions

def extract_tls_version(version_bytes):
    """
    Extracts the TLS version from the version bytes in the ClientHello message.
    """
    version_mapping = {
        b"\x03\x03": "TLS 1.2",
        b"\x03\x02": "TLS 1.1",
        b"\x03\x01": "TLS 1.0"
    }
    return version_mapping.get(version_bytes, None)

def parse_tls_client_hello(packet, data):
    
    try:
        if data[0] == 0x16:  # TLS Handshake message
            
            # Extract TLS version
            version = extract_tls_version(data[9:11])
            handshake_type = data[5]
            if handshake_type != 0x01:  # Check if it's a ClientHello
                return None, None

            # Extract session ID length and other relevant lengths
            session_id_length = data[43]
            cipher_suites_length = int.from_bytes(data[44 + session_id_length:44 + session_id_length + 2], byteorder='big')
            compression_methods_length = data[44 + session_id_length + 2 + cipher_suites_length]
            
            # Extract TLS extensions
            extensions_pos = 44 + session_id_length + 2 + cipher_suites_length + 1 + compression_methods_length + 2
            tls_extensions = parse_tls_extensions(data, extensions_pos)
            
            sni = tls_extensions.get('sni', None)
            
            return version, sni
    except Exception as e:
        print(f"Error parsing TLS Client Hello: {e}")
    return None, None

def parse_https_tls_callback(packet):
    if  packet.haslayer(HTTP):
        # If the packet contains HTTP layer
        http_layer = packet.getlayer(HTTP)

        if not http_layer:
            return None

        # Extracting necessary information from HTTP layer
        timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        src_ip, src_port = packet[IP].src, packet[TCP].sport
        dst_ip, dst_port = packet[IP].dst, packet[TCP].dport
        
        method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else None
        if method not in ('GET', 'POST'):
            return None

        host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else None
        path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else None

        if None in (timestamp, src_ip, src_port, dst_ip, dst_port, method, host, path):
            return None
        
        # Printing HTTP information
        print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {host} {method} {path}")

    elif packet.haslayer("TCP") and packet.haslayer("Raw"):
        # If the packet contains TCP and Raw layers (indicating it's likely a TLS handshake)
        
        version, sni = parse_tls_client_hello(packet, bytes(packet[Raw]))
        if sni:
            # Extracting necessary information from the TLS handshake
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"{timestamp} {version} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {sni}")     

def main():
    # Parsing command line arguments
    parser = argparse.ArgumentParser(description="HTTP/TLS connection monitoring")
    parser.add_argument("-i", metavar="interface", help="Live capture from the network device <interface> (e.g., eth0)")
    parser.add_argument("-r", metavar="tracefile", help="Read packets from <tracefile> (tcpdump format)")
    parser.add_argument("expression", nargs="?", help="BPF filter that specifies a subset of the traffic to be monitored")
    args = parser.parse_args()

    load_layer("http")

    # Handling tracefile or live capture
    if args.r:
        if args.expression:
            packets = sniff(offline=args.r, filter=args.expression, prn=parse_https_tls_callback)
            
        else:
            packets = rdpcap(args.r)
            for packet in packets:
                parse_https_tls_callback(packet)
    if args.i:
        packets = sniff(iface=args.i, filter=args.expression, prn=parse_https_tls_callback)
    if args.i == None and args.r == None:
        print('Starting on default interface: eth0')
        packets = sniff(iface=args.i, filter=args.expression, prn=parse_https_tls_callback)
        return

if __name__ == "__main__":
    main()
