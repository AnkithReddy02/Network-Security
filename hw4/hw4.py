import argparse
import socket
import ssl
from scapy.all import sr, IP, TCP
import select
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP Service Fingerprinting Tool - synprobe")
    parser.add_argument("-p", "--port", help="Port range to scan, e.g., 80 or 80-100")
    parser.add_argument("target", help="IP address of the target host")
    return parser.parse_args()


def syn_scan(host, port_range):
    ports = range(int(port_range.split('-')[0]), int(port_range.split('-')[1])+1) if '-' in port_range else [int(port_range)]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # Set a timeout for the connection attempt
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"Port {port} is open.")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

def receive_data(sock, timeout=3):
    sock.setblocking(0)
    total_data = []
    while True:
        try:

            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                break  # No more data available
            data = sock.recv(1024)
            if not data:
                break  # No more data to read
            total_data.append(data)
        except ssl.SSLWantReadError:
            continue
        
    return b''.join(total_data) if total_data else None

import traceback

def send_probe(ip, port, message, use_tls=False):
    try:
        print(f"Connecting to {ip}:{port} using {'TLS' if use_tls else 'TCP'}")
        sock = socket.create_connection((ip, port), timeout=3)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip, do_handshake_on_connect=False)
            if not sock:
                print("Sock is None")
            sock.do_handshake()
        sock.sendall(message.encode())
        return receive_data(sock), 'TLS' if use_tls else 'TCP'
    except socket.timeout:
        print(f"Timeout connecting to {ip}:{port}")
        return None, 'Timeout'
    except ssl.SSLError as e:
        print(f"SSL error during connection to {ip}:{port}: {e}")
        traceback.print_exc()
        return None, 'SSL'
    except socket.error as e:
        print(f"Socket error during probe to {ip}:{port}: {e}")
        traceback.print_exc()
        return None, 'Socket'
    except Exception as e:
        print(f"General exception during probe to {ip}:{port}: {e}")
        return None, 'Error'
    finally:
        if sock:
            try:
                sock.close()
            except socket.error as e:
                print(f"Error closing socket for {ip}:{port}: {e}")


def print_response(response):
    if response:
        # Replace non-printable bytes with '.'
        printable_response = ''.join([chr(c) if 32 <= c <= 126 else '.' for c in response])
        print(printable_response[:1024])
    else:
        print("No response received")

def probe_port(ip, port):
    probes = [
        
        ("TLS server-initiated", "", True),
        ("TLS client-initiated", "GET / HTTP/1.0\r\n\r\n", True),
        ("Generic TLS server", "\r\n\r\n\r\n\r\n", True),
        ("TCP server-initiated", "", False),
        ("TCP client-initiated", "GET / HTTP/1.0\r\n\r\n", False),
        ("Generic TCP server", "\r\n\r\n\r\n\r\n", False),
    ]
    for description, data, use_tls in probes:
        response, status = send_probe(ip, port, data, use_tls)
        if description == 'Generic TLS server' and status == 'TLS':
            if response:
                print(f"Port {port}: {description} -")
                print_response(response)
            else:
                print(f"Port {port}: {description} -")
                print('None')

            break

        if description == 'Generic TCP server' and status == 'TCP':
            if response:
                print(f"Port {port}: {description} -")
                print_response(response)
            else:
                print(f"Port {port}: {description} -")
                print('None')

            break

        if response:
            print(f"Port {port}: {description} -")
            print_response(response)
            break  # assuming you want to stop after the first response


def main():
    args = parse_arguments()
    target = args.target
    port_range = args.port if args.port else "21,22,23,25,80,110,143,443,587,853,993,3389,8080"
    
    if '-' not in port_range and ',' not in port_range:
        port_range = f"{port_range}-{port_range}"
        open_ports = syn_scan(target, port_range)
        for port in open_ports:
            probe_port(target, port)
    elif ',' in port_range:
        for p in port_range.split(','):
            open_ports = syn_scan(target, p.strip())
            for port in open_ports:
                probe_port(target, port)
    else:
        open_ports = syn_scan(target, port_range)
        for port in open_ports:
            probe_port(target, port)

if __name__ == "__main__":
    main()
