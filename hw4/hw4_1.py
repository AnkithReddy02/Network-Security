import argparse
import socket
import ssl
import select
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP Service Fingerprinting Tool - synprobe")
    parser.add_argument("-p", "--port", help="Port range to scan, e.g., 80 or 80-100")
    parser.add_argument("target", help="IP address of the target host")
    return parser.parse_args()

def syn_scan(host, port_range):
    ports = range(int(port_range.split('-')[0]), int(port_range.split('-')[1]) + 1) if '-' in port_range else [int(port_range)]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"Port {port} is open.")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

def receive_data(sock, timeout=3):
    sock.setblocking(0)
    try:
        ready = select.select([sock], [], [], timeout)
        if ready[0]:
            data = sock.recv(1024)
            return data if data else "No data received"
    except Exception as e:
        return None
    return "No response"

def send_probe(ip, port, message, use_tls=False):
    try:
        sock = socket.create_connection((ip, port), timeout=3)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.sendall(message.encode())
        return receive_data(sock)
    except Exception as e:
        return f"Send Probe Exception: {str(e)}"
    finally:
        sock.close()

def probe_port(ip, port):
    probes = {
        "TLS server-initiated": ("", True),
        "TLS client-initiated": ("GET / HTTP/1.0\r\n\r\n", True),
        "Generic TLS server": ("\r\n\r\n\r\n\r\n", True),
        "TCP server-initiated": ("", False),
        "TCP client-initiated": ("GET / HTTP/1.0\r\n\r\n", False),
        "Generic TCP server": ("\r\n\r\n\r\n\r\n", False)
    }
    for desc, (probe, tls) in probes.items():
        response = send_probe(ip, port, probe, tls)
        if response and response not in ["No response", "No data received", "Error"]:
            print(f"Port {port}: {desc} - {response.decode('utf-8', 'replace')[:1024]}")
        else:
            print(f"Port {port}: {desc} - {response}")

def main():
    args = parse_arguments()
    target = args.target
    port_range = args.port if args.port else "80-100"

    if '-' not in port_range and ',' not in port_range:
        port_range = f"{port_range}-{port_range}"

    if ',' in port_range:
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
