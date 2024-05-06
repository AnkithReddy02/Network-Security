import argparse
import socket
import ssl
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import traceback

states = ["1. TCP server-initiated", "2. TLS server-initiated", "3. HTTP - TCP client-initiated", "4. HTTPS - TLS client-initiated", "5. Generic TCP server", "6. Generic TLS server" ]

def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP Service Fingerprinting Tool - synprobe")
    parser.add_argument("-p", "--port", help="Port range to scan, e.g., 80 or 80-100")
    parser.add_argument("target", help="IP address of the target host")
    return parser.parse_args()

def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((host, port))
            if result == 0:
                return port, True
    except Exception as e:
        return port, False
    return port, False

def syn_scan(host, port_range):
    ports = range(int(port_range.split('-')[0]), int(port_range.split('-')[1]) + 1) if '-' in port_range else [int(port_range)]
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(check_port, host, port): port for port in ports}
        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                logging.info(f"Port {port} is open.")
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

def send_probe(ip, port, message, description, use_tls=False):
    try:
        logging.info(f"{description} : Connecting to {ip}:{port} using {'TLS' if use_tls else 'TCP'}")
        sock = socket.create_connection((ip, port), timeout=3)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip, do_handshake_on_connect=False)
            if not sock:
                logging.error("Sock is None")
            sock.do_handshake()
        sock.sendall(message.encode())
        return receive_data(sock), 'TLS' if use_tls else 'TCP'
    except socket.timeout:
        logging.exception(f"Timeout connecting to {ip}:{port}")
        return None, 'Timeout'
    except ssl.SSLError as e:
        logging.exception(f"SSL error during connection to {ip}:{port}: {e}")
        # traceback.print_exc()
        return None, 'SSL'
    except socket.error as e:
        logging.exception(f"Socket error during probe to {ip}:{port}: {e}")
        # traceback.print_exc()
        return None, 'Socket'
    except Exception as e:
        logging.exception(f"General exception during probe to {ip}:{port}: {e}")
        return None, 'Error'
    finally:
        if sock:
            try:
                sock.close()
            except socket.error as e:
                logging.exception(f"Error closing socket for {ip}:{port}: {e}")

def print_response(response):
    if response:
        # Replace non-printable bytes with '.'
        printable_response = ''.join([chr(c) if 32 <= c <= 126 else '.' for c in response])
        print('Data: ', printable_response[:1024])
        print('\n\n')
    else:
        logging.error("No response received!!")

def probe_port(ip, port):
    probes = [
        (1, "", True),
        (3, "GET / HTTP/1.0\r\n\r\n", True),
        (5, "\r\n\r\n\r\n\r\n", True),
        (0, "", False),
        (2, "GET / HTTP/1.0\r\n\r\n", False),
        (4, "\r\n\r\n\r\n\r\n", False),
    ]
    for state_num, data, use_tls in probes:
        response, status = send_probe(ip, port, data, states[state_num], use_tls)
        if state_num == 5 and status == 'TLS':
            if response:
                print(f"\n\nPort {port}: {states[state_num]} -")
                print_response(response)
            else:
                print(f"\n\nPort {port}: {states[state_num]} -")
                print('Data: ', None)
                print('\n\n')

            break

        if state_num == 4 and status == 'TCP':
            if response:
                print(f"\n\nPort {port}: {states[state_num]} -")
                print_response('Data: ', response)
            else:
                print(f"\n\nPort {port}: {states[state_num]} -")
                print('Data: ', None)
                print('\n\n')

            break

        if response:
            print(f"\n\nPort {port}: {states[state_num]} -")
            print_response(response)

            break

def configure_logger():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='synprobe.log',
        filemode='w'
    )

def main():
    configure_logger()
    args = parse_arguments()
    target = args.target
    port_range = args.port if args.port else "21,22,23,25,80,110,143,443,587,853,993,3389,8080"

    print('Computing Open Ports [takes <50 seconds]...')
    
    if '-' not in port_range and ',' not in port_range:
        port_range = f"{port_range}-{port_range}"
        open_ports = syn_scan(target, port_range)
        print('Open Ports: ', open_ports)
        for port in open_ports:
            probe_port(target, port)
    elif ',' in port_range:
        open_ports = []
        for p in port_range.split(','):
            current_open_ports = syn_scan(target, p.strip())
            for open_port in current_open_ports:
                open_ports.append(open_port)
        print('Open Ports: ', open_ports)    
        for port in open_ports:
            probe_port(target, port)
    else:
        open_ports = syn_scan(target, port_range)
        print('Open Ports: ', open_ports)
        for port in open_ports:
            probe_port(target, port)

if __name__ == "__main__":
    main()
