Source Code: synprobe.py
Logs: synprobe.log

Usage: sudo python3 synprobe.py [-p PORT_RANGE or SINGLE_PORT] target
Look for sample runs at the end.

****************************************************************************
                            DESIGN
****************************************************************************

1. SYN Scanning (`syn_scan` Function):
   - This function takes a hostname and a port range as input.
   - It uses a `ThreadPoolExecutor` to scan multiple ports concurrently to check their status (open or closed).
   - Each port's status is determined by attempting to establish a connection using the `check_port` function. If a connection is successful (i.e., the port is open), it logs the information and returns the port as open.

2. Service Fingerprinting (`probe_port` Function):
   - For each port that is found to be open in the `syn_scan`, the `probe_port` function is called.
   - This function sends different probes to the open port based on predefined states (like TCP or TLS connections, sending HTTP requests, etc.).
   - It logs and processes responses from the server to identify and fingerprint the service running on that port. This includes interpreting the response to determine if it matches expected patterns for known services.

3. Main Workflow (`main` Function):
   - The `main` function coordinates the entire process. It starts by configuring logging, then parses command-line arguments to get the target IP and port range.
   - It calls `syn_scan` to identify open ports.
   - For each open port returned by `syn_scan`, `probe_port` is then called to perform detailed fingerprinting.
   - This is an example of combining both SYN scanning and service fingerprinting in a single execution sequence but managing them via separate functions for clarity and modular coding.

****************************************************************************
                            Order of Probe Requests
****************************************************************************

1. TLS Server Initiated
2. TLS Client Initiated
3. Generic TLS
4. TCP Server Initiated
5. TCP Client Initiated
6. Generic TCP

TLS works on TCP.

----------------------------------------------------------------------------------

*** Sample Runs ***

****************************************************************************
                            Port - Range Test
****************************************************************************

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 1-1000 smtp.gmail.com
Password:
Computing Open Ports [takes <50 seconds]...
Open Ports:  [465, 587, 993, 995]


Port 465: 2. TLS server-initiated -
Data:  220 smtp.gmail.com ESMTP n10-20020a05620a222a00b007929914d7cbsm532919qkh.81 - gsmtp..





Port 587: 1. TCP server-initiated -
Data:  220 smtp.gmail.com ESMTP c10-20020ac8660a000000b004372541e823sm4570607qtp.79 - gsmtp..





Port 993: 2. TLS server-initiated -
Data:  * OK Gimap ready for requests from 130.245.192.1 gy4mb128454729qvb..





Port 995: 2. TLS server-initiated -
Data:  +OK Gpop ready for requests from 130.245.192.1 c34mb5386853vsv..

----------------------------------------------------------------------------------

****************************************************************************
                            TCP - Server Initiated
****************************************************************************

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 21 ftp.dlptest.com   
Computing Open Ports [takes <50 seconds]...
Open Ports:  [21]


Port 21: 1. TCP server-initiated -
Data:  220 Welcome to the DLP Test FTP Server..

----------------------------------------------------------------------------------

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 130 compute.cs.stonybrook.edu
Computing Open Ports [takes <50 seconds]...
Open Ports:  [130]


Port 130: 1. TCP server-initiated -
Data:  SSH-2.0-OpenSSH_7.4..

----------------------------------------------------------------------------------

****************************************************************************
                            TCP - Client Initiated
****************************************************************************


ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 80 cs.stonybrook.edu         
Computing Open Ports [takes <50 seconds]...
Open Ports:  [80]


Port 80: 3. HTTP - TCP client-initiated -
Data:  HTTP/1.1 404 Unknown site..Connection: close..Content-Length: 566..Retry-After: 0..Server: Pantheon..Cache-Control: no-cache, must-revalidate..Content-Type: text/html; charset=utf-8..X-pantheon-serious-reason: The page could not be loaded properly...Date: Mon, 06 May 2024 01:12:42 GMT..X-Served-By: cache-lga21956-LGA..X-Cache: MISS..X-Cache-Hits: 0..X-Timer: S1714957963.521976,VS0,VE32..Vary: Cookie..Age: 0..Accept-Ranges: bytes..Via: 1.1 varnish....<!DOCTYPE HTML>.      <html>.        <head>.          <title>404 - Unknown site</title>.        </head>.        <body style="font-family:Arial, Helvetica, sans-serif; text-align: center">.          <div style='padding-block: 180px'>.            <h1>.              <div style='font-size: 180px; font-weight: 700'>404</div>.              <div style='font-size: 24px; font-weight: 700'>Unknown site</div>.            </h1>.            <p style="font-size: 16px; font-weight: 400">The page could not be loaded properly.</p>.          </div>.        </body>.      </html>

----------------------------------------------------------------------------------

****************************************************************************
                            TLS - Server Initiated
****************************************************************************

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 465 smtp.gmail.com  
Computing Open Ports [takes <50 seconds]...
Open Ports:  [465]


Port 465: 2. TLS server-initiated -
Data:  220 smtp.gmail.com ESMTP fj15-20020a05622a550f00b00434946547d3sm4552861qtb.53 - gsmtp..

----------------------------------------------------------------------------------

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 993 imap.gmail.com
Computing Open Ports [takes <50 seconds]...
Open Ports:  [993]


Port 993: 2. TLS server-initiated -
Data:  * OK Gimap ready for requests from 130.245.192.1 jq8mb113840478qvb..

----------------------------------------------------------------------------------

****************************************************************************
                            TLS - Client Initiated
****************************************************************************

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 443 cs.stonybrook.edu
Computing Open Ports [takes <50 seconds]...
Open Ports:  [443]


Port 443: 4. HTTPS - TLS client-initiated -
Data:  HTTP/1.1 404 Unknown site..Connection: close..Content-Length: 566..Retry-After: 0..Server: Pantheon..Cache-Control: no-cache, must-revalidate..Content-Type: text/html; charset=utf-8..X-pantheon-serious-reason: The page could not be loaded properly...Date: Mon, 06 May 2024 01:15:40 GMT..X-Served-By: cache-lga21970-LGA..X-Cache: MISS..X-Cache-Hits: 0..X-Timer: S1714958140.039608,VS0,VE34..Vary: Cookie..Age: 0..Accept-Ranges: bytes..Via: 1.1 varnish....<!DOCTYPE HTML>.      <html>.        <head>.          <title>404 - Unknown site</title>.        </head>.        <body style="font-family:Arial, Helvetica, sans-serif; text-align: center">.          <div style='padding-block: 180px'>.            <h1>.              <div style='font-size: 180px; font-weight: 700'>404</div>.              <div style='font-size: 24px; font-weight: 700'>Unknown site</div>.            </h1>.            <p style="font-size: 16px; font-weight: 400">The page could not be loaded properly.</p>.          </div>.        </body>.      </html>

----------------------------------------------------------------------------------

****************************************************************************
                            TLS - Generic
****************************************************************************

ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 853 8.8.8.8 
Computing Open Ports [takes <50 seconds]...
Open Ports:  [853]


Port 853: 6. Generic TLS server -
Data:  None
----------------------------------------------------------------------------------

****************************************************************************
                            TCP - Generic
****************************************************************************

ankithreddy@Ankiths-MacBook-Air hw4 % brew services start postgresql@14
==> Successfully started `postgresql@14` (label: homebrew.mxcl.postgresql@14)
ankithreddy@Ankiths-MacBook-Air hw4 % sudo python3 synprobe.py -p 5432 localhost
Computing Open Ports [takes <50 seconds]...
Open Ports:  [5432]


Port 5432: 5. Generic TCP server -
Data:  None

----------------------------------------------------------------------------------