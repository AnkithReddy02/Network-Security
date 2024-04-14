Initial Setup

go mod init jumpproxy
go mod tidy
go build .

server: ./jumpproxy -k mykey -l SERVER_PORT localhost 22
client: ssh -o "ProxyCommand ./jumpproxy -k mykey SERVER_IP SERVER_PORT" server_username@localhost

Testcase:
wget https://raw.githubusercontent.com/dscape/spell/master/test/resources/big.txt
cat big.txt

Code Structure and Brief Description

1. All output is sent to the file 'logfile.log'

Structure:

1. crypto.go --> contains methods for encryption, decryptiona and key generation.
2. start_client.go --> code for starting the client.
3. start_server.go --> code for starting the server.
4. preprocess.go --> code for setting up the logging file, extracting command line arguments and error handling
5. transfer_data.go --> code for transferring encrypted data from client to server and vice versa. Also, for decrypting the data.
6. logfile.log --> All the logs are stored in this file.
7. mykey --> File that contains passphrase.
8. jumpproxy.go --> Main code that starts either client or server based on the arguments provided.

Brief Description:

1. Based on the command line arguments such as as listen port, the program starts either Client or Server.
2. Client --> Server
    Write --> Socket1, Read --> stdin:
        1. The Client mode starts reading the data from *stdin*[max. of 1024 bytes](whatever the user types in the terminal).
        2. The received data is encrypted, which is prefixed with the block length.
        3. The data(along with prefix length) is written to *socket1*
    
    Read --> Socket1, Write --> stdout:
        1. Read the first 4 bytes(that represents the length of the encrypted data)
        2. Decrypt the data with given length.
        3. Writes the decrypted data to *stdout*

3. Server --> Client:
    Write --> Socket1, Read --> Socket2:
        1. The Server mode starts reading the data from **socket2**.
        2. The received data is encrypted, which is prefixed with the block length.
        3. The data(along with prefix length) is written to *socket1*

    Read --> Socket1, Write --> Socket2:
        1. Read the first 4 bytes(that represents the length of the encrypted data) from socket1.
        2. Decrypt the data with given length.
        3. Writes the decrypted data to *socket2*

Sources:
GPT, Stackoverflow