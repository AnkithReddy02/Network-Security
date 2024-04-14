go mod init jumpproxy
go mod tidy
go build .

server: ./jumpproxy -k mykey -l 2222 localhost 22
client: ssh -o "ProxyCommand go run ./jumpproxy -k mykey SERVER_IP" server_username@localhost

All output is sent to the file 'logfile.log'