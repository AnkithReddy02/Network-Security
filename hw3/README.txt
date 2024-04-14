go mod init jumproxy.go
go mod tidy

server: go run test.go -k mykey -l 2222 localhost 22
client: ssh -o "ProxyCommand go run jumpproxy.go -k mykey 172.24.21.239 2222" ankith@localhost

All output is sent to the file 'logfile.log'