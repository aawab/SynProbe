Aawab Mahmood
Network Scanning and Fingerprinting

No external libraries used

go.mod included for anything necessary

no need to run go build, can just use sudo go run 

-----------------------

To run: 

cd to project directory, then run the following, replacing <target> with ip/address and <port> with port num or range
in form of x-y

sudo go run synprobe.go -p <port> <target> 

-----------------------

Implementation:

Everything is done in one file, synprobe.go. I've separated the functionality in the main() function
along with two fingerprinting functions for each of the TCP/TLS service types. I've also separated the
fingerprinting and port scanning - scanOpenPorts is the function used for that. Details below:

scanOpenPorts(target string, portList []int): 
- Given target and portlist, dials the target at each port
- If dial goes smoothly with no errors, then it is open and able to be fingerprinted
- Returns a list of the openport numbers

fingerprintTCP(target string, port int):
- Given target and port number, dials the target at the port
- Once dial goes smoothly, reads first 1024 to check server-init. If so, return with data and type of service
- If not server-init, writes a GET request with two enters to the server and waits to read 1024 and if so, it's client-init
- If not client-init, writes generic lines to the server to check generic TCP service

fingerprintTLS(target string, port int):
- Does the same as TCP but wraps the connection in TLS and performs the handshake before reading anything

