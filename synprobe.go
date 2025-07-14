package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"time"
)

func main() {
	// Argparse
	portInput := flag.String("p", "", "Port/port range to scan e.g 0-100 or 98")
	flag.Parse()

	target := flag.Arg(0)
	if target == "" {
		fmt.Println("Host IP required to scan. e.g 192.168.0.1 or www.cs.stonybrook.edu")
		return
	}

	// Parse ports
	var portList []int
	var startPort, endPort int
	if *portInput != "" {
		n, err := fmt.Sscanf(*portInput, "%d-%d", &startPort, &endPort)
		if err != nil || n != 2 {
			// One port
			portList = []int{startPort}
		} else {
			// Port range
			portList = make([]int, endPort-startPort+1)
			for i := range portList {
				portList[i] = startPort + i
			}
		}
	} else {
		// Default to commonly used TCP ports
		portList = []int{21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080}
	}

	// Perform SYN scan
	openPorts := scanOpenPorts(target, portList)

	// Fingerprint all open ports
	for _, port := range openPorts {
		fmt.Printf("Fingerprinting port %d.\n", port)

		// Fingerprint TLS first
		tlsType, tlsData := fingerprintTLS(target, port)
		if tlsType != "" {
			fmt.Printf("Port %d: %s\n", port, tlsType)
			fmt.Printf("Data: %s\n", tlsData)
			continue
		}

		// Fingerprint TCP
		tcpType, tcpData := fingerprintTCP(target, port)
		if tcpType != "" {
			fmt.Printf("Port %d: %s\n", port, tcpType)
			fmt.Printf("Data: %s\n", tcpData)
			continue
		}
	}
}

// Scan for open ports and return list
func scanOpenPorts(target string, portList []int) []int {
	fmt.Printf("Scanning %s on port(s) %v\n", target, portList)
	openPorts := []int{}

	for _, port := range portList {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.Dial("tcp", address)

		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	fmt.Printf("Open ports: %v\n", openPorts)
	return openPorts
}

// Fingerprint as TCP service
func fingerprintTCP(target string, port int) (string, []byte) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)

	if err != nil {
		return "", nil
	}
	defer conn.Close()

	// Check server-init
	data := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(data)
	if n > 0 && err == nil {
		return "TCP server-initiated", data[:1024]
	}

	// Check client-init
	_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err = conn.Read(data)
		if n > 0 && err == nil {
			return "TCP client-initiated", data[:1024]
		}
	}

	// // Check generic TCP
	_, err = conn.Write([]byte("\r\n\r\n\r\n\r\n"))
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err = conn.Read(data)
		if n > 0 && err == nil {
			return "Generic TCP server", data[:1024]
		}
	}

	return "Generic TCP server", nil
}

// Function to check TLS service
func fingerprintTLS(target string, port int) (string, []byte) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)

	if err != nil {
		return "", nil
	}
	defer conn.Close()

	// TLS wrapping and handshake
	config := tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target,
	}

	tlsConn := tls.Client(conn, &config)
	err = tlsConn.Handshake()
	if err != nil {
		return "", nil
	}

	// Check server-init
	data := make([]byte, 1024)
	tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := tlsConn.Read(data)
	if n > 0 && err == nil {
		return "TLS server-initiated", data[:1024]
	}

	// Check client-init
	_, err = tlsConn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	if err == nil {
		tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err = tlsConn.Read(data)
		if n > 0 && err == nil {
			return "TLS client-initiated", data[:1024]
		}
	}

	// Check generic TLS
	_, err = tlsConn.Write([]byte("\r\n\r\n\r\n\r\n"))
	if err == nil {
		tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err = tlsConn.Read(data)
		if n > 0 && err == nil {
			return "Generic TLS server", data[:1024]
		}

	}

	return "Generic TLS server", nil
}
