package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	mode := flag.String("mode", "", "server or client")
	port := flag.Int("port", 8088, "UDP port")
	targetIP := flag.String("target", "", "Target IP for client mode")
	bindIP := flag.String("bind", "0.0.0.0", "IP to bind to")
	flag.Parse()

	if *mode == "server" {
		runServer(*bindIP, *port)
	} else if *mode == "client" {
		if *targetIP == "" {
			fmt.Println("Usage: udptest -mode client -target <IP> [-port 8088]")
			os.Exit(1)
		}
		runClient(*targetIP, *port)
	} else {
		fmt.Println("Usage:")
		fmt.Println("  Server: udptest -mode server [-bind 10.100.0.2] [-port 8088]")
		fmt.Println("  Client: udptest -mode client -target 10.100.0.2 [-port 8088]")
	}
}

func runServer(bindIP string, port int) {
	addr := fmt.Sprintf("%s:%d", bindIP, port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Printf("Failed to listen on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("UDP server listening on %s\n", addr)
	fmt.Println("Waiting for packets... (press Ctrl+C to stop)")

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Read error: %v\n", err)
			continue
		}

		fmt.Printf("[%s] Received %d bytes from %s: %s\n",
			time.Now().Format("15:04:05.000"),
			n, remoteAddr.String(), string(buf[:n]))

		// Echo back
		response := fmt.Sprintf("PONG from server at %s", time.Now().Format("15:04:05.000"))
		conn.WriteTo([]byte(response), remoteAddr)
		fmt.Printf("[%s] Sent response to %s\n",
			time.Now().Format("15:04:05.000"), remoteAddr.String())
	}
}

func runClient(targetIP string, port int) {
	targetAddr := fmt.Sprintf("%s:%d", targetIP, port)
	conn, err := net.Dial("udp", targetAddr)
	if err != nil {
		fmt.Printf("Failed to connect to %s: %v\n", targetAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Sending UDP packets to %s\n", targetAddr)
	fmt.Printf("Local address: %s\n", conn.LocalAddr().String())

	for i := 1; i <= 10; i++ {
		msg := fmt.Sprintf("PING #%d from client at %s", i, time.Now().Format("15:04:05.000"))

		_, err := conn.Write([]byte(msg))
		if err != nil {
			fmt.Printf("Send error: %v\n", err)
			continue
		}
		fmt.Printf("[%s] Sent: %s\n", time.Now().Format("15:04:05.000"), msg)

		// Wait for response
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Printf("[%s] No response (timeout or error: %v)\n",
				time.Now().Format("15:04:05.000"), err)
		} else {
			fmt.Printf("[%s] Received: %s\n",
				time.Now().Format("15:04:05.000"), string(buf[:n]))
		}

		time.Sleep(1 * time.Second)
	}

	fmt.Println("\nTest complete!")
}
