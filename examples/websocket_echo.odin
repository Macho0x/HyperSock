package main

/*
 * Example: WebSocket Echo Client
 * Demonstrates basic WebSocket client usage
 */

import websocket "../hypersock_websocket"
import "core:fmt"
import "core:os"
import "core:time"

main :: proc() {
	fmt.println("=== WebSocket Echo Client Example ===")
	
	// Configure dialer
	dialer := websocket.Dialer {
		read_buffer_size = 1024,
		write_buffer_size = 1024,
	}
	
	// Connect to echo server (echo.websocket.org is a public test server)
	url := "wss://echo.websocket.org/"
	fmt.println("Connecting to:", url)
	
	conn, err := websocket.dial(url, &dialer)
	if err != os.ERROR_NONE {
		fmt.println("Failed to connect:", err)
		os.exit(1)
	}
	defer websocket.destroy_conn(conn)
	
	fmt.println("Connected!")
	
	// Send a message
	message := "Hello, WebSocket!"
	fmt.println("Sending:", message)
	
	err = websocket.write_message(conn, .Text, transmute([]byte)message)
	if err != os.ERROR_NONE {
		fmt.println("Failed to send:", err)
		os.exit(1)
	}
	
	// Read the echo response
	fmt.println("Waiting for response...")
	opcode, data, read_err := websocket.read_message(conn)
	if read_err != os.ERROR_NONE {
		fmt.println("Failed to read:", read_err)
		os.exit(1)
	}
	
	if opcode == .Text {
		fmt.println("Received:", string(data))
	}
	
	// Send close frame
	fmt.println("Closing connection...")
	close_err := websocket.write_message(conn, .Close, {})
	if close_err != os.ERROR_NONE {
		fmt.println("Error closing:", close_err)
	}
}
