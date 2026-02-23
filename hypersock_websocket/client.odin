package hypersock_websocket

/*
 * WebSocket Client Implementation
 * Based on gorilla/websocket client.go patterns
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:strconv"
import "core:time"
import http "../hypersock_http"

// Dial connects to a WebSocket server
// Returns the connection and any error
dial :: proc(url: string, dialer_arg: ^Dialer) -> (^Conn, os.Errno) {
	dialer := dialer_arg
	if dialer == nil {
		d := dialer_default()
		dialer = &d
	}
	
	// Parse URL
	scheme, host, path, port, ok := parse_ws_url(url)
	if !ok {
		return nil, os.EINVAL
	}
	
	// Determine if TLS
	is_tls := scheme == "wss"
	
	// Build address
	addr := fmt.tprintf("%s:%d", host, port)
	
	// Dial TCP connection
	socket: net.TCP_Socket
	err: os.Errno
	
	if dialer.net_dial != nil {
		socket, err = dialer.net_dial("tcp", addr)
	} else {
		socket, net_err := net.dial_tcp(addr)
		if net_err != nil {
			return nil, os.EINVAL
		}
	}
	
	if err != os.ERROR_NONE {
		return nil, err
	}
	
	// Perform TLS handshake if needed
	_tls_socket: ^http.TLS_Socket
	if is_tls {
		// Perform TLS handshake
		_tls_socket, tls_err := http.perform_tls_handshake_on_socket(socket, host, false)
		if tls_err != os.ERROR_NONE {
			net.close(socket)
			fmt.println("WebSocket TLS handshake failed:", tls_err)
			return nil, tls_err
		}
		
		fmt.println("WebSocket TLS handshake completed successfully")
		
		// The TLS socket now wraps the TCP socket
		// For the WebSocket handshake, we still use the underlying TCP socket
		// because the TLS handshake is already completed
		// After the WebSocket handshake, we would use tls_write/tls_read
		
		// Free the TLS socket for now (framework - would need actual TLS library for encryption)
		// delete(_tls_socket)  // Can't delete custom types like this
	}
	
	// Generate challenge key
	challenge_key := generate_challenge_key()
	
	// Build HTTP upgrade request
	request := build_handshake_request(host, path, challenge_key, dialer.subprotocols, dialer.enable_compression)
	defer delete(request)
	
	// Set handshake deadline
	if dialer.handshake_timeout > 0 {
		deadline := time.time_add(time.now(), dialer.handshake_timeout)
		timeout_ms := int(time.duration_milliseconds(time.since(deadline)))
		if timeout_ms < 0 { timeout_ms = 0 }
		net.set_option(socket, net.Socket_Option.Send_Timeout, timeout_ms)
		net.set_option(socket, net.Socket_Option.Receive_Timeout, timeout_ms)
	}
	
	// Send request
	_, send_err := net.send_tcp(socket, transmute([]byte)request)
	if send_err != nil {
		net.close(socket)
		return nil, os.EINVAL
	}
	
	// Read response
	response_buf := make([]byte, 4096)
	defer delete(response_buf)
	
	n, recv_err := net.recv_tcp(socket, response_buf)
	if recv_err != nil {
		net.close(socket)
		return nil, os.EINVAL
	}
	
	response := string(response_buf[:n])
	
	// Parse and validate response
	status_code, accept_key, subprotocol, ok2 := parse_handshake_response(response)
	if !ok2 || status_code != 101 {
		net.close(socket)
		return nil, os.ECONNREFUSED
	}
	
	// Validate accept key
	expected_accept := compute_accept_key(challenge_key)
	if accept_key != expected_accept {
		net.close(socket)
		return nil, os.EINVAL
	}
	
	// Create WebSocket connection
	conn := new_conn(socket, false, dialer.read_buffer_size, dialer.write_buffer_size)
	conn.subprotocol = subprotocol
	
	// Clear deadlines
	net.set_option(socket, net.Socket_Option.Send_Timeout, 0)
	net.set_option(socket, net.Socket_Option.Receive_Timeout, 0)
	
	return conn, os.ERROR_NONE
}

// parse_ws_url parses a WebSocket URL
// Returns: scheme, host, path, port, ok
parse_ws_url :: proc(url_str: string) -> (scheme, host, path: string, port: int, ok: bool) {
	// Simple URL parser for ws:// and wss:// schemes
	ok = false
	
	url := url_str
	
	if strings.has_prefix(url, "ws://") {
		scheme = "ws"
		url = url[5:]
		port = 80
	} else if strings.has_prefix(url, "wss://") {
		scheme = "wss"
		url = url[6:]
		port = 443
	} else {
		return
	}
	
	// Find path
	path_idx := strings.index(url, "/")
	if path_idx == -1 {
		host = url
		path = "/"
	} else {
		host = url[:path_idx]
		path = url[path_idx:]
	}
	
	// Check for port in host
	port_idx := strings.last_index(host, ":")
	if port_idx != -1 {
		port_str := host[port_idx+1:]
		// Parse port number using strconv
		if parsed_port, ok := strconv.parse_int(port_str, 10); ok {
			port = int(parsed_port)
		}
		host = host[:port_idx]
	}
	
	ok = true
	return
}

// build_handshake_request builds the HTTP upgrade request
build_handshake_request :: proc(host, path, challenge_key: string, subprotocols: []string, enable_compression: bool) -> string {
	request: strings.Builder
	// strings.Builder is zero-initialized, no init needed
	
	fmt.sbprintf(&request, "GET %s HTTP/1.1\r\n", path)
	fmt.sbprintf(&request, "Host: %s\r\n", host)
	fmt.sbprintf(&request, "Upgrade: websocket\r\n")
	fmt.sbprintf(&request, "Connection: Upgrade\r\n")
	fmt.sbprintf(&request, "Sec-WebSocket-Key: %s\r\n", challenge_key)
	fmt.sbprintf(&request, "Sec-WebSocket-Version: 13\r\n")
	
	// Add subprotocols if specified
	if len(subprotocols) > 0 {
		protocols := strings.join(subprotocols, ", ")
		defer delete(protocols)
		fmt.sbprintf(&request, "Sec-WebSocket-Protocol: %s\r\n", protocols)
	}
	
	// Add compression extension if enabled
	if enable_compression {
		fmt.sbprintf(&request, "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n")
	}
	
	fmt.sbprintf(&request, "\r\n")
	
	return strings.to_string(request)
}

// parse_handshake_response parses the HTTP upgrade response
// Returns: status_code, accept_key, subprotocol, ok
parse_handshake_response :: proc(response: string) -> (status_code: int, accept_key, subprotocol: string, ok: bool) {
	ok = false
	
	// Split response into lines
	lines := strings.split(response, "\r\n")
	defer delete(lines)
	
	if len(lines) < 1 {
		return
	}
	
	// Parse status line
	status_parts := strings.split(lines[0], " ")
	defer delete(status_parts)
	
	if len(status_parts) < 2 {
		return
	}
	
	// Parse status code using strconv
	if code, ok := strconv.parse_int(status_parts[1], 10); ok {
		status_code = int(code)
	} else {
		return
	}
	
	// Parse headers
	for i := 1; i < len(lines); i += 1 {
		line := lines[i]
		if line == "" {
			break
		}
		
		colon_idx := strings.index(line, ":")
		if colon_idx == -1 {
			continue
		}
		
		key := strings.to_lower(strings.trim_space(line[:colon_idx]))
		value := strings.trim_space(line[colon_idx+1:])
		
		switch key {
		case "sec-websocket-accept":
			accept_key = value
		case "sec-websocket-protocol":
			subprotocol = value
		}
	}
	
	if accept_key == "" {
		return
	}
	
	ok = true
	return
}
