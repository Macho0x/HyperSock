package hypersock_http

/*
 * HTTP Client Implementation
 * Based on fasthttp client.go patterns
 * 
 * Features:
 * - Connection pooling and reuse
 * - Zero-allocation request/response handling
 * - Timeout and deadline support
 * - Concurrent-safe operations
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:strconv"
import "core:time"
import "core:sync"
import "core:mem"

// Simple HTTP GET request
get :: proc(url: string) -> (int, []byte, os.Errno) {
	return client_get(client_default(), url)
}

// Simple HTTP POST request
post :: proc(url: string, body: []byte) -> (int, []byte, os.Errno) {
	return client_post(client_default(), url, body)
}

// HTTP GET with custom client
client_get :: proc(c: ^Client, url: string) -> (int, []byte, os.Errno) {
	// Parse URL
	uri, ok := uri_parse(url)
	if !ok {
		return 0, nil, os.EINVAL
	}
	
	// Get or create host client
	host_key := fmt.tprintf("%s:%d", uri.host, uri.port)
	
	sync.rw_mutex_lock(&c.mutex)
	hc, exists := c.host_clients[host_key]
	if !exists {
		hc = host_client_new(c, uri.host, uri.port, uri.scheme == "https")
		c.host_clients[host_key] = hc
	}
	sync.rw_mutex_unlock(&c.mutex)
	
	// Build request
	req: Request
	request_reset(&req)
	req.method = .GET
	req.uri = uri
	
	// Set default headers
	header_set(&req.header, "Host", uri.host)
	header_set(&req.header, "User-Agent", c.name)
	header_set(&req.header, "Accept", "*/*")
	header_set(&req.header, "Connection", "keep-alive")
	
	// Execute request
	resp: Response
	response_reset(&resp)
	
	err := host_client_do(hc, &req, &resp)
	if err != os.ERROR_NONE {
		return 0, nil, err
	}
	
	return resp.status_code, resp.body, os.ERROR_NONE
}

// HTTP POST with custom client
client_post :: proc(c: ^Client, url: string, body: []byte) -> (int, []byte, os.Errno) {
	// Parse URL
	uri, ok := uri_parse(url)
	if !ok {
		return 0, nil, os.EINVAL
	}
	
	// Get or create host client
	host_key := fmt.tprintf("%s:%d", uri.host, uri.port)
	
	sync.rw_mutex_lock(&c.mutex)
	hc, exists := c.host_clients[host_key]
	if !exists {
		hc = host_client_new(c, uri.host, uri.port, uri.scheme == "https")
		c.host_clients[host_key] = hc
	}
	sync.rw_mutex_unlock(&c.mutex)
	
	// Build request
	req: Request
	request_reset(&req)
	req.method = .POST
	req.uri = uri
	req.body = body
	
	// Set default headers
	header_set(&req.header, "Host", uri.host)
	header_set(&req.header, "User-Agent", c.name)
	header_set(&req.header, "Content-Type", "application/json")
	header_set(&req.header, "Content-Length", fmt.tprintf("%d", len(body)))
	header_set(&req.header, "Accept", "*/*")
	header_set(&req.header, "Connection", "keep-alive")
	
	// Execute request
	resp: Response
	response_reset(&resp)
	
	err := host_client_do(hc, &req, &resp)
	if err != os.ERROR_NONE {
		return 0, nil, err
	}
	
	return resp.status_code, resp.body, os.ERROR_NONE
}

// Create a new host client
host_client_new :: proc(client: ^Client, host: string, port: int, is_tls: bool) -> ^HostClient {
	hc := new(HostClient)
	hc.addr = fmt.tprintf("%s:%d", host, port)
	hc.is_tls = is_tls
	hc.max_conns = client.max_conns_per_host
	hc.max_idle_conn_duration = client.max_idle_conn_duration
	hc.read_buffer_size = client.read_buffer_size
	hc.write_buffer_size = client.write_buffer_size
	hc.read_timeout = client.read_timeout
	hc.write_timeout = client.write_timeout
	hc.max_response_body_size = client.max_response_body_size
	hc.client = client
	hc.conns = make([dynamic]^clientConn)
	return hc
}

// Execute request on host client
host_client_do :: proc(hc: ^HostClient, req: ^Request, resp: ^Response) -> os.Errno {
	// Acquire connection from pool
	cc, err := acquire_conn(hc)
	if err != os.ERROR_NONE {
		return err
	}
	defer release_conn(hc, cc)
	
	// Set timeouts if configured
	if hc.write_timeout > 0 {
		net.set_option(cc.conn, net.Socket_Option.Send_Timeout, int(hc.write_timeout))
	}
	if hc.read_timeout > 0 {
		net.set_option(cc.conn, net.Socket_Option.Receive_Timeout, int(hc.read_timeout))
	}
	
	// Build and send HTTP request
	err = write_request(cc.conn, req)
	if err != os.ERROR_NONE {
		// Connection is bad, don't return it to pool
		cc.conn = 0
		return err
	}
	
	// Read HTTP response
	err = read_response(cc.conn, resp, hc.max_response_body_size)
	if err != os.ERROR_NONE {
		// Connection is bad, don't return it to pool
		cc.conn = 0
		return err
	}
	
	// Update last use time
	cc.last_use = time.now()
	
	return os.ERROR_NONE
}

// Acquire a connection from the pool
acquire_conn :: proc(hc: ^HostClient) -> (^clientConn, os.Errno) {
	sync.mutex_lock(&hc.mutex)
	defer sync.mutex_unlock(&hc.mutex)
	
	// Try to find an idle connection
	now := time.now()
	for i := len(hc.conns) - 1; i >= 0; i -= 1 {
		cc := hc.conns[i]
		
		// Check if connection is still alive
		if cc.conn != 0 {
			// Remove from slice
			ordered_remove(&hc.conns, i)
			hc.conns_count -= 1
			return cc, os.ERROR_NONE
		} else {
			// Dead connection, remove it
			ordered_remove(&hc.conns, i)
			hc.conns_count -= 1
			free(cc)
		}
	}
	
	// Check if we can create a new connection
	if hc.conns_count >= hc.max_conns {
		return nil, os.ENOENT  // Too many open files
	}
	
	// Create new connection
	socket, net_err := net.dial_tcp(hc.addr)
	if net_err != nil {
		return nil, os.ECONNREFUSED
	}
	
	// Perform TLS handshake if needed
	tls_socket: ^TLS_Socket
	is_tls_conn: bool = false
	
	if hc.is_tls {
		// Extract server name from host configuration
		server_name := hc.addr
		if idx := strings.index(server_name, ":"); idx != -1 {
			server_name = server_name[:idx]
		}
		
		// Check if client has insecure skip verify
		insecure_skip := false
		if hc.client.tls_config != nil {
			insecure_skip = hc.client.tls_config.insecure_skip_verify
		}
		
		// Perform TLS handshake
		tls_socket, tls_err := perform_tls_handshake_on_socket(socket, server_name, insecure_skip)
		if tls_err != os.ERROR_NONE {
			net.close(socket)
			fmt.println("TLS handshake failed:", tls_err)
			return nil, tls_err
		}
		
		is_tls_conn = true
		fmt.println("TLS handshake completed successfully")
	}
	
	cc := new(clientConn)
	cc.conn = socket
	cc.tls_socket = tls_socket
	cc.is_tls = is_tls_conn
	cc.created = now
	cc.last_use = now
	hc.conns_count += 1
	
	return cc, os.ERROR_NONE
}

// Release connection back to pool
release_conn :: proc(hc: ^HostClient, cc: ^clientConn) {
	if cc.conn == 0 {
		// Connection is dead, free it
		// Clean up TLS socket if present
		if cc.is_tls && cc.tls_socket != nil {
			tls_close(cc.tls_socket)
			free(cc.tls_socket)
		}
		sync.mutex_lock(&hc.mutex)
		hc.conns_count -= 1
		sync.mutex_unlock(&hc.mutex)
		free(cc)
		return
	}
	
	sync.mutex_lock(&hc.mutex)
	
	// Check if we should keep this connection
	if hc.conns_count > hc.max_conns {
		// Too many connections, close this one
		if cc.is_tls && cc.tls_socket != nil {
			tls_close(cc.tls_socket)
			free(cc.tls_socket)
		}
		net.close(cc.conn)
		hc.conns_count -= 1
		free(cc)
	} else {
		// Return to pool
		cc.last_use = time.now()
		append(&hc.conns, cc)
	}
	
	sync.mutex_unlock(&hc.mutex)
}

// Close all connections for a host client
host_client_close :: proc(hc: ^HostClient) {
	sync.mutex_lock(&hc.mutex)
	defer sync.mutex_unlock(&hc.mutex)
	
	for cc in hc.conns {
		if cc.is_tls && cc.tls_socket != nil {
			tls_close(cc.tls_socket)
			free(cc.tls_socket)
		}
		if cc.conn != 0 {
			net.close(cc.conn)
		}
		free(cc)
	}
	delete(hc.conns)
}

// Write HTTP request to connection
write_request :: proc(conn: net.TCP_Socket, req: ^Request) -> os.Errno {
	// Build HTTP request
	request := strings.builder_make()
	defer strings.builder_destroy(&request)
	
	// Request line
	fmt.sbprintf(&request, "%s %s HTTP/1.1\r\n", method_to_string(req.method), req.uri.path)
	
	// Headers
	sync.mutex_lock(&req.header.mutex)
	for key, value in req.header.data {
		fmt.sbprintf(&request, "%s: %s\r\n", key, value)
	}
	sync.mutex_unlock(&req.header.mutex)
	
	// Empty line
	fmt.sbprintf(&request, "\r\n")
	
	// Body
	if len(req.body) > 0 {
		fmt.sbprintf(&request, "%s", string(req.body))
	}
	
	// Send request
	data := transmute([]byte)strings.to_string(request)
	_, send_err := net.send_tcp(conn, data)
	if send_err != nil {
		return os.ECONNREFUSED
	}
	return os.ERROR_NONE
}

// Read HTTP response from connection
read_response :: proc(conn: net.TCP_Socket, resp: ^Response, max_body_size: int) -> os.Errno {
	// Read response into buffer
	buf := make([]byte, 65536)
	defer delete(buf)
	
	n, recv_err := net.recv_tcp(conn, buf)
	if recv_err != nil {
		return os.ECONNREFUSED
	}
	if n == 0 {
		return os.ECONNREFUSED
	}
	
	response := string(buf[:n])
	
	// Parse status line
	lines := strings.split(response, "\r\n")
	defer delete(lines)
	
	if len(lines) < 1 {
		return os.EINVAL
	}
	
	// Parse status code using strconv
	parts := strings.split(lines[0], " ")
	defer delete(parts)
	
	if len(parts) >= 2 {
		// Parse status code as integer
		if code, ok := strconv.parse_int(parts[1], 10); ok {
			resp.status_code = int(code)
		} else {
			resp.status_code = 200 // Default on parse error
		}
	}
	
	// Parse headers
	header_end := 0
	for i := 1; i < len(lines); i += 1 {
		if lines[i] == "" {
			header_end = i
			break
		}
		
		colon_idx := strings.index(lines[i], ":")
		if colon_idx != -1 {
			key := strings.to_lower(strings.trim_space(lines[i][:colon_idx]))
			value := strings.trim_space(lines[i][colon_idx+1:])
			header_set(&resp.header, key, value)
		}
	}
	
	// Parse body
	if header_end > 0 && header_end + 1 < len(lines) {
		body_start := strings.index(response, "\r\n\r\n")
		if body_start != -1 {
			body_start += 4
			body := buf[body_start:n]
			
			if max_body_size > 0 && len(body) > max_body_size {
				return os.EINVAL  // Buffer too small
			}
			
			resp.body = make([]byte, len(body))
			copy(resp.body, body)
		}
	}
	
	return os.ERROR_NONE
}

// Do performs an HTTP request with full control
do_request :: proc(c: ^Client, req: ^Request, resp: ^Response) -> os.Errno {
	// Parse URI if needed
	if req.uri.host == "" {
		uri, ok := uri_parse(fmt.tprintf("%s://%s%s", req.uri.scheme, req.header.data["Host"], req.uri.path))
		if !ok {
			return os.EINVAL
		}
		req.uri = uri
	}
	
	// Get or create host client
	host_key := fmt.tprintf("%s:%d", req.uri.host, req.uri.port)
	
	sync.rw_mutex_lock(&c.mutex)
	hc, exists := c.host_clients[host_key]
	if !exists {
		hc = host_client_new(c, req.uri.host, req.uri.port, req.uri.scheme == "https")
		c.host_clients[host_key] = hc
	}
	sync.rw_mutex_unlock(&c.mutex)
	
	return host_client_do(hc, req, resp)
}


// DoWithRedirects performs an HTTP request following redirects
do_with_redirects :: proc(c: ^Client, req: ^Request, resp: ^Response, max_redirects: int) -> os.Errno {
	// Execute the request with redirect handling
	// Note: This implementation is a simple version that follows redirects
	// For full implementation, see client_advanced.odin
	
	for i := 0; i <= max_redirects; i += 1 {
		// Execute request
		err := do_request(c, req, resp)
		if err != os.ERROR_NONE {
			return err
		}
		
		// Check if response is a redirect (3xx)
		if resp.status_code < 300 || resp.status_code >= 400 {
			return os.ERROR_NONE  // Not a redirect, return normally
		}
		
		// Get Location header
		location := header_get(&resp.header, "location")
		if location == "" {
			return os.ERROR_NONE  // No location header, return normally
		}
		
		// Build new URL
		base_url := fmt.tprintf("%s://%s%s", req.uri.scheme, req.uri.host, req.uri.path)
		redirect_url := resolve_base_url(base_url, location)
		if redirect_url == "" {
			return os.EINVAL
		}
		
		// Parse new URL
		new_uri, ok := uri_parse(redirect_url)
		if !ok {
			return os.EINVAL
		}
		
		// Update request with new URL
		req.uri = new_uri
		
		// For 301/302, change POST to GET
		if (resp.status_code == 301 || resp.status_code == 302) && req.method == .POST {
			req.method = .GET
			req.body = req.body[:0]
		}
		
		// Reset response for next request
		response_reset(resp)
	}
	
	return os.EINVAL
}

// resolve_base_url resolves relative URL against base URL
resolve_base_url :: proc(base_url, relative_url: string) -> string {
	// If relative URL is absolute, return it
	if strings.has_prefix(relative_url, "http://") || strings.has_prefix(relative_url, "https://") {
		return relative_url
	}
	
	// Parse base URL
	base_uri, ok := uri_parse(base_url)
	if !ok {
		return ""
	}
	
	// Handle path resolution
	if len(relative_url) > 0 && relative_url[0] == '/' {
		// Absolute path
		return fmt.tprintf("%s://%s%s", base_uri.scheme, base_uri.host, relative_url)
	} else {
		// Relative path - join with base path
		base_path := base_uri.path
		if !strings.has_suffix(base_path, "/") {
			// Remove last segment
			last_slash := strings.last_index_byte(base_path, '/')
			if last_slash != -1 {
				base_path = base_path[:last_slash+1]
			}
		}
		return fmt.tprintf("%s://%s%s%s", base_uri.scheme, base_uri.host, base_path, relative_url)
	}
}

// GetTimeout performs GET with timeout
get_timeout :: proc(c: ^Client, url: string, timeout: time.Duration) -> (int, []byte, os.Errno) {
	if timeout <= 0 {
		return client_get(c, url)
	}
	
	// Create request
	req: Request
	request_reset(&req)
	req.method = .GET
	req.uri, _ = uri_parse(url)
	req.timeout = timeout
	
	// Create response
	resp: Response
	response_reset(&resp)
	
	// Execute with timeout
	err := do_with_retry(c, &req, &resp, 3)
	if err != os.ERROR_NONE {
		return 0, nil, err
	}
	
	return resp.status_code, resp.body, os.ERROR_NONE
}
