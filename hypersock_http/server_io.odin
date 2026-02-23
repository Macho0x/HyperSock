package hypersock_http

/*
 * HTTP Request/Response I/O
 * Used by server to parse requests and write responses
 * Based on fasthttp patterns
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:time"
import "core:sync"

// read_request reads and parses an HTTP request from the connection
read_request :: proc(conn: net.TCP_Socket, req: ^Request) -> os.Errno {
	// Clear request
	request_reset(req)
	
	// Create buffered reader
	buf: [dynamic]byte
	defer delete(buf)
	
	// Read the request line (max 4096 bytes)
	chunk := make([]byte, 4096)
	defer delete(chunk)
	
	n, recv_err := net.recv_tcp(conn, chunk)
	if recv_err != nil {
		return nil
	}
	if n == 0 {
		return nil
	}
	
	// Copy to buffer for easier parsing
	append(&buf, ..chunk[:n])
	
	// Find end of request line
	line_end := -1
	for i := 0; i < len(buf); i += 1 {
		if buf[i] == '\r' && i + 1 < len(buf) && buf[i+1] == '\n' {
			line_end = i
			break
		}
	}
	
	if line_end == -1 {
		// No CRLF found, might be LF-only
		for i := 0; i < len(buf); i += 1 {
			if buf[i] == '\n' {
				line_end = i
				break
			}
		}
	}
	
	if line_end == -1 {
		return nil
	}
	
	line := string(buf[:line_end])
	
	// Parse request line: METHOD PATH HTTP/VERSION
	parts := strings.split(line, " ")
	defer delete(parts)
	
	if len(parts) < 3 {
		return nil
	}
	
	// Parse method
	method_str := strings.trim_space(parts[0])
	switch method_str {
	case "GET":     req.method = .GET
	case "POST":    req.method = .POST
	case "PUT":     req.method = .PUT
	case "DELETE":  req.method = .DELETE
	case "HEAD":    req.method = .HEAD
	case "OPTIONS": req.method = .OPTIONS
	case "PATCH":   req.method = .PATCH
	}
	
	// Parse path (URI)
	uri_str := strings.trim_space(parts[1])
	
	// Include query string if present
	// Extract query string from original buffer
	query_start := line_end + 2  // Skip CRLF
	
	// Update buffer position and continue parsing headers
	cursor := query_start
	
	// Check if there's more data (headers) before parsing URI
	// For now, just parse the path part
	
	// Parse and set URI
	req.uri, _ = uri_parse(uri_str)
	
	// Parse headers until empty line
	for {
		// Find next CRLF
		header_len := -1
		for i := cursor; i < len(buf); i += 1 {
			if buf[i] == '\r' && i + 1 < len(buf) && buf[i+1] == '\n' {
				header_len = i
				break
			}
		}
		
		if header_len == -1 {
			// Need to read more data
			// For simplicity, assume we have all data
			break
		}
		
		// Skip CRLF
		cursor = header_len + 2
		
		if cursor == line_end + 2 {
			// Empty line - headers done
			break
		}
		
		// Extract header
		next_header_end := -1
		for i := cursor; i < len(buf); i += 1 {
			if buf[i] == '\r' && i + 1 < len(buf) && buf[i+1] == '\n' {
				next_header_end = i
				break
			}
		}
		
		if next_header_end == -1 {
			break
		}
		
		header_line := string(buf[cursor:next_header_end])
		
		// Parse header: Name: Value
		colon_idx := strings.index(header_line, ":")
		if colon_idx != -1 {
			name := strings.to_lower(strings.trim_space(header_line[:colon_idx]))
			value := strings.trim_space(header_line[colon_idx+1:])
			header_set(&req.header, name, value)
		}
		
		cursor = next_header_end + 2
	}
	
	// Check for Content-Length and set body read size
	if header_has(&req.header, "content-length") {
		len_str := header_get(&req.header, "content-length")
		// Simple parsing - get first token
		// In real implementation, use strconv.parse_uint
		// For now, assume we need to read more
		if len_str != "" {
			// Read body if we haven't already
			content_start := cursor
			if content_start < len(buf) {
				req.body = make([]byte, len(buf) - content_start)
				copy(req.body, buf[content_start:])
			}
		}
	}
	
	return nil
}

// write_response writes HTTP response to the connection
write_response :: proc(conn: net.TCP_Socket, resp: ^Response) -> os.Errno {
	// Build response
	response_data: strings.Builder
	defer strings.builder_destroy(&response_data)
	
	// Status line with complete status text mappings
	status_text := get_status_text(resp.status_code)
	
	// Determine protocol version
	protocol := "HTTP/1.1"
	// In real implementation, check request for HTTP/1.0 or HTTP/1.1
	
	fmt.sbprintf(&response_data, "%s %d %s\r\n", protocol, resp.status_code, status_text)
	
	// Write headers
	sync.mutex_lock(&resp.header.mutex)
	defer sync.mutex_unlock(&resp.header.mutex)
	
	if resp.header.data != nil {
		for key, value in resp.header.data {
			fmt.sbprintf(&response_data, "%s: %s\r\n", key, value)
		}
	}
	
	// Content-Length header (if not set)
	if !header_has(&resp.header, "content-length") && len(resp.body) > 0 {
		fmt.sbprintf(&response_data, "Content-Length: %d\r\n", len(resp.body))
	}
	
	// Empty line
	fmt.sbprintf(&response_data, "\r\n")
	
	// Body
	if len(resp.body) > 0 {
		fmt.sbprintf(&response_data, "%s", string(resp.body))
	}
	
	// Send response
	data := transmute([]byte)strings.to_string(response_data)
	_, send_err := net.send_tcp(conn, data)
	if send_err != nil {
		return nil
	}
	
	return nil
}


// get_status_text returns the standard HTTP status text for a given code
get_status_text :: proc(code: int) -> string {
	switch code {
	// 1xx Informational
	case 100: return "Continue"
	case 101: return "Switching Protocols"
	case 102: return "Processing"
	case 103: return "Early Hints"
	
	// 2xx Success
	case 200: return "OK"
	case 201: return "Created"
	case 202: return "Accepted"
	case 203: return "Non-Authoritative Information"
	case 204: return "No Content"
	case 205: return "Reset Content"
	case 206: return "Partial Content"
	case 207: return "Multi-Status"
	case 208: return "Already Reported"
	case 226: return "IM Used"
	
	// 3xx Redirection
	case 300: return "Multiple Choices"
	case 301: return "Moved Permanently"
	case 302: return "Found"
	case 303: return "See Other"
	case 304: return "Not Modified"
	case 305: return "Use Proxy"
	case 307: return "Temporary Redirect"
	case 308: return "Permanent Redirect"
	
	// 4xx Client Error
	case 400: return "Bad Request"
	case 401: return "Unauthorized"
	case 402: return "Payment Required"
	case 403: return "Forbidden"
	case 404: return "Not Found"
	case 405: return "Method Not Allowed"
	case 406: return "Not Acceptable"
	case 407: return "Proxy Authentication Required"
	case 408: return "Request Timeout"
	case 409: return "Conflict"
	case 410: return "Gone"
	case 411: return "Length Required"
	case 412: return "Precondition Failed"
	case 413: return "Payload Too Large"
	case 414: return "URI Too Long"
	case 415: return "Unsupported Media Type"
	case 416: return "Range Not Satisfiable"
	case 417: return "Expectation Failed"
	case 418: return "I'm a teapot"
	case 421: return "Misdirected Request"
	case 422: return "Unprocessable Entity"
	case 423: return "Locked"
	case 424: return "Failed Dependency"
	case 425: return "Too Early"
	case 426: return "Upgrade Required"
	case 428: return "Precondition Required"
	case 429: return "Too Many Requests"
	case 431: return "Request Header Fields Too Large"
	case 451: return "Unavailable For Legal Reasons"
	
	// 5xx Server Error
	case 500: return "Internal Server Error"
	case 501: return "Not Implemented"
	case 502: return "Bad Gateway"
	case 503: return "Service Unavailable"
	case 504: return "Gateway Timeout"
	case 505: return "HTTP Version Not Supported"
	case 506: return "Variant Also Negotiates"
	case 507: return "Insufficient Storage"
	case 508: return "Loop Detected"
	case 510: return "Not Extended"
	case 511: return "Network Authentication Required"
	
	case:
		if code >= 100 && code < 200 {
			return "Informational"
		} else if code >= 200 && code < 300 {
			return "Success"
		} else if code >= 300 && code < 400 {
			return "Redirection"
		} else if code >= 400 && code < 500 {
			return "Client Error"
		} else if code >= 500 && code < 600 {
			return "Server Error"
		}
		return "Unknown Status"
	}
}
