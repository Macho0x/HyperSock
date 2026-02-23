package hypersock_websocket

/*
 * WebSocket Upgrader Implementation
 * Based on gorilla/websocket server.go patterns
 * 
 * Handles HTTP to WebSocket upgrade requests
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:time"
import http "../hypersock_http"

// UpgradeResponse contains the response from an upgrade
UpgradeResponse :: struct {
	conn:       ^Conn,
	subprotocol: string,
	handshake_complete: bool,
}

// Upgrade upgrades the HTTP connection to WebSocket protocol
upgrade :: proc(u: ^Upgrader, w: ^http.Response, r: ^http.Request) -> (^Conn, http.Header, os.Errno) {
	// Check if connection is already hijacked
	// For simplicity, we'll assume the response writer has the underlying connection
	
	// Validate request method
	if r.method != .GET {
		return nil, http.Header{}, os.EINVAL
	}
	
	// Check for Upgrade header
	upgrade_header := http.header_get(&r.header, "Upgrade")
	if strings.to_lower(upgrade_header) != "websocket" {
		return nil, http.Header{}, os.EINVAL
	}
	
	// Check for Connection header
	connection_header := http.header_get(&r.header, "Connection")
	if !strings.contains(strings.to_lower(connection_header), "upgrade") {
		return nil, http.Header{}, os.EINVAL
	}
	
	// Check for Sec-WebSocket-Version
	version_header := http.header_get(&r.header, "Sec-WebSocket-Version")
	if version_header != "13" {
		return nil, http.Header{}, os.EINVAL
	}
	
	// Check for Sec-WebSocket-Key
	key_header := http.header_get(&r.header, "Sec-WebSocket-Key")
	if len(key_header) == 0 {
		return nil, http.Header{}, os.EINVAL
	}
	
	// Validate key format (must be base64)
	if len(key_header) != 24 {  // Base64 encoded 16 bytes
		return nil, http.Header{}, os.EINVAL
	}
	
	// Handle optional origin check
	if u.check_origin != nil {
		if !u.check_origin(r) {
			return nil, http.Header{}, os.EACCES
		}
	}
	
	// Handle subprotocol negotiation
	selected_subprotocol: string
	if len(u.subprotocols) > 0 {
		client_protocols_header := http.header_get(&r.header, "Sec-WebSocket-Protocol")
		if client_protocols_header != "" {
			client_protocols := strings.split(client_protocols_header, ",")
			defer delete(client_protocols)
			
			for cp in client_protocols {
				client_proto := strings.trim_space(strings.trim(cp, "\""))
				for sp in u.subprotocols {
					if sp == client_proto {
						selected_subprotocol = sp
						break
					}
				}
				if selected_subprotocol != "" {
					break
				}
			}
		}
	}
	
	// Hijack the connection (in real implementation, this would get the underlying TCP socket)
	// For now, we'll need the underlying connection from the response
	// This is a simplified implementation - in practice, you'd need access to the raw TCP socket
	
	// Compute accept key
	accept_key := compute_accept_key(key_header)
	
	// Build response headers
	response_headers: http.Header
	// Headers are zero-initialized, no explicit init needed
	http.header_set(&response_headers, "Upgrade", "websocket")
	http.header_set(&response_headers, "Connection", "Upgrade")
	http.header_set(&response_headers, "Sec-WebSocket-Accept", accept_key)
	
	if selected_subprotocol != "" {
		http.header_set(&response_headers, "Sec-WebSocket-Protocol", selected_subprotocol)
	}
	
	// In real implementation, you would:
	// 1. Get the raw TCP socket from the HTTP response writer
	// 2. Send the HTTP 101 Switching Protocols response
	// 3. Create a WebSocket connection from the socket
	
	// For now, return an error indicating the connection needs to be hijacked
	// In production, integrate with http package to properly hijack connection
	
	// Placeholder: would normally create WebSocket connection like this:
	// conn := new_conn(socket, true, u.read_buffer_size, u.write_buffer_size)
	// conn.subprotocol = selected_subprotocol
	
	return nil, response_headers, os.ENOSYS
}

// IsWebSocketUpgrade checks if the request is a WebSocket upgrade request
is_websocket_upgrade :: proc(ctx: ^http.RequestCtx) -> bool {
	if ctx.request.method != .GET {
		return false
	}
	
	upgrade_header := http.header_get(&ctx.request.header, "Upgrade")
	if strings.to_lower(upgrade_header) != "websocket" {
		return false
	}
	
	connection_header := http.header_get(&ctx.request.header, "Connection")
	if !strings.contains(strings.to_lower(connection_header), "upgrade") {
		return false
	}
	
	return true
}

// Subprotocol negotiates subprotocols based on client offer
select_subprotocol :: proc(proto_client, proto_server: string) -> string {
	if proto_client == "" || proto_server == "" {
		return ""
	}
	
	client_protocols := strings.split(proto_client, ",")
	defer delete(client_protocols)
	
	server_protocols := strings.split(proto_server, ",")
	defer delete(server_protocols)
	
	for cp in client_protocols {
		client_proto := strings.trim_space(strings.trim(cp, "\""))
		if client_proto == "" {
			continue
		}
		
		for sp in server_protocols {
			server_proto := strings.trim_space(strings.trim(sp, "\""))
			if client_proto == server_proto {
				return server_proto
			}
		}
	}
	
	return ""
}

// RejectionError builds an error response for rejected upgrades
rejection_error :: proc(w: ^http.Response, status: int, reason: string) {
	w.status_code = status
	body := reason
	w.body = make([]byte, len(body))
	copy(w.body, body)
	http.header_set(&w.header, "Connection", "close")
}

// Default check_origin function - always returns true
check_origin_default :: proc(req: ^http.Request) -> bool {
	return true
}
