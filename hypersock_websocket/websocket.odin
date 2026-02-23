package hypersock_websocket

/*
 * WebSocket implementation for Odin
 * Based on gorilla/websocket patterns
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:time"
import "core:crypto"
import "core:crypto/legacy/sha1"

import "core:encoding/base64"
import "core:encoding/endian"
import "core:sync"
import http "../hypersock_http"

// WebSocket frame opcodes (RFC 6455)
Opcode :: enum u8 {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

// Close codes (RFC 6455, section 11.7)
CloseCode :: enum u16 {
	NormalClosure           = 1000,
	GoingAway               = 1001,
	ProtocolError           = 1002,
	UnsupportedData         = 1003,
	NoStatusReceived        = 1005,
	AbnormalClosure         = 1006,
	InvalidFramePayloadData = 1007,
	PolicyViolation         = 1008,
	MessageTooBig           = 1009,
	MandatoryExtension      = 1010,
	InternalServerErr       = 1011,
	ServiceRestart          = 1012,
	TryAgainLater           = 1013,
	TLSHandshake            = 1015,
}

// Frame header bits
Frame_Bits :: enum u8 {
	FIN  = 0x80,
	RSV1 = 0x40,
	RSV2 = 0x20,
	RSV3 = 0x10,
	MASK = 0x80,
}

// Frame represents a WebSocket frame
Frame :: struct {
	fin:     bool,
	rsv1:    bool,
	rsv2:    bool,
	rsv3:    bool,
	opcode:  Opcode,
	masked:  bool,
	mask:    [4]byte,
	payload: []byte,
}

// Connection state
Conn_State :: enum {
	Open,
	Closing,
	Closed,
}

// Conn represents a WebSocket connection
Conn :: struct {
	conn:        net.TCP_Socket,
	is_server:   bool,
	state:       Conn_State,
	subprotocol: string,
	
	// Read fields
	read_buf:        [dynamic]byte,
	read_remaining:  i64,
	read_final:      bool,
	read_msg_type:   Opcode,
	read_limit:      i64,
	read_mask_key:   [4]byte,
	read_mask_pos:   int,
	read_err:        os.Errno,
	
	// Write fields
	write_buf:        [dynamic]byte,
	write_mutex:      sync.Mutex,
	write_deadline:   time.Time,
	is_writing:       bool,
	
	// Read deadline
	read_deadline:    time.Time,
	// Handlers
	handle_ping: proc(data: string) -> os.Errno,
	handle_pong: proc(data: string) -> os.Errno,
	handle_close: proc(code: u16, text: string) -> os.Errno,
}

// Upgrader handles HTTP to WebSocket upgrade
Upgrader :: struct {
	read_buffer_size:  int,
	write_buffer_size: int,
	handshake_timeout: time.Duration,
	subprotocols:    []string,
	check_origin:    proc(req: ^http.Request) -> bool,
	enable_compression: bool,
}

// Dialer creates client WebSocket connections
Dialer :: struct {
	net_dial:          proc(network, addr: string) -> (net.TCP_Socket, os.Errno),
	read_buffer_size:  int,
	write_buffer_size: int,
	handshake_timeout: time.Duration,
	subprotocols:      []string,
	enable_compression: bool,
}

// Errors
WebSocket_Error :: enum {
	None,
	BadHandshake,
	InvalidFrame,
	ReadLimitExceeded,
	WriteClosed,
	CloseSent,
}

// Initialize default upgrader
upgrader_default :: proc() -> Upgrader {
	return Upgrader{
		read_buffer_size  = 4096,
		write_buffer_size = 4096,
		handshake_timeout = 45 * time.Second,
	}
}

// Initialize default dialer
dialer_default :: proc() -> Dialer {
	return Dialer{
		read_buffer_size  = 4096,
		write_buffer_size = 4096,
		handshake_timeout = 45 * time.Second,
	}
}

// Compute WebSocket accept key from challenge key
// RFC 6455: Concatenate challenge with magic string, SHA1 hash, then base64 encode
compute_accept_key :: proc(challenge: string) -> string {
	magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	combined := strings.concatenate([]string{challenge, magic})
	defer delete(combined)
	
	// Initialize SHA1 context
	ctx: sha1.Context
	sha1.init(&ctx)
	
	// Hash the combined string
	combined_bytes := transmute([]byte)combined
	sha1.update(&ctx, combined_bytes)
	
	// Get the final hash
	hash: [sha1.DIGEST_SIZE]byte
	sha1.final(&ctx, hash[:])
	
	return base64.encode(hash[:])
}

// Mask/unmask payload bytes
mask_bytes :: proc(key: [4]byte, start: int, data: []byte) -> int {
	for i := 0; i < len(data); i += 1 {
		j := (start + i) % 4
		data[i] ~= key[j]
	}
	return (start + len(data)) % 4
}

// Check if opcode is a control frame
is_control :: proc(opcode: Opcode) -> bool {
	return opcode == .Close || opcode == .Ping || opcode == .Pong
}

// Check if opcode is a data frame
is_data :: proc(opcode: Opcode) -> bool {
	return opcode == .Text || opcode == .Binary
}

// Generate random challenge key
generate_challenge_key :: proc() -> string {
	buf: [16]byte
	crypto.rand_bytes(buf[:])
	return base64.encode(buf[:])
}
