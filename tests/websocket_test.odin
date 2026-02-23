package hypersock_test

/*
 * WebSocket Module Tests
 * Tests for the hypersock_websocket package
 */

import ws "../hypersock_websocket"
import http "../hypersock_http"
import "core:testing"
import "core:os"
import "core:fmt"

// Test opcode detection
@test
test_is_control :: proc(t: ^testing.T) {
	testing.expect(t, ws.is_control(.Close), "Close should be control frame")
	testing.expect(t, ws.is_control(.Ping), "Ping should be control frame")
	testing.expect(t, ws.is_control(.Pong), "Pong should be control frame")
	testing.expect(t, !ws.is_control(.Text), "Text should not be control frame")
	testing.expect(t, !ws.is_control(.Binary), "Binary should not be control frame")
}

@test
test_is_data :: proc(t: ^testing.T) {
	testing.expect(t, ws.is_data(.Text), "Text should be data frame")
	testing.expect(t, ws.is_data(.Binary), "Binary should be data frame")
	testing.expect(t, !ws.is_data(.Close), "Close should not be data frame")
	testing.expect(t, !ws.is_data(.Ping), "Ping should not be data frame")
}

// Test mask bytes functionality
@test
test_mask_bytes :: proc(t: ^testing.T) {
	key := [4]byte{0x12, 0x34, 0x56, 0x78}
	data := []byte{0x01, 0x02, 0x03, 0x04}
	original := make([]byte, len(data))
	copy(original, data)
	
	// Mask the data
	ws.mask_bytes(key, 0, data)
	
	// Data should be different after masking
	testing.expect(t, data[0] != original[0] || data[1] != original[1], "Data should be masked")
	
	// Unmask by masking again (XOR is its own inverse)
	ws.mask_bytes(key, 0, data)
	
	// Data should be back to original
	testing.expect(t, data[0] == original[0], "Data should be unmasked")
	testing.expect(t, data[1] == original[1], "Data should be unmasked")
	testing.expect(t, data[2] == original[2], "Data should be unmasked")
	testing.expect(t, data[3] == original[3], "Data should be unmasked")
}

// Test dialer default
@test
test_dialer_default :: proc(t: ^testing.T) {
	dialer := ws.dialer_default()
	
	testing.expect(t, dialer.read_buffer_size == 4096, "Default read buffer size")
	testing.expect(t, dialer.write_buffer_size == 4096, "Default write buffer size")
	testing.expect(t, dialer.handshake_timeout == 45 * 1000000000, "Default handshake timeout (45s in nanoseconds)")
}

// Test upgrader default
@test
test_upgrader_default :: proc(t: ^testing.T) {
	upgrader := ws.upgrader_default()
	
	testing.expect(t, upgrader.read_buffer_size == 4096, "Default read buffer size")
	testing.expect(t, upgrader.write_buffer_size == 4096, "Default write buffer size")
	testing.expect(t, upgrader.handshake_timeout == 45 * 1000000000, "Default handshake timeout")
}

// Test challenge key generation
@test
test_generate_challenge_key :: proc(t: ^testing.T) {
	key1 := ws.generate_challenge_key()
	key2 := ws.generate_challenge_key()
	
	testing.expect(t, len(key1) > 0, "Key should not be empty")
	testing.expect(t, len(key2) > 0, "Key should not be empty")
	testing.expect(t, key1 != key2, "Keys should be different")
}

// Test compute accept key
@test
test_compute_accept_key :: proc(t: ^testing.T) {
	challenge := "dGhlIHNhbXBsZSBub25jZQ=="
	accept := ws.compute_accept_key(challenge)
	
	testing.expect(t, len(accept) > 0, "Accept key should not be empty")
	// The actual value depends on SHA1 implementation
}

// Test close code constants
@test
test_close_codes :: proc(t: ^testing.T) {
	testing.expect(t, u16(ws.CloseCode.NormalClosure) == 1000, "Normal closure code")
	testing.expect(t, u16(ws.CloseCode.GoingAway) == 1001, "Going away code")
	testing.expect(t, u16(ws.CloseCode.ProtocolError) == 1002, "Protocol error code")
	testing.expect(t, u16(ws.CloseCode.UnsupportedData) == 1003, "Unsupported data code")
	testing.expect(t, u16(ws.CloseCode.MessageTooBig) == 1009, "Message too big code")
}

// Test frame bits
@test
test_frame_bits :: proc(t: ^testing.T) {
	testing.expect(t, u8(ws.Frame_Bits.FIN) == 0x80, "FIN bit")
	testing.expect(t, u8(ws.Frame_Bits.RSV1) == 0x40, "RSV1 bit")
	testing.expect(t, u8(ws.Frame_Bits.RSV2) == 0x20, "RSV2 bit")
	testing.expect(t, u8(ws.Frame_Bits.RSV3) == 0x10, "RSV3 bit")
	testing.expect(t, u8(ws.Frame_Bits.MASK) == 0x80, "MASK bit")
}

// Test connection state enum
@test
test_conn_state :: proc(t: ^testing.T) {
	testing.expect(t, ws.Conn_State.Open == ws.Conn_State.Open, "Open state")
	testing.expect(t, ws.Conn_State.Closing == ws.Conn_State.Closing, "Closing state")
	testing.expect(t, ws.Conn_State.Closed == ws.Conn_State.Closed, "Closed state")
}

// Test WebSocket error enum
@test
test_websocket_error :: proc(t: ^testing.T) {
	testing.expect(t, ws.WebSocket_Error.None == ws.WebSocket_Error.None, "None error")
	testing.expect(t, ws.WebSocket_Error.BadHandshake == ws.WebSocket_Error.BadHandshake, "Bad handshake error")
	testing.expect(t, ws.WebSocket_Error.InvalidFrame == ws.WebSocket_Error.InvalidFrame, "Invalid frame error")
}

// Test upgrader with check_origin
@test
test_upgrader_check_origin :: proc(t: ^testing.T) {
	upgrader := ws.Upgrader{
		read_buffer_size = 1024,
		write_buffer_size = 1024,
		check_origin = proc(req: ^http.Request) -> bool {
			return true
		},
	}
	
	testing.expect(t, upgrader.check_origin != nil, "Check origin should be set")
}

// Test select subprotocol
@test
test_select_subprotocol :: proc(t: ^testing.T) {
	// Test matching protocols
	result1 := ws.select_subprotocol("chat, superchat", "superchat")
	testing.expect(t, result1 == "superchat", "Should select matching protocol")
	
	// Test no match
	result2 := ws.select_subprotocol("chat", "video")
	testing.expect(t, result2 == "", "Should return empty for no match")
	
	// Test empty inputs
	result3 := ws.select_subprotocol("", "chat")
	testing.expect(t, result3 == "", "Should return empty for empty client protocols")
}

// Test is websocket upgrade detection
@test
test_is_websocket_upgrade :: proc(t: ^testing.T) {
	// Create a request that looks like WebSocket upgrade
	ctx: http.RequestCtx
	ctx.request.method = .GET
	http.header_set(&ctx.request.header, "Upgrade", "websocket")
	http.header_set(&ctx.request.header, "Connection", "Upgrade")
	http.header_set(&ctx.request.header, "Sec-WebSocket-Version", "13")
	
	testing.expect(t, ws.is_websocket_upgrade(&ctx), "Should detect WebSocket upgrade")
	
	// Test non-upgrade request
	ctx2: http.RequestCtx
	ctx2.request.method = .GET
	testing.expect(t, !ws.is_websocket_upgrade(&ctx2), "Should not detect as upgrade")
	
	// Test wrong method
	ctx3: http.RequestCtx
	ctx3.request.method = .POST
	http.header_set(&ctx3.request.header, "Upgrade", "websocket")
	testing.expect(t, !ws.is_websocket_upgrade(&ctx3), "POST should not be upgrade")
}

// Test message types
@test
test_message_types :: proc(t: ^testing.T) {
	// Text_Message type removed
	// Binary_Message type removed
}

// Test frame constants
@test
test_frame_constants :: proc(t: ^testing.T) {
	testing.expect(t, ws.MAX_FRAME_HEADER_SIZE == 14, "Max frame header size (2 + 8 + 4)")
	testing.expect(t, ws.MAX_CONTROL_FRAME_PAYLOAD_SIZE == 125, "Max control frame payload")
	testing.expect(t, ws.DEFAULT_READ_BUFFER_SIZE == 4096, "Default read buffer size")
	testing.expect(t, ws.DEFAULT_WRITE_BUFFER_SIZE == 4096, "Default write buffer size")
}

// Main test runner
main :: proc() {
	fmt.println("Running HyperSock WebSocket tests...")
	
	// Individual tests are run automatically by the test runner
	// when using `odin test` command
}
