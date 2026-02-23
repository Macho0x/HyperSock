package hypersock_websocket

/*
 * WebSocket Connection Implementation
 * Based on gorilla/websocket conn.go patterns
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:mem"
import "core:time"
import "core:sync"
import "core:strings"
import "core:encoding/endian"
import "core:unicode/utf8"

// Frame size limits
MAX_FRAME_HEADER_SIZE :: 2 + 8 + 4
MAX_CONTROL_FRAME_PAYLOAD_SIZE :: 125
DEFAULT_READ_BUFFER_SIZE :: 4096
DEFAULT_WRITE_BUFFER_SIZE :: 4096

// Write deadline
WRITE_WAIT :: time.Second

// Message types (convenience)
Text_Message :: 1
Binary_Message :: 2

// new_conn creates a new WebSocket connection
new_conn :: proc(socket: net.TCP_Socket, is_server: bool, read_buf_size, write_buf_size: int) -> ^Conn {
	c := new(Conn)
	c.conn = socket
	c.is_server = is_server
	c.state = .Open
	
	// Initialize read buffer
	actual_read_buf_size := read_buf_size
	if actual_read_buf_size == 0 {
		actual_read_buf_size = DEFAULT_READ_BUFFER_SIZE
	}
	c.read_buf = make([dynamic]byte, 0, actual_read_buf_size)
	c.read_limit = 0
	c.read_final = true
	
	// Initialize write buffer
	actual_write_buf_size := write_buf_size
	if actual_write_buf_size == 0 {
		actual_write_buf_size = DEFAULT_WRITE_BUFFER_SIZE
	}
	c.write_buf = make([dynamic]byte, 0, actual_write_buf_size + MAX_FRAME_HEADER_SIZE)
	c.write_deadline = time.Time{}
	c.read_deadline = time.Time{}
	c.is_writing = false
	
	// Set default handlers
	c.handle_ping = proc(data: string) -> os.Errno {
		return os.ERROR_NONE
	}
	c.handle_pong = proc(data: string) -> os.Errno {
		return os.ERROR_NONE
	}
	c.handle_close = proc(code: u16, text: string) -> os.Errno {
		return os.ERROR_NONE
	}
	
	return c
}

// destroy_conn cleans up a WebSocket connection
destroy_conn :: proc(c: ^Conn) {
	if c == nil do return
	
	if c.state != .Closed {
		close_connection(c)
	}
	
	delete(c.read_buf)
	delete(c.write_buf)
	free(c)
}

// close_connection closes the underlying network connection
close_connection :: proc(c: ^Conn) -> os.Errno {
	if c.state == .Closed {
		return os.ERROR_NONE
	}
	
	c.state = .Closed
	net.close(c.conn)
	return os.ERROR_NONE
}

// advance_frame reads and parses the next frame header
advance_frame :: proc(c: ^Conn) -> (opcode: Opcode, err: os.Errno) {
	// Skip remainder of previous frame
	if c.read_remaining > 0 {
		to_skip := make([]byte, c.read_remaining)
		defer delete(to_skip)
		_, recv_err := net.recv_tcp(c.conn, to_skip)
		if recv_err != nil {
			return .Continuation, os.EINVAL
		}
	}
	
	// Read first two bytes of frame header
	header_buf: [2]byte
	_, recv_err := net.recv_tcp(c.conn, header_buf[:])
	if recv_err != nil {
		return .Continuation, os.EINVAL
	}
	
	b0 := header_buf[0]
	b1 := header_buf[1]
	
	fin := (b0 & 0x80) != 0
	rsv1 := (b0 & 0x40) != 0
	rsv2 := (b0 & 0x20) != 0
	rsv3 := (b0 & 0x10) != 0
	opcode_val := Opcode(b0 & 0x0F)
	masked := (b1 & 0x80) != 0
	payload_len := i64(b1 & 0x7F)
	
	errors: [dynamic]string
	defer delete(errors)
	
	// Validate RSV bits
	if rsv1 || rsv2 || rsv3 {
		append(&errors, "RSV bits set")
	}
	
	// Validate opcode
	#partial switch opcode_val {
	case .Close, .Ping, .Pong:
		if payload_len > MAX_CONTROL_FRAME_PAYLOAD_SIZE {
			append(&errors, "control frame payload too large")
		}
		if !fin {
			append(&errors, "FIN not set on control frame")
		}
	case .Text, .Binary:
		if !c.read_final {
			append(&errors, "data before FIN")
		}
		c.read_final = fin
	case .Continuation:
		if c.read_final {
			append(&errors, "continuation after FIN")
		}
		c.read_final = fin
	case:
		append(&errors, fmt.tprintf("unknown opcode: %d", opcode_val))
	}
	
	// Validate mask bit
	if masked != c.is_server {
		append(&errors, "bad MASK bit")
	}
	
	if len(errors) > 0 {
		handle_protocol_error(c, "protocol error")
		return .Continuation, os.EINVAL
	}
	
	// Read extended payload length
	if payload_len == 126 {
		len_buf: [2]byte
		_, recv_err := net.recv_tcp(c.conn, len_buf[:])
		if recv_err != nil {
			return .Continuation, os.EINVAL
		}
		val, _ := endian.get_u16(len_buf[:], .Big)
		payload_len = i64(val)
	} else if payload_len == 127 {
		len_buf: [8]byte
		_, recv_err := net.recv_tcp(c.conn, len_buf[:])
		if recv_err != nil {
			return .Continuation, os.EINVAL
		}
		val64, _ := endian.get_u64(len_buf[:], .Big)
		payload_len = i64(val64)
	}
	
	c.read_remaining = payload_len
	
	// Read mask key if present
	if masked {
		_, recv_err := net.recv_tcp(c.conn, c.read_mask_key[:])
		if recv_err != nil {
			return .Continuation, os.EINVAL
		}
		c.read_mask_pos = 0
	}
	
	// For data frames, enforce read limit
	if is_data(opcode_val) || opcode_val == .Continuation {
		if c.read_limit > 0 && c.read_remaining > c.read_limit {
			deadline := time.time_add(time.now(), WRITE_WAIT)
			_ = write_control(c, .Close, format_close_message(.MessageTooBig, ""), deadline)
			return .Continuation, os.EINVAL
		}
		return opcode_val, os.ERROR_NONE
	}
	
	// Handle control frames
	if payload_len > 0 {
		payload := make([]byte, payload_len)
		defer delete(payload)
		_, recv_err := net.recv_tcp(c.conn, payload)
		if recv_err != nil {
			return .Continuation, os.EINVAL
		}
		if c.is_server {
			mask_bytes(c.read_mask_key, 0, payload)
		}
		
		#partial switch opcode_val {
		case .Pong:
			_ = c.handle_pong(string(payload))
		case .Ping:
			_ = c.handle_ping(string(payload))
		case .Close:
			close_code := u16(1005)
			close_text := ""
			if len(payload) >= 2 {
				cc, _ := endian.get_u16(payload[0:2], .Big)
			close_code = cc
				if len(payload) > 2 {
					close_text = string(payload[2:])
					if !utf8.valid_string(close_text) {
						handle_protocol_error(c, "invalid UTF-8 in close frame")
						return .Continuation, os.EINVAL
					}
				}
			}
			_ = c.handle_close(close_code, close_text)
			c.state = .Closing
			return .Continuation, os.ECONNREFUSED
		}
	}
	
	return opcode_val, os.ERROR_NONE
}

// write_control writes a control message
write_control :: proc(c: ^Conn, opcode: Opcode, data: []byte, deadline: time.Time) -> os.Errno {
	if !is_control(opcode) {
		return os.EINVAL
	}
	if len(data) > MAX_CONTROL_FRAME_PAYLOAD_SIZE {
		return os.EINVAL
	}
	
	sync.mutex_lock(&c.write_mutex)
	defer sync.mutex_unlock(&c.write_mutex)
	
	// Build frame header
	b0 := byte(opcode) | 0x80
	b1 := byte(len(data))
	if !c.is_server {
		b1 |= 0x80
	}
	
	buf: [MAX_FRAME_HEADER_SIZE + MAX_CONTROL_FRAME_PAYLOAD_SIZE]byte
	buf[0] = b0
	buf[1] = b1
	pos := 2
	
	if c.is_server {
		copy(buf[pos:], data)
		pos += len(data)
	} else {
		mask := generate_mask_key()
		copy(buf[pos:], mask[:])
		pos += 4
		copy(buf[pos:], data)
		mask_bytes(mask, 0, buf[pos:pos+len(data)])
		pos += len(data)
	}
	
	// Set deadline
	if time.time_to_unix_nano(deadline) != 0 {
		timeout_ms := int(time.duration_milliseconds(time.since(deadline)))
		if timeout_ms < 0 { timeout_ms = 0 }
		net.set_option(c.conn, net.Socket_Option.Send_Timeout, timeout_ms)
	}
	
	_, send_err := net.send_tcp(c.conn, buf[:pos])
	if send_err != nil {
		return os.EINVAL
	}
	return os.ERROR_NONE
}

// write_message writes a data message
write_message :: proc(c: ^Conn, opcode: Opcode, data: []byte) -> os.Errno {
	if c.state != .Open {
		return os.ECONNREFUSED
	}
	
	if !is_data(opcode) {
		return os.EINVAL
	}
	
	sync.mutex_lock(&c.write_mutex)
	defer sync.mutex_unlock(&c.write_mutex)
	
	// Clear write buffer
	clear(&c.write_buf)
	
	// Reserve space for frame header
	header_start := len(c.write_buf)
	resize(&c.write_buf, len(c.write_buf) + MAX_FRAME_HEADER_SIZE)
	
	// Write payload
	payload_start := len(c.write_buf)
	append(&c.write_buf, ..data)
	
	payload_len := len(data)
	
	// Determine frame header size
	header_len: int
	b0 := byte(opcode) | 0x80
	
	if payload_len < 126 {
		c.write_buf[header_start] = b0
		c.write_buf[header_start + 1] = byte(payload_len)
		header_len = 2
	} else if payload_len < 65536 {
		c.write_buf[header_start] = b0
		c.write_buf[header_start + 1] = 126
		endian.put_u16(c.write_buf[header_start+2:], .Big, u16(payload_len))
		header_len = 4
	} else {
		c.write_buf[header_start] = b0
		c.write_buf[header_start + 1] = 127
		endian.put_u64(c.write_buf[header_start+2:], .Big, u64(payload_len))
		header_len = 10
	}
	
	// Apply mask if client
	if !c.is_server {
		c.write_buf[header_start + 1] |= 0x80
		mask := generate_mask_key()
		copy(c.write_buf[header_start + header_len:], mask[:])
		header_len += 4
		mask_bytes(mask, 0, c.write_buf[payload_start:])
	}
	
	// Send frame
	frame := c.write_buf[header_start:payload_start+payload_len]
	_, send_err := net.send_tcp(c.conn, frame)
	if send_err != nil {
		return os.EINVAL
	}
	
	return os.ERROR_NONE
}

// read_message reads a complete message
read_message :: proc(c: ^Conn) -> (opcode: Opcode, data: []byte, err: os.Errno) {
	if c.state != .Open {
		return .Continuation, nil, os.ECONNREFUSED
	}
	
	clear(&c.read_buf)
	
	for {
		frame_opcode, frame_err := advance_frame(c)
		if frame_err != os.ERROR_NONE {
			return .Continuation, nil, frame_err
		}
		
		// Skip control frames
		if is_control(frame_opcode) {
			continue
		}
		
		// Read frame payload
		if c.read_remaining > 0 {
			payload := make([]byte, c.read_remaining)
			_, recv_err := net.recv_tcp(c.conn, payload)
			if recv_err != nil {
				delete(payload)
				return .Continuation, nil, os.EINVAL
			}
			
			// Unmask if server
			if c.is_server {
				mask_bytes(c.read_mask_key, c.read_mask_pos, payload)
			}
			
			append(&c.read_buf, ..payload)
			delete(payload)
		}
		
		// Check if this is the final frame
		if c.read_final {
			break
		}
	}
	
	return c.read_msg_type, c.read_buf[:], os.ERROR_NONE
}

// handle_protocol_error handles protocol errors
handle_protocol_error :: proc(c: ^Conn, message: string) {
	data := format_close_message(.ProtocolError, message)
	deadline := time.time_add(time.now(), WRITE_WAIT)
	_ = write_control(c, .Close, data, deadline)
}

// format_close_message formats a close message payload
format_close_message :: proc(code: CloseCode, text: string) -> []byte {
	buf := make([]byte, 2 + len(text))
	endian.put_u16(buf, .Big, u16(code))
	copy(buf[2:], text)
	return buf
}

// generate_mask_key generates a random 4-byte mask key
generate_mask_key :: proc() -> [4]byte {
	key: [4]byte
	counter: u32 = 0
	counter += 1
	endian.put_u32(key[:], .Little, counter)
	return key
}

// set_read_limit sets the maximum message size
set_read_limit :: proc(c: ^Conn, limit: i64) {
	c.read_limit = limit
}

// set_ping_handler sets the handler for ping messages
set_ping_handler :: proc(c: ^Conn, handler: proc(data: string) -> os.Errno) {
	if handler == nil {
		c.handle_ping = proc(data: string) -> os.Errno {
			return os.ERROR_NONE
		}
	} else {
		c.handle_ping = handler
	}
}

// set_pong_handler sets the handler for pong messages
set_pong_handler :: proc(c: ^Conn, handler: proc(data: string) -> os.Errno) {
	if handler == nil {
		c.handle_pong = proc(data: string) -> os.Errno {
			return os.ERROR_NONE
		}
	} else {
		c.handle_pong = handler
	}
}

// set_close_handler sets the handler for close messages
set_close_handler :: proc(c: ^Conn, handler: proc(code: u16, text: string) -> os.Errno) {
	if handler == nil {
		c.handle_close = proc(code: u16, text: string) -> os.Errno {
			return os.ERROR_NONE
		}
	} else {
		c.handle_close = handler
	}
}

// SetWriteDeadline sets the write deadline for the connection
set_write_deadline :: proc(c: ^Conn, deadline: time.Time) {
	c.write_deadline = deadline
	if time.time_to_unix_nano(deadline) != 0 {
		timeout_ms := int(time.duration_milliseconds(time.since(deadline)))
		if timeout_ms < 0 { timeout_ms = 0 }
		net.set_option(c.conn, net.Socket_Option.Send_Timeout, timeout_ms)
	}
}

// SetReadDeadline sets the read deadline for the connection
set_read_deadline :: proc(c: ^Conn, deadline: time.Time) {
	c.read_deadline = deadline
	if time.time_to_unix_nano(deadline) != 0 {
		timeout_ms := int(time.duration_milliseconds(time.since(deadline)))
		if timeout_ms < 0 { timeout_ms = 0 }
		net.set_option(c.conn, net.Socket_Option.Receive_Timeout, timeout_ms)
	}
}

// WriteMessage writes a message to the connection
write_message_public :: proc(c: ^Conn, message_type: int, data: []byte) -> os.Errno {
	opcode: Opcode
	switch message_type {
	case 1:
		opcode = .Text
	case 2:
		opcode = .Binary
	case:
		return os.EINVAL
	}
	
	return write_message(c, opcode, data)
}

// ReadMessage reads a message from the connection
read_message_public :: proc(c: ^Conn) -> (message_type: int, data: []byte, err: os.Errno) {
	opcode, data0, err0 := read_message(c)
	
	if err0 != os.ERROR_NONE {
		return 0, nil, err0
	}
	
	#partial switch opcode {
	case .Text:
		return Text_Message, data0, os.ERROR_NONE
	case .Binary:
		return Binary_Message, data0, os.ERROR_NONE
	case:
		return 0, nil, os.EINVAL
	}
}

// Close sends a close frame and closes the connection
close_connection_public :: proc(c: ^Conn) -> os.Errno {
	if c.state != .Open {
		return os.ECONNREFUSED
	}
	
	// Send close frame
	deadline := time.time_add(time.now(), WRITE_WAIT)
	_ = write_control(c, .Close, format_close_message(.NormalClosure, ""), deadline)
	
	return close_connection(c)
}

// Streaming API for incremental read/write

// MessageReader provides streaming read interface for WebSocket messages
MessageReader :: struct {
	conn:      ^Conn,
	opcode:    Opcode,
	reader:    strings.Reader,
	remaining: int,
	first:     bool,
	next_read_count: int,
}

// NextReader returns a reader for the next message
next_reader :: proc(c: ^Conn) -> (r: ^MessageReader, err: os.Errno) {
	// Check connection state
	if c.state != .Open {
		return nil, os.ECONNREFUSED
	}
	
	// Read the next frame header
	frame_opcode, frame_err := advance_frame(c)
	if frame_err != os.ERROR_NONE {
		return nil, frame_err
	}
	
	// Skip control frames (handled internally)
	if is_control(frame_opcode) {
		// Read ahead for data frame
		reader, reader_err := next_reader(c)
		return reader, reader_err
	}
	
	// Check if it's a data frame
	if !is_data(frame_opcode) {
		return nil, os.EINVAL
	}
	
	// For continuation frames, track message type
	if frame_opcode == .Continuation {
		c.read_msg_type = c.read_msg_type
	} else {
		c.read_msg_type = frame_opcode
	}
	
	// Create reader
	mr := new(MessageReader)
	mr.conn = c
	mr.opcode = frame_opcode
	mr.remaining = int(c.read_remaining)
	mr.first = true
	
	return mr, os.ERROR_NONE
}

// Read reads from the message reader
message_reader_read :: proc(r: ^MessageReader, p: []byte) -> (n: int, err: os.Errno) {
	if r.remaining <= 0 {
		return 0, os.ERROR_NONE
	}
	
	// Calculate read size
	to_read := r.remaining
	if to_read > len(p) {
		to_read = len(p)
	}
	
	// Read from connection
	actual_read, recv_err := net.recv_tcp(r.conn.conn, p[:to_read])
	if recv_err != nil {
		return int(actual_read), os.EINVAL
	}
	
	// Unmask if server
	if r.conn.is_server && actual_read > 0 {
		mask_bytes(r.conn.read_mask_key, r.conn.read_mask_pos, p[:actual_read])
		r.conn.read_mask_pos = (r.conn.read_mask_pos + int(actual_read)) % 4
	}
	
	r.remaining -= int(actual_read)
	r.next_read_count += 1
	
	return int(actual_read), os.ERROR_NONE
}

// Close closes the message reader
message_reader_close :: proc(r: ^MessageReader) -> os.Errno {
	// Skip any remaining bytes in this frame
	if r.remaining > 0 {
		to_skip := make([]byte, r.remaining)
		defer delete(to_skip)
		_, recv_err := net.recv_tcp(r.conn.conn, to_skip)
		if recv_err != nil {
			return os.EINVAL
		}
	}
	
	return os.ERROR_NONE
}

// MessageWriter provides streaming write interface for WebSocket messages
MessageWriter :: struct {
	conn:   ^Conn,
	opcode: Opcode,
	pos:    int,
	closed: bool,
	payload: [dynamic]byte,
}

// NextWriter returns a writer for the next message
next_writer :: proc(c: ^Conn, message_type: int) -> (w: ^MessageWriter, err: os.Errno) {
	if c.state != .Open {
		return nil, os.ECONNREFUSED
	}
	
	// Map int message type to opcode
	opcode: Opcode
	switch message_type {
	case 1:
		opcode = .Text
	case 2:
		opcode = .Binary
	case:
		return nil, os.EINVAL
	}
	
	// Clear write buffer
	clear(&c.write_buf)
	
	// Reserve space for frame header
	header_start := len(c.write_buf)
	resize(&c.write_buf, len(c.write_buf) + MAX_FRAME_HEADER_SIZE)
	
	// Create writer
	mw := new(MessageWriter)
	mw.conn = c
	mw.opcode = opcode
	mw.pos = header_start + MAX_FRAME_HEADER_SIZE
	mw.closed = false
	
	return mw, os.ERROR_NONE
}

// Write writes to the message writer
message_writer_write :: proc(w: ^MessageWriter, p: []byte) -> (n: int, err: os.Errno) {
	if w.closed {
		return 0, os.ECONNREFUSED
	}
	
	// Append to payload
	append(&w.payload, ..p)
	return len(p), os.ERROR_NONE
}

// Close flushes the message writer and sends the message
message_writer_close :: proc(w: ^MessageWriter) -> os.Errno {
	if w.closed {
		return os.ERROR_NONE
	}
	w.closed = true
	
	// Append payload to connection's write buffer
	payload_start := len(w.conn.write_buf)
	for b in w.payload { append(&w.conn.write_buf, b) }
	payload_len := len(w.payload)
	
	// Now build the frame header
	header_start := w.pos - MAX_FRAME_HEADER_SIZE
	b0 := byte(w.opcode) | 0x80
	
	header_len: int
	if payload_len < 126 {
		w.conn.write_buf[header_start] = b0
		w.conn.write_buf[header_start + 1] = byte(payload_len)
		header_len = 2
	} else if payload_len < 65536 {
		w.conn.write_buf[header_start] = b0
		w.conn.write_buf[header_start + 1] = 126
		endian.put_u16(w.conn.write_buf[header_start+2:], .Big, u16(payload_len))
		header_len = 4
	} else {
		w.conn.write_buf[header_start] = b0
		w.conn.write_buf[header_start + 1] = 127
		endian.put_u64(w.conn.write_buf[header_start+2:], .Big, u64(payload_len))
		header_len = 10
	}
	
	// Apply mask if client
	if !w.conn.is_server {
		w.conn.write_buf[header_start + 1] |= 0x80
		mask := generate_mask_key()
		copy(w.conn.write_buf[header_start + header_len:], mask[:])
		header_len += 4
		mask_bytes(mask, 0, w.conn.write_buf[payload_start:])
	}
	
	// Send frame
	frame := w.conn.write_buf[header_start:payload_start+payload_len]
	_, send_err := net.send_tcp(w.conn.conn, frame)
	if send_err != nil {
		delete(w.payload)
		return os.EINVAL
	}
	
	// Clean up
	delete(w.payload)
	
	return os.ERROR_NONE
}
