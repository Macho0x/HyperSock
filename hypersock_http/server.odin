package hypersock_http

/*
 * HTTP Server Implementation
 * Based on fasthttp server.go patterns
 * 
 * Features:
 * - RequestCtx pattern for request/response lifecycle
 * - Connection pooling and reuse
 * - Concurrent request handling
 * - Graceful shutdown support
 * - Keep-alive connections
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:strconv"
import "core:time"
import "core:sync"
import "core:thread"
import "core:mem"

// ConnectionQueue is a thread-safe queue for accepted connections
ConnectionQueue :: struct {
	mutex:    sync.Mutex,
	cond:     sync.Cond,
	items:    [dynamic]net.TCP_Socket,
	closed:   bool,
}

// Queue initialization
queue_init :: proc(q: ^ConnectionQueue) {
	q.items = make([dynamic]net.TCP_Socket)
	q.closed = false
}

// Queue cleanup
queue_destroy :: proc(q: ^ConnectionQueue) {
	sync.mutex_lock(&q.mutex)
	q.closed = true
	sync.cond_broadcast(&q.cond)
	sync.mutex_unlock(&q.mutex)
	delete(q.items)
}

// Push a connection to the queue
queue_push :: proc(q: ^ConnectionQueue, conn: net.TCP_Socket) -> bool {
	sync.mutex_lock(&q.mutex)
	if q.closed {
		sync.mutex_unlock(&q.mutex)
		return false
	}
	append(&q.items, conn)
	sync.cond_signal(&q.cond)
	sync.mutex_unlock(&q.mutex)
	return true
}

// Pop a connection from the queue (blocking)
queue_pop :: proc(q: ^ConnectionQueue) -> (net.TCP_Socket, bool) {
	sync.mutex_lock(&q.mutex)
	for len(q.items) == 0 && !q.closed {
		sync.cond_wait(&q.cond, &q.mutex)
	}
	if q.closed && len(q.items) == 0 {
		sync.mutex_unlock(&q.mutex)
		return {}, false
	}
	conn := pop_front(&q.items)
	sync.mutex_unlock(&q.mutex)
	return conn, true
}

// Signal all waiting threads to wake up
queue_close :: proc(q: ^ConnectionQueue) {
	sync.mutex_lock(&q.mutex)
	q.closed = true
	sync.cond_broadcast(&q.cond)
	sync.mutex_unlock(&q.mutex)
}

// Check if queue is closed
queue_is_closed :: proc(q: ^ConnectionQueue) -> bool {
	sync.mutex_lock(&q.mutex)
	closed := q.closed
	sync.mutex_unlock(&q.mutex)
	return closed
}

// Server implements HTTP server
Server :: struct {
	handler:          RequestHandler,
	name:             string,
	read_buffer_size: int,
	write_buffer_size: int,
	read_timeout:     time.Duration,
	write_timeout:    time.Duration,
	idle_timeout:     time.Duration,
	max_body_size:    int,
	concurrency:      int,
	
	// Internal fields
	listen:           net.TCP_Socket,
	accept_queue:     ConnectionQueue,
	wg:               sync.Wait_Group,
	running_mutex:    sync.Mutex,
	running:          bool,
}

// Server thread context data
AcceptThreadData :: struct {
	server: ^Server,
}

WorkerThreadData :: struct {
	server: ^Server,
	id:     int,
}

// HijackHandler is called when a connection is hijacked
Hijack_Handler :: proc(^RequestCtx) -> (net.TCP_Socket, os.Errno)

// RequestCtx contains incoming request and manages outgoing response
RequestCtx :: struct {
	request:      Request,
	response:     Response,
	conn:         net.TCP_Socket,
	conn_time:    time.Time,
	request_num:  u64,
	remote_addr:  net.Address,
	local_addr:   net.Address,
	
	// User data storage
	user_data:    map[string]any,
	
	// Connection hijacking
	hijacked:     bool,
}

// Create new HTTP server
server_new :: proc(handler: RequestHandler) -> ^Server {
	s := new(Server)
	s.handler = handler
	s.name = "odin-http-server"
	s.read_buffer_size = 4096
	s.write_buffer_size = 4096
	s.read_timeout = 30 * time.Second
	s.write_timeout = 30 * time.Second
	s.idle_timeout = 10 * time.Second
	s.max_body_size = 4 * 1024 * 1024  // 4MB
	s.concurrency = 256
	s.running = false
	
	queue_init(&s.accept_queue)
	
	return s
}

// Destroy server and free memory
server_destroy :: proc(s: ^Server) {
	if s == nil {
		return
	}
	
	// Shutdown if running
	if server_is_running(s) {
		shutdown(s)
	}
	
	// Clean up queue
	queue_destroy(&s.accept_queue)
	
	// Free server
	free(s)
}

// ListenAndServe starts HTTP server on addr
listen_and_serve :: proc(s: ^Server, addr: string) -> os.Errno {
	// Create listener
	endpoint, endpoint_err := net.parse_endpoint(addr)
	if endpoint_err {
		return os.EINVAL
	}
	
	listen_socket, listen_err := net.listen_tcp(endpoint)
	if listen_err != nil {
		return os.ECONNREFUSED
	}
	s.listen = listen_socket
	
	sync.mutex_lock(&s.running_mutex)
	s.running = true
	sync.mutex_unlock(&s.running_mutex)
	
	fmt.printf("Server listening on %s\n", addr)
	
	// Start accept thread
	accept_data := new(AcceptThreadData)
	accept_data.server = s
	sync.wait_group_add(&s.wg, 1)
	accept_thread := thread.create(proc(t: ^thread.Thread) {
		accept_data := cast(^AcceptThreadData)t.data
		server_accept(accept_data.server)
		free(accept_data)
	})
	accept_thread.data = accept_data
	thread.start(accept_thread)
	
	// Start worker pool
	for i := 0; i < s.concurrency; i += 1 {
		worker_data := new(WorkerThreadData)
		worker_data.server = s
		worker_data.id = i
		sync.wait_group_add(&s.wg, 1)
		worker_thread := thread.create(proc(t: ^thread.Thread) {
			worker_data := cast(^WorkerThreadData)t.data
			server_worker(worker_data.server, worker_data.id)
			free(worker_data)
		})
		worker_thread.data = worker_data
		thread.start(worker_thread)
	}
	
	// Wait for shutdown signal (block main thread)
	sync.wait_group_wait(&s.wg)
	
	// Close listener
	net.close(s.listen)
	
	return os.ERROR_NONE
}

// Check if server is running
server_is_running :: proc(s: ^Server) -> bool {
	sync.mutex_lock(&s.running_mutex)
	running := s.running
	sync.mutex_unlock(&s.running_mutex)
	return running
}

// Accept incoming connections
server_accept :: proc(s: ^Server) {
	defer sync.wait_group_done(&s.wg)
	
	for server_is_running(s) {
		conn, _, accept_err := net.accept_tcp(s.listen)
		if accept_err != nil {
			if server_is_running(s) {
				fmt.println("Accept error:", accept_err)
			}
			continue
		}
		
		// Try to push to queue, exit if shutdown
		if !queue_push(&s.accept_queue, conn) {
			net.close(conn)
			return
		}
	}
}

// Worker handles connections
server_worker :: proc(s: ^Server, worker_id: int) {
	defer sync.wait_group_done(&s.wg)
	
	for {
		conn, ok := queue_pop(&s.accept_queue)
		if !ok {
			// Queue closed, exit worker
			return
		}
		
		server_handle_connection(s, conn)
	}
}

// Handle a single connection (with keep-alive)
server_handle_connection :: proc(s: ^Server, conn: net.TCP_Socket) {
	// Check if connection was hijacked before closing
	hijacked := false
	
	defer {
		if !hijacked {
			net.close(conn)
		}
	}
	
	// Set timeouts using socket options
	if s.read_timeout > 0 {
		net.set_option(conn, .Receive_Timeout, int(s.read_timeout))
	}
	if s.write_timeout > 0 {
		net.set_option(conn, .Send_Timeout, int(s.write_timeout))
	}
	
	ctx: RequestCtx
	ctx.conn = conn
	ctx.conn_time = time.now()
	ctx.request_num = 1
	ctx.remote_addr = {}
	ctx.local_addr = {}
	
	for server_is_running(s) {
		// Read request
		err := read_request(conn, &ctx.request)
		if err != os.ERROR_NONE {
			if err != os.ECONNRESET {
				fmt.println("Read error:", err)
			}
			break
		}
		
		// Reset response
		response_reset(&ctx.response)
		
		// Set default headers
		header_set(&ctx.response.header, "Server", s.name)
	header_set(&ctx.response.header, "Date", fmt.tprintf("%v", time.now()))
		
		// Call handler
		s.handler(&ctx)
		
		// Write response
		err = write_response(conn, &ctx.response)
		if err != os.ERROR_NONE {
			fmt.println("Write error:", err)
			break
		}
		
		// Check if connection was hijacked
		if ctx.hijacked {
			hijacked = true
			break
		}
		
		// Check if connection should be closed
		connection := header_get(&ctx.request.header, "Connection")
		if strings.to_lower(connection) == "close" ||
		   ctx.response.status_code >= 400 {
			break
		}
		
		ctx.request_num += 1
	}
}

// Shutdown gracefully shuts down server
shutdown :: proc(s: ^Server) {
	sync.mutex_lock(&s.running_mutex)
	s.running = false
	sync.mutex_unlock(&s.running_mutex)
	
	// Close the accept queue to signal workers to exit
	queue_close(&s.accept_queue)
	
	// Close the listener to unblock accept()
	if s.listen != {} {
		net.close(s.listen)
	}
}

// RequestCtx utility methods

// SetStatusCode sets response status code
set_status_code :: proc(ctx: ^RequestCtx, status: int) {
	ctx.response.status_code = status
}

// SetBody sets response body (as byte slice)
set_body :: proc(ctx: ^RequestCtx, body: []byte) {
	ctx.response.body = make([]byte, len(body))
	copy(ctx.response.body, body)
}

// SetBodyString sets response body (as string)
set_body_string :: proc(ctx: ^RequestCtx, body: string) {
	set_body(ctx, transmute([]byte)body)
}

// SetContentType sets Content-Type header on response
set_content_type :: proc(ctx: ^RequestCtx, content_type: string) {
	header_set(&ctx.response.header, "Content-Type", content_type)
}

// SetHeader sets a header on response
set_header :: proc(ctx: ^RequestCtx, name, value: string) {
	header_set(&ctx.response.header, name, value)
}

// Write writes data to response body
write :: proc(ctx: ^RequestCtx, data: []byte) -> int {
	// Append data to body
	new_body := make([]byte, len(ctx.response.body) + len(data))
	copy(new_body, ctx.response.body)
	copy(new_body[len(ctx.response.body):], data)
	ctx.response.body = new_body
	return len(data)
}

// WriteString writes string to response body
write_string :: proc(ctx: ^RequestCtx, data: string) -> int {
	return write(ctx, transmute([]byte)data)
}

// GetRequest returns the request
get_request :: proc(ctx: ^RequestCtx) -> ^Request {
	return &ctx.request
}

// GetResponse returns the response
get_response :: proc(ctx: ^RequestCtx) -> ^Response {
	return &ctx.response
}

// GetConn returns the underlying connection
get_conn :: proc(ctx: ^RequestCtx) -> net.TCP_Socket {
	return ctx.conn
}

// RemoteAddr returns the remote address
remote_addr :: proc(ctx: ^RequestCtx) -> net.Address {
	return ctx.remote_addr
}

// LocalAddr returns the local address
local_addr :: proc(ctx: ^RequestCtx) -> net.Address {
	return ctx.local_addr
}

// ConnTime returns when the connection was accepted
conn_time :: proc(ctx: ^RequestCtx) -> time.Time {
	return ctx.conn_time
}

// RequestNum returns the request sequence number
request_num :: proc(ctx: ^RequestCtx) -> u64 {
	return ctx.request_num
}

// SetUserValue stores a value in the context
set_user_value :: proc(ctx: ^RequestCtx, key: string, value: any) {
	if ctx.user_data == nil {
		ctx.user_data = make(map[string]any)
	}
	ctx.user_data[key] = value
}

// GetUserValue retrieves a value from the context
get_user_value :: proc(ctx: ^RequestCtx, key: string) -> any {
	if ctx.user_data == nil {
		return nil
	}
	return ctx.user_data[key]
}

// Method returns the request method
method :: proc(ctx: ^RequestCtx) -> Method {
	return ctx.request.method
}

// Path returns the request path
path :: proc(ctx: ^RequestCtx) -> string {
	return ctx.request.uri.path
}

// Query returns the query string
query :: proc(ctx: ^RequestCtx) -> string {
	return ctx.request.uri.query
}

// Host returns the Host header
host :: proc(ctx: ^RequestCtx) -> string {
	return header_get(&ctx.request.header, "Host")
}

// UserAgent returns the User-Agent header
user_agent :: proc(ctx: ^RequestCtx) -> string {
	return header_get(&ctx.request.header, "User-Agent")
}

// ContentLength returns the Content-Length header
content_length :: proc(ctx: ^RequestCtx) -> int {
	length_str := header_get(&ctx.request.header, "Content-Length")
	if length_str == "" {
		return 0
	}
	// Parse integer using strconv
	if length, ok := strconv.parse_int(length_str, 10); ok {
		return int(length)
	}
	return 0
}

// FormValue returns the first value for the named component of the query string or POST form
form_value :: proc(ctx: ^RequestCtx, key: string) -> string {
	// First check query string
	if ctx.request.uri.query != "" {
		query_value := parse_query_value(ctx.request.uri.query, key)
		if query_value != "" {
			return query_value
		}
	}
	
	// Then check POST body if content-type is form data
	content_type := header_get(&ctx.request.header, "Content-Type")
	if strings.contains(content_type, "application/x-www-form-urlencoded") && len(ctx.request.body) > 0 {
		post_value := parse_form_value(string(ctx.request.body), key)
		if post_value != "" {
			return post_value
		}
	}
	
	return ""
}

// PostArgs parses and returns POST form arguments
post_args :: proc(ctx: ^RequestCtx) -> map[string]string {
	args: map[string]string
	
	if len(ctx.request.body) == 0 {
		return args
	}
	
	content_type := header_get(&ctx.request.header, "Content-Type")
	if !strings.contains(content_type, "application/x-www-form-urlencoded") {
		return args
	}
	
	return parse_form(string(ctx.request.body))
}

// parse_query_value extracts a value from URL query string
parse_query_value :: proc(query_str, key: string) -> string {
	pairs := strings.split(query_str, "&")
	defer delete(pairs)
	
	for pair in pairs {
		parts := strings.split(pair, "=")
		defer delete(parts)
		
		if len(parts) >= 1 {
			url_decode, _ := strings.replace(parts[0], "+", " ", -1)
			if url_decode == key {
				if len(parts) >= 2 {
					result, _ := strings.replace(parts[1], "+", " ", -1)
				return result
				}
				return ""
			}
		}
	}
	
	return ""
}

// parse_form_value extracts a value from form body
parse_form_value :: proc(form_str, key: string) -> string {
	pairs := strings.split(form_str, "&")
	defer delete(pairs)
	
	for pair in pairs {
		parts := strings.split(pair, "=")
		defer delete(parts)
		
		if len(parts) >= 1 {
			if parts[0] == key {
				if len(parts) >= 2 {
					return parts[1]
				}
				return ""
			}
		}
	}
	
	return ""
}

// parse_form parses a form string into a map
parse_form :: proc(form_str: string) -> map[string]string {
	result := make(map[string]string)
	
	pairs := strings.split(form_str, "&")
	defer delete(pairs)
	
	for pair in pairs {
		parts := strings.split(pair, "=")
		defer delete(parts)
		
		if len(parts) >= 1 {
			key := parts[0]
			if len(parts) >= 2 {
				result[key] = parts[1]
			} else {
				result[key] = ""
			}
		}
	}
	
	return result
}

// Hijack takes over the connection from the server
// Returns the underlying TCP socket
// After hijacking, the server will not close the connection
hijack :: proc(ctx: ^RequestCtx) -> (net.TCP_Socket, os.Errno) {
	if ctx.hijacked {
		return {}, os.EINVAL
	}
	ctx.hijacked = true
	return ctx.conn, os.ERROR_NONE
}

// String returns a string representation of the context
string_ctx :: proc(ctx: ^RequestCtx) -> string {
	return fmt.tprintf("[#%d %s<->%s %s %s]", 
		ctx.request_num,
		ctx.local_addr,
		ctx.remote_addr,
		method_to_string(ctx.request.method),
		ctx.request.uri.path)
}
