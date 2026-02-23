package hypersock_http

/*
 * High-Performance HTTP Client for Odin
 * Based on fasthttp patterns
 * 
 * Key features:
 * - Zero-allocation in hot paths
 * - Connection pooling and reuse
 * - RequestCtx pattern for request/response lifecycle
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

// HTTP Methods
Method :: enum {
	GET,
	POST,
	PUT,
	DELETE,
	HEAD,
	OPTIONS,
	PATCH,
}

method_to_string :: proc(m: Method) -> string {
	switch m {
	case .GET:     return "GET"
	case .POST:    return "POST"
	case .PUT:     return "PUT"
	case .DELETE:  return "DELETE"
	case .HEAD:    return "HEAD"
	case .OPTIONS: return "OPTIONS"
	case .PATCH:   return "PATCH"
	}
	return "GET"
}

// HTTP Status codes
Status_OK                   :: 200
Status_Created              :: 201
Status_Accepted             :: 202
Status_NoContent            :: 204
Status_MovedPermanently     :: 301
Status_Found                :: 302
Status_SeeOther             :: 303
Status_NotModified          :: 304
Status_TemporaryRedirect    :: 307
Status_PermanentRedirect    :: 308
Status_BadRequest           :: 400
Status_Unauthorized         :: 401
Status_Forbidden            :: 403
Status_NotFound             :: 404
Status_MethodNotAllowed     :: 405
Status_RequestTimeout       :: 408
Status_Conflict             :: 409
Status_Gone                 :: 410
Status_LengthRequired       :: 411
Status_PayloadTooLarge      :: 413
Status_URITooLong           :: 414
Status_UnsupportedMediaType :: 415
Status_TooManyRequests      :: 429
Status_InternalServerError  :: 500
Status_NotImplemented       :: 501
Status_BadGateway           :: 502
Status_ServiceUnavailable   :: 503
Status_GatewayTimeout       :: 504

// Header represents HTTP headers (supports multiple values per key)
Header :: struct {
	data: map[string][dynamic]string,
	mutex: sync.Mutex,
}

// Request represents an HTTP request
Request :: struct {
	method:   Method,
	uri:      URI,
	header:   Header,
	body:     []byte,
	timeout:  time.Duration,
	// User data for passing values between handlers
	user_data: map[string]any,
}

// Response represents an HTTP response
Response :: struct {
	status_code: int,
	header:      Header,
	body:        []byte,
	keep_body:   bool,  // Don't release body buffer after use
}

// URI represents a parsed URL
URI :: struct {
	scheme:   string,
	host:     string,
	port:     int,
	path:     string,
	query:    string,
	fragment: string,
	// Parsed query args
	query_args: Args,
}

// Args represents URL-encoded arguments
Args :: struct {
	data: map[string][dynamic]string,
}

// RequestCtx is defined in server.odin

// RequestHandler processes incoming requests
RequestHandler :: proc(ctx: ^RequestCtx)

// Server is defined in server.odin

// Client implements high-performance HTTP client
Client :: struct {
	host_clients:         map[string]^HostClient,
	mutex:                sync.RW_Mutex,
	max_conns_per_host:   int,
	max_idle_conn_duration: time.Duration,
	read_buffer_size:     int,
	write_buffer_size:    int,
	read_timeout:         time.Duration,
	write_timeout:        time.Duration,
	max_response_body_size: int,
	tls_config:           ^TLS_Config,
	name:                 string,
}

// TLS_Config is defined in tls.odin

// HostClient manages connections to a specific host
HostClient :: struct {
	addr:                  string,
	is_tls:                bool,
	max_conns:             int,
	conns:                 [dynamic]^clientConn,
	mutex:                 sync.Mutex,
	conns_count:           int,
	pending_requests:      int,
	max_idle_conn_duration: time.Duration,
	read_buffer_size:      int,
	write_buffer_size:     int,
	read_timeout:          time.Duration,
	write_timeout:         time.Duration,
	max_response_body_size: int,
	client:                ^Client,
}

// clientConn represents a pooled connection
clientConn :: struct {
	conn:        net.TCP_Socket,
	tls_socket:   ^TLS_Socket,  // TLS wrapper (nil for plain TCP)
	is_tls:      bool,          // Whether this is a TLS connection
	created:     time.Time,
	last_use:    time.Time,
}

// Default configuration values
Default_Max_Conns_Per_Host :: 512
Default_Max_Idle_Conn_Duration :: 10 * time.Second
Default_Read_Buffer_Size :: 4096
Default_Write_Buffer_Size :: 4096

// Error types
HTTP_Error :: enum {
	None,
	Timeout,
	NoFreeConnections,
	ConnectionClosed,
	BodyTooLarge,
	InvalidURL,
	TooManyRedirects,
}

// Global default client
_default_client: Client
_default_client_initialized: bool

// Initialize client with default settings
client_default :: proc() -> ^Client {
	if !_default_client_initialized {
		_default_client = Client{
			max_conns_per_host = Default_Max_Conns_Per_Host,
			max_idle_conn_duration = Default_Max_Idle_Conn_Duration,
			read_buffer_size = Default_Read_Buffer_Size,
			write_buffer_size = Default_Write_Buffer_Size,
			name = "odin-http-client",
		}
		_default_client_initialized = true
	}
	return &_default_client
}

// Create a new client
client_new :: proc() -> ^Client {
	c := new(Client)
	c.max_conns_per_host = Default_Max_Conns_Per_Host
	c.max_idle_conn_duration = Default_Max_Idle_Conn_Duration
	c.read_buffer_size = Default_Read_Buffer_Size
	c.write_buffer_size = Default_Write_Buffer_Size
	c.host_clients = make(map[string]^HostClient)
	return c
}

// Clean up client
client_destroy :: proc(c: ^Client) {
	if c == nil do return
	
	// Close all host clients
	for _, hc in c.host_clients {
		host_client_close(hc)
		free(hc)
	}
	delete(c.host_clients)
	
	if c != &_default_client {
		free(c)
	}
}

// Parse URL string into URI structure
uri_parse :: proc(url_str: string) -> (URI, bool) {
	uri: URI
	
	// Simple URL parser
	rest := url_str
	
	// Extract scheme
	if idx := strings.index(rest, "://"); idx != -1 {
		uri.scheme = strings.to_lower(rest[:idx])
		rest = rest[idx+3:]
	}
	
	// Extract fragment
	if idx := strings.index(rest, "#"); idx != -1 {
		uri.fragment = rest[idx+1:]
		rest = rest[:idx]
	}
	
	// Extract query
	if idx := strings.index(rest, "?"); idx != -1 {
		uri.query = rest[idx+1:]
		rest = rest[:idx]
		// Parse query args
		parse_args(&uri.query_args, uri.query)
	}
	
	// Extract host and port
	path_idx := strings.index(rest, "/")
	if path_idx == -1 {
		uri.host = rest
		uri.path = "/"
	} else {
		uri.host = rest[:path_idx]
		uri.path = rest[path_idx:]
	}
	
	// Check for port
	if idx := strings.last_index(uri.host, ":"); idx != -1 {
		port_str := uri.host[idx+1:]
		// Parse port using strconv
		if parsed_port, ok := strconv.parse_int(port_str, 10); ok {
			uri.port = int(parsed_port)
		} else {
			// Fallback to default ports on parse error
			if uri.scheme == "https" {
				uri.port = 443
			} else {
				uri.port = 80
			}
		}
		uri.host = uri.host[:idx]
	} else {
		// Default ports
		if uri.scheme == "https" {
			uri.port = 443
		} else {
			uri.port = 80
		}
	}
	
	return uri, true
}

// URL percent-decode a string
url_decode :: proc(s: string) -> string {
	if !strings.contains(s, "%") {
		return s
	}
	
	result := strings.builder_make()
	defer strings.builder_destroy(&result)
	
	for i := 0; i < len(s); i += 1 {
		if s[i] == '%' && i + 2 < len(s) {
			// Parse hex value
			hex_str := s[i+1:i+3]
			if val, ok := strconv.parse_int(hex_str, 16); ok {
				fmt.sbprintf(&result, "%c", byte(val))
				i += 2
			} else {
				strings.write_byte(&result, s[i])
			}
		} else if s[i] == '+' {
			strings.write_byte(&result, ' ')
		} else {
			strings.write_byte(&result, s[i])
		}
	}
	
	return strings.to_string(result)
}

// Parse query string into Args with URL decoding
parse_args :: proc(args: ^Args, query: string) {
	args.data = make(map[string][dynamic]string)
	
	pairs := strings.split(query, "&")
	defer delete(pairs)
	
	for pair in pairs {
		kv := strings.split(pair, "=")
		if len(kv) == 2 {
			key := url_decode(kv[0])
			value := url_decode(kv[1])
			if key not_in args.data {
				args.data[key] = make([dynamic]string)
			}
			append(&args.data[key], value)
		}
	}
}

// Get argument value
args_get :: proc(args: ^Args, key: string) -> string {
	if values, ok := args.data[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// Header operations
// header_set adds a value to a header (appends if key already exists)
header_set :: proc(h: ^Header, key, value: string) {
	sync.mutex_lock(&h.mutex)
	defer sync.mutex_unlock(&h.mutex)
	
	if h.data == nil {
		h.data = make(map[string][dynamic]string)
	}
	
	lower_key := strings.to_lower(key)
	if lower_key not_in h.data {
		h.data[lower_key] = make([dynamic]string)
	}
	append(&h.data[lower_key], value)
}

// header_replace replaces all values for a header key
header_replace :: proc(h: ^Header, key, value: string) {
	sync.mutex_lock(&h.mutex)
	defer sync.mutex_unlock(&h.mutex)
	
	if h.data == nil {
		h.data = make(map[string][dynamic]string)
	}
	
	lower_key := strings.to_lower(key)
	// Clear existing values if any
	if lower_key in h.data {
		clear(&h.data[lower_key])
	} else {
		h.data[lower_key] = make([dynamic]string)
	}
	append(&h.data[lower_key], value)
}

// header_get gets the first value for a header key
header_get :: proc(h: ^Header, key: string) -> string {
	sync.mutex_lock(&h.mutex)
	defer sync.mutex_unlock(&h.mutex)
	
	if h.data == nil {
		return ""
	}
	
	lower_key := strings.to_lower(key)
	if values, ok := h.data[lower_key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// header_get_all gets all values for a header key
header_get_all :: proc(h: ^Header, key: string) -> []string {
	sync.mutex_lock(&h.mutex)
	defer sync.mutex_unlock(&h.mutex)
	
	if h.data == nil {
		return nil
	}
	
	lower_key := strings.to_lower(key)
	if values, ok := h.data[lower_key]; ok {
		return values[:]
	}
	return nil
}

header_has :: proc(h: ^Header, key: string) -> bool {
	sync.mutex_lock(&h.mutex)
	defer sync.mutex_unlock(&h.mutex)
	
	if h.data == nil {
		return false
	}
	
	lower_key := strings.to_lower(key)
	values, ok := h.data[lower_key]
	return ok && len(values) > 0
}

// Reset request for reuse (zero-allocation pattern)
request_reset :: proc(r: ^Request) {
	r.method = .GET
	r.body = r.body[:0]
	if r.user_data != nil {
		clear(&r.user_data)
	}
	// Keep header map for reuse
}

// Reset response for reuse
response_reset :: proc(r: ^Response) {
	r.status_code = 0
	if !r.keep_body {
		r.body = r.body[:0]
	}
	// Keep header map for reuse
}

// Reset URI for reuse
uri_reset :: proc(u: ^URI) {
	u.scheme = ""
	u.host = ""
	u.port = 0
	u.path = "/"
	u.query = ""
	u.fragment = ""
	if u.query_args.data != nil {
		clear(&u.query_args.data)
	}
}


// URI Builder for constructing URIs

// URI_Builder helps build URLs programmatically
URI_Builder :: struct {
	scheme:   string,
	host:     string,
	port:     int,
	path:     string,
	query: strings.Builder,
	fragment: string,
}

// uri_builder_new creates a new URI builder
uri_builder_new :: proc() -> URI_Builder {
	builder: URI_Builder
	builder.scheme = "http"
	builder.port = 80
	builder.path = "/"
	// Builder is zero-initialized, no init needed
	return builder
}

// uri_builder_set_scheme sets the scheme (http, https, etc.)
uri_builder_set_scheme :: proc(b: ^URI_Builder, scheme: string) {
	b.scheme = scheme
	
	// Set default port based on scheme
	switch scheme {
	case "http":
		if b.port == 443 {
			b.port = 80
		}
	case "https":
		if b.port == 80 {
			b.port = 443
		}
	case:
		b.port = 80
	}
}

// uri_builder_set_host sets the host
uri_builder_set_host :: proc(b: ^URI_Builder, host: string) {
	b.host = host
}

// uri_builder_set_port sets the port
uri_builder_set_port :: proc(b: ^URI_Builder, port: int) {
	b.port = port
}

// uri_builder_set_path sets the path
uri_builder_set_path :: proc(b: ^URI_Builder, path: string) {
	b.path = path
}

// uri_builder_add_query adds a query parameter
uri_builder_add_query :: proc(b: ^URI_Builder, key, value: string) {
	if len(strings.to_string(b.query)) > 0 {
		fmt.sbprintf(&b.query, "&")
	}
	fmt.sbprintf(&b.query, "%s=%s", key, value)
}

// uri_builder_set_fragment sets the fragment
uri_builder_set_fragment :: proc(b: ^URI_Builder, fragment: string) {
	b.fragment = fragment
}

// uri_builder_build constructs the final URI string
uri_builder_build :: proc(b: ^URI_Builder) -> string {
	// Start with scheme://host
	result := strings.builder_make()
	defer strings.builder_destroy(&result)
	
	fmt.sbprintf(&result, "%s://%s", b.scheme, b.host)
	
	// Add port if non-default
	needs_port := false
	switch b.scheme {
	case "http":
		if b.port != 80 {
			needs_port = true
		}
	case "https":
		if b.port != 443 {
			needs_port = true
		}
	}
	
	if needs_port {
		fmt.sbprintf(&result, ":%d", b.port)
	}
	
	// Add path
	fmt.sbprintf(&result, "%s", b.path)
	
	// Add query string if present
	query_str := strings.to_string(b.query)
	if query_str != "" {
		fmt.sbprintf(&result, "?%s", query_str)
	}
	
	// Add fragment if present
	if b.fragment != "" {
		fmt.sbprintf(&result, "#%s", b.fragment)
	}
	
	return strings.to_string(result)
}

// uri_builder_destroy cleans up the URI builder
uri_builder_destroy :: proc(b: ^URI_Builder) {
	// Builder is zero-initialized, no cleanup needed
}

// Convenience function: build a URI from components
uri_build :: proc(scheme, host: string, port: int, path: string, query_map: map[string]string, fragment: string) -> string {
	builder := uri_builder_new()
	defer uri_builder_destroy(&builder)
	
	uri_builder_set_scheme(&builder, scheme)
	uri_builder_set_host(&builder, host)
	uri_builder_set_port(&builder, port)
	uri_builder_set_path(&builder, path)
	
	for key, value in query_map {
		uri_builder_add_query(&builder, key, value)
	}
	
	uri_builder_set_fragment(&builder, fragment)
	
	return uri_builder_build(&builder)
}
