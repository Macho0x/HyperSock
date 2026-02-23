package hypersock_test

/*
 * HTTP Module Tests
 * Tests for the hypersock_http package
 */

import http "../hypersock_http"
import "core:testing"
import "core:os"
import "core:fmt"

// Test URI parsing
@test
test_uri_parse_basic :: proc(t: ^testing.T) {
	uri, ok := http.uri_parse("https://example.com/path?query=value")
	
	testing.expect(t, ok, "URI parsing should succeed")
	testing.expect(t, uri.scheme == "https", "Scheme should be https")
	testing.expect(t, uri.host == "example.com", "Host should be example.com")
	testing.expect(t, uri.port == 443, "Port should be 443 for https")
	testing.expect(t, uri.path == "/path", "Path should be /path")
	testing.expect(t, uri.query == "query=value", "Query should be query=value")
}

@test
test_uri_parse_http :: proc(t: ^testing.T) {
	uri, ok := http.uri_parse("http://example.com:8080/api")
	
	testing.expect(t, ok, "URI parsing should succeed")
	testing.expect(t, uri.scheme == "http", "Scheme should be http")
	testing.expect(t, uri.host == "example.com", "Host should be example.com")
	testing.expect(t, uri.port == 8080, "Port should be 8080")
	testing.expect(t, uri.path == "/api", "Path should be /api")
}

@test
test_uri_parse_with_fragment :: proc(t: ^testing.T) {
	uri, ok := http.uri_parse("https://example.com/page#section")
	
	testing.expect(t, ok, "URI parsing should succeed")
	testing.expect(t, uri.path == "/page", "Path should be /page")
	testing.expect(t, uri.fragment == "section", "Fragment should be section")
}

// Test header operations
@test
test_header_set_get :: proc(t: ^testing.T) {
	h: http.Header
	
	http.header_set(&h, "Content-Type", "application/json")
	value := http.header_get(&h, "content-type")
	
	testing.expect(t, value == "application/json", "Header value should match")
}

@test
test_header_case_insensitive :: proc(t: ^testing.T) {
	h: http.Header
	
	http.header_set(&h, "X-Custom-Header", "value")
	value := http.header_get(&h, "x-custom-header")
	
	testing.expect(t, value == "value", "Header lookup should be case-insensitive")
}

@test
test_header_has :: proc(t: ^testing.T) {
	h: http.Header
	
	http.header_set(&h, "Authorization", "Bearer token")
	
	testing.expect(t, http.header_has(&h, "authorization"), "Should have header")
	testing.expect(t, !http.header_has(&h, "missing"), "Should not have missing header")
}

// Test request/response reset
@test
test_request_reset :: proc(t: ^testing.T) {
	req: http.Request
	req.method = .POST
	req.body = []byte{1, 2, 3}
	
	http.request_reset(&req)
	
	testing.expect(t, req.method == .GET, "Method should reset to GET")
	testing.expect(t, len(req.body) == 0, "Body should be empty after reset")
}

@test
test_response_reset :: proc(t: ^testing.T) {
	resp: http.Response
	resp.status_code = 200
	resp.body = []byte{1, 2, 3}
	
	http.response_reset(&resp)
	
	testing.expect(t, resp.status_code == 0, "Status code should reset to 0")
	testing.expect(t, len(resp.body) == 0, "Body should be empty after reset")
}

// Test URI builder
@test
test_uri_builder :: proc(t: ^testing.T) {
	builder := http.uri_builder_new()
	defer http.uri_builder_destroy(&builder)
	
	http.uri_builder_set_scheme(&builder, "https")
	http.uri_builder_set_host(&builder, "api.example.com")
	http.uri_builder_set_port(&builder, 443)
	http.uri_builder_set_path(&builder, "/v1/users")
	http.uri_builder_add_query(&builder, "page", "1")
	http.uri_builder_add_query(&builder, "limit", "10")
	
	url := http.uri_builder_build(&builder)
	
	testing.expect(t, url == "https://api.example.com/v1/users?page=1&limit=10", "Built URL should match")
}

@test
test_uri_builder_http_port :: proc(t: ^testing.T) {
	builder := http.uri_builder_new()
	defer http.uri_builder_destroy(&builder)
	
	http.uri_builder_set_scheme(&builder, "http")
	http.uri_builder_set_host(&builder, "example.com")
	http.uri_builder_set_port(&builder, 8080)
	http.uri_builder_set_path(&builder, "/test")
	
	url := http.uri_builder_build(&builder)
	
	testing.expect(t, url == "http://example.com:8080/test", "URL with non-default port should include port")
}

// Test cookie jar
@test
test_cookie_jar :: proc(t: ^testing.T) {
	jar := http.cookie_jar_new()
	defer http.cookie_jar_destroy(jar)
	
	cookie := http.Cookie{
		name = "session",
		value = "abc123",
		domain = "example.com",
		path = "/",
	}
	
	http.set_cookie(jar, &cookie)
	
	cookies, err := http.get_cookies(jar, "https://example.com/page")
	
	testing.expect(t, err == os.ERROR_NONE, "Get cookies should not error")
	testing.expect(t, len(cookies) == 1, "Should have one cookie")
	testing.expect(t, cookies[0].name == "session", "Cookie name should match")
	testing.expect(t, cookies[0].value == "abc123", "Cookie value should match")
}

// Test method to string
@test
test_method_to_string :: proc(t: ^testing.T) {
	testing.expect(t, http.method_to_string(.GET) == "GET", "GET method")
	testing.expect(t, http.method_to_string(.POST) == "POST", "POST method")
	testing.expect(t, http.method_to_string(.PUT) == "PUT", "PUT method")
	testing.expect(t, http.method_to_string(.DELETE) == "DELETE", "DELETE method")
}

// Test args parsing
@test
test_parse_args :: proc(t: ^testing.T) {
	args: http.Args
	http.parse_args(&args, "key1=value1&key2=value2")
	
	value1 := http.args_get(&args, "key1")
	value2 := http.args_get(&args, "key2")
	
	testing.expect(t, value1 == "value1", "First arg should match")
	testing.expect(t, value2 == "value2", "Second arg should match")
}

// Test redirect status detection
@test
test_is_redirect_status :: proc(t: ^testing.T) {
	testing.expect(t, http.is_redirect_status(301), "301 should be redirect")
	testing.expect(t, http.is_redirect_status(302), "302 should be redirect")
	testing.expect(t, http.is_redirect_status(307), "307 should be redirect")
	testing.expect(t, http.is_redirect_status(308), "308 should be redirect")
	testing.expect(t, !http.is_redirect_status(200), "200 should not be redirect")
	testing.expect(t, !http.is_redirect_status(404), "404 should not be redirect")
}

// Test client creation and destruction
@test
test_client_lifecycle :: proc(t: ^testing.T) {
	client := http.client_new()
	testing.expect(t, client != nil, "Client should be created")
	
	// Check default values
	testing.expect(t, client.max_conns_per_host == http.Default_Max_Conns_Per_Host, "Default max conns")
	testing.expect(t, client.read_buffer_size == http.Default_Read_Buffer_Size, "Default read buffer")
	
	http.client_destroy(client)
}

// Test server creation
@test
test_server_creation :: proc(t: ^testing.T) {
	handler :: proc(ctx: ^http.RequestCtx) {
		http.set_status_code(ctx, 200)
		http.write_string(ctx, "OK")
	}
	
	server := http.server_new(handler)
	testing.expect(t, server != nil, "Server should be created")
	testing.expect(t, server.handler != nil, "Handler should be set")
	testing.expect(t, server.concurrency == 256, "Default concurrency")
	testing.expect(t, server.max_body_size == 4 * 1024 * 1024, "Default max body size")
	
	http.server_destroy(server)
}

// Test TLS config
@test
test_tls_config_default :: proc(t: ^testing.T) {
	config := http.tls_config_default()
	
	testing.expect(t, config.min_version == .Version_1_2, "Default min version should be TLS 1.2")
	testing.expect(t, config.max_version == .Version_1_3, "Default max version should be TLS 1.3")
	testing.expect(t, !config.insecure_skip_verify, "Default should verify certificates")
}

// Main test runner
main :: proc() {
	fmt.println("Running HyperSock HTTP tests...")
	
	// Individual tests are run automatically by the test runner
	// when using `odin test` command
}
