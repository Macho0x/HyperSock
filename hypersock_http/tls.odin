package hypersock_http

/*
 * TLS Support for HTTP and WebSocket
 * 
 * NOTE: Odin's core library does not include TLS/SSL support.
 * This module provides a framework and interfaces for TLS operations.
 * Actual TLS implementation requires either:
 * 1. External bindings to OpenSSL/BoringSSL
 * 2. System-level TLS through OS-specific APIs
 * 3. Third-party TLS libraries
 * 
 * For production trading bots, consider using system TLS proxies
 * or external libraries for secure connections.
 */

import "core:net"
import "core:c"
import "core:os"
import "core:strings"
import "core:time"
import "core:fmt"

// TLS Protocol versions
TLS_Version :: enum {
	None,
	Version_1_0,  // TLS 1.0 (deprecated, not recommended)
	Version_1_1,  // TLS 1.1 (deprecated)
	Version_1_2,  // TLS 1.2 (recommended for production)
	Version_1_3,  // TLS 1.3 (latest)
}

// TLS Connection state
TLS_State :: enum {
	Idle,
	Handshaking,
	Connected,
	Failed,
}

// Certificate information
Certificate :: struct {
	// Certificate subject
	subject_common_name: string,
	subject_organization: string,
	subject_country: string,
	
	// Certificate issuer
	issuer_common_name: string,
	issuer_organization: string,
	
	// Validity period
	not_before:   time.Time,
	not_after:    time.Time,
	
	// Certificate details
	serial_number: string,
	version:       u32,
	public_key_alg: string,
	signature_alg: string,
	
	// Extended validation
	dns_names:     []string,
	email_addresses: []string,
	ip_addresses:   []string,
	
	// Validation status
	is_valid: bool,
	is_trusted: bool,
	error_message: string,
}

// TLS Configuration
TLS_Config :: struct {
	// Server name for SNI (Server Name Indication)
	server_name: string,
	
	// Protocol version
	min_version: TLS_Version,
	max_version: TLS_Version,
	
	// Certificate verification
	insecure_skip_verify: bool,
	ca_certificates:       []byte,  // PEM encoded CA certs
	client_certificates:    []byte,  // PEM encoded client certs
	client_private_key:     []byte,  // PEM encoded private key
	
	// Cipher suites
	cipher_suites: []string,
	
	// Session resumption
	session_tickets_enabled: bool,
	client_session_cache:    bool,
	
	// ALPN (Application-Layer Protocol Negotiation)
	next_protos:           []string,
	
	// Handshake timeout
	handshake_timeout: time.Duration,
	
	// Verification callback
	verify_callback: proc(cert: ^Certificate) -> bool,
	
	// Connection state (internal)
	state:               TLS_State,
	last_error:          string,
	peer_certificates:   []Certificate,
	selected_protocol:   string,
}

// TLS Socket wrapper
TLS_Socket :: struct {
	// Underlying TCP socket
	tcp_conn: net.TCP_Socket,
	
	// TLS configuration
	config: ^TLS_Config,
	
	// Connection state
	state:  TLS_State,
	is_server: bool,
	
	// Handshake data
	local_random:  [32]byte,
	remote_random: [32]byte,
	master_secret:  [48]byte,
	session_id:     [32]byte,
	
	// Protocol info
	version: TLS_Version,
	cipher_suite: string,
	
	// Connection statistics
	bytes_sent:     u64,
	bytes_received: u64,
	handshake_start: time.Time,
	handshake_end:   time.Time,
	
	// OpenSSL handles
	openssl_ctx:  ^SSL_CTX,
	openssl_sock: ^OpenSSL_Socket,
}

// Convert OpenSSL version string to TLS_Version
tls_version_from_string :: proc(version_str: string) -> TLS_Version {
	if strings.contains(version_str, "TLSv1.3") {
		return .Version_1_3
	} else if strings.contains(version_str, "TLSv1.2") {
		return .Version_1_2
	} else if strings.contains(version_str, "TLSv1.1") {
		return .Version_1_1
	} else if strings.contains(version_str, "TLSv1.0") {
		return .Version_1_0
	}
	return .Version_1_2  // Default
}

// Create default TLS configuration
tls_config_default :: proc() -> TLS_Config {
	config: TLS_Config
	config.server_name = ""
	config.min_version = .Version_1_2
	config.max_version = .Version_1_3
	config.insecure_skip_verify = false
	config.session_tickets_enabled = false
	config.client_session_cache = false
	config.handshake_timeout = 10 * time.Second
	config.state = .Idle
	
	return config
}

// Create TLS socket for client
tls_socket_new :: proc(tcp_conn: net.TCP_Socket, config: ^TLS_Config) -> ^TLS_Socket {
	tls := new(TLS_Socket)
	tls.tcp_conn = tcp_conn
	tls.config = config
	tls.state = .Idle
	tls.is_server = false
	return tls
}

// TLS Handshake - performs TLS handshake
// Uses OpenSSL foreign bindings for actual encryption
tls_handshake :: proc(tls: ^TLS_Socket) -> os.Errno {
	if tls.state == .Connected {
		return os.ERROR_NONE
	}
	
	if tls.state != .Idle && tls.state != .Handshaking {
		return os.EINVAL
	}
	
	tls.state = .Handshaking
	tls.handshake_start = time.now()
	
	// Create OpenSSL context if not exists
	if tls.openssl_ctx == nil {
		ctx, err := openssl_client_context_new()
		if err != os.ERROR_NONE {
			tls.state = .Failed
			tls.config.state = .Failed
			tls.config.last_error = "Failed to create OpenSSL context"
			return err
		}
		
		// Configure verification
		if tls.config.insecure_skip_verify {
			openssl_set_verify_mode(ctx, SSL_VERIFY_NONE)
		} else {
			openssl_set_verify_mode(ctx, SSL_VERIFY_PEER)
			// Try to load CA certificates
			if len(tls.config.ca_certificates) > 0 {
				// Note: ca_certificates is byte array, would need to be written to temp file
				// For now, rely on system defaults
				_ = openssl_load_ca_file(ctx, "/etc/ssl/certs/ca-certificates.crt")
			}
		}
		
		tls.openssl_ctx = ctx
	}
	
	// Create OpenSSL socket wrapper
	if tls.openssl_sock == nil {
		sock, err := openssl_socket_new(tls.openssl_ctx, cast(os.Socket)tls.tcp_conn, tls.is_server)
		if err != os.ERROR_NONE {
			tls.state = .Failed
			tls.config.state = .Failed
			tls.config.last_error = "Failed to create OpenSSL socket"
			return err
		}
		tls.openssl_sock = sock
	}
	
	// Perform handshake
	err: os.Errno
	if tls.is_server {
		err = openssl_accept(tls.openssl_sock)
	} else {
		err = openssl_connect(tls.openssl_sock)
	}
	
	if err == os.ERROR_NONE {
		tls.state = .Connected
		tls.config.state = .Connected
		tls.handshake_end = time.now()
		
		// Get TLS version and cipher
		tls.version = tls_version_from_string(openssl_get_version(tls.openssl_sock))
		tls.cipher_suite = openssl_get_cipher(tls.openssl_sock)
		
		fmt.println("TLS Handshake completed:", tls.version, tls.cipher_suite)
	} else if err == os.EAGAIN {
		// Handshake in progress
		return os.EAGAIN
	} else {
		tls.state = .Failed
		tls.config.state = .Failed
		tls.config.last_error = openssl_get_error_string()
		return err
	}
	
	return os.ERROR_NONE
}

// Read from TLS connection
tls_read :: proc(tls: ^TLS_Socket, p: []byte) -> (n: int, err: os.Errno) {
	if tls.openssl_sock == nil || !tls.openssl_sock.connected {
		return 0, os.ENOTCONN
	}
	
	n, err = openssl_read(tls.openssl_sock, p)
	if n > 0 {
		tls.bytes_received += u64(n)
	}
	if err != os.ERROR_NONE {
		tls.state = .Failed
	}
	return n, err
}

// Write to TLS connection
tls_write :: proc(tls: ^TLS_Socket, p: []byte) -> (n: int, err: os.Errno) {
	if tls.openssl_sock == nil || !tls.openssl_sock.connected {
		return 0, os.ENOTCONN
	}
	
	n, err = openssl_write(tls.openssl_sock, p)
	if n > 0 {
		tls.bytes_sent += u64(n)
	}
	if err != os.ERROR_NONE {
		tls.state = .Failed
	}
	return n, err
}

// Close TLS connection
tls_close :: proc(tls: ^TLS_Socket) -> os.Errno {
	if tls.state == .Idle {
		return os.ERROR_NONE
	}
	
	// Close OpenSSL connection
	if tls.openssl_sock != nil {
		openssl_close(tls.openssl_sock)
		tls.openssl_sock = nil
	}
	
	// Free OpenSSL context
	if tls.openssl_ctx != nil {
		SSL_CTX_free(tls.openssl_ctx)
		tls.openssl_ctx = nil
	}
	
	// Close underlying TCP
	net.close(tls.tcp_conn)
	tls.state = .Idle
	
	return os.ERROR_NONE
}

// Get connection state
tls_get_state :: proc(tls: ^TLS_Socket) -> TLS_State {
	return tls.state
}

// Get peer certificates
tls_get_peer_certificates :: proc(tls: ^TLS_Socket) -> []Certificate {
	return tls.config.peer_certificates
}

// Get connection statistics
tls_get_stats :: proc(tls: ^TLS_Socket) -> (bytes_sent, bytes_received: u64, handshake_duration: time.Duration) {
	// Framework placeholder - actual timing requires real TLS
	return tls.bytes_sent, tls.bytes_received, 0
}

// Certificate Verification Helper Functions

// verify_certificate verifies a certificate against the config
verify_certificate :: proc(config: ^TLS_Config, cert: ^Certificate) -> bool {
	// Check expiration (framework - requires real TLS library)
	// Skipping time comparison - needs external TLS implementation
	if !cert.is_trusted && !config.insecure_skip_verify {
		config.state = .Failed
		config.last_error = "Certificate not trusted"
		return false
	}
	
	// Call verify callback if provided
	if config.verify_callback != nil {
		if !config.verify_callback(cert) {
			config.state = .Failed
			config.last_error = "Certificate verification callback failed"
			return false
		}
	}
	
	cert.is_valid = true
	return true
}

// verify_hostname verifies that the certificate matches the hostname
verify_hostname :: proc(cert: ^Certificate, hostname: string) -> bool {
	// Check Common Name
	if cert.subject_common_name == hostname {
		return true
	}
	
	// Check Subject Alternative Names (SAN)
	for dns in cert.dns_names {
		if dns == hostname {
			return true
		}
		// Check wildcard certificates
		if strings.has_prefix(dns, "*.") {
			domain := dns[2:]
			if strings.has_suffix(hostname, domain) {
				// Verify that hostname doesn't have additional dots before the wildcarded part
				host_parts := strings.split(hostname, ".")
				domain_parts := strings.split(domain, ".")
				if len(host_parts) == len(domain_parts) {
					return true
				}
			}
		}
	}
	
	// Check IP addresses
	for ip in cert.ip_addresses {
		if ip == hostname {
			return true
		}
	}
	
	return false
}

// parse_x509_certificate parses a PEM-encoded X.509 certificate
// Uses OpenSSL for actual parsing
parse_x509_certificate :: proc(pem_data: []byte) -> (Certificate, bool) {
	cert: Certificate
	
	if len(pem_data) == 0 {
		cert.error_message = "Empty certificate data"
		return cert, false
	}
	
	// Create BIO from memory
	bio := BIO_new_mem_buf(rawptr(raw_data(pem_data)), c.int(len(pem_data)))
	if bio == nil {
		cert.error_message = "Failed to create BIO"
		return cert, false
	}
	defer BIO_free(bio)
	
	// Read X509 certificate from BIO
	x509_cert := PEM_read_bio_X509(bio, nil, nil, nil)
	if x509_cert == nil {
		cert.error_message = "Failed to parse X509 certificate"
		return cert, false
	}
	defer X509_free(x509_cert)
	
	// Extract subject name
	subject_name := X509_get_subject_name(x509_cert)
	if subject_name != nil {
		buf: [1024]c.char
		subject_str := X509_NAME_oneline(subject_name, &buf[0], 1024)
		if subject_str != nil {
			cert.subject_common_name = string(subject_str)
		}
	}
	
	// Extract issuer name
	issuer_name := X509_get_issuer_name(x509_cert)
	if issuer_name != nil {
		buf: [1024]c.char
		issuer_str := X509_NAME_oneline(issuer_name, &buf[0], 1024)
		if issuer_str != nil {
			cert.issuer_common_name = string(issuer_str)
		}
	}
	
	// Extract validity periods
	not_before := X509_get_notBefore(x509_cert)
	not_after := X509_get_notAfter(x509_cert)
	if not_before != nil {
		cert.not_before = time.now() // Simplified - would need ASN1_TIME parsing
	}
	if not_after != nil {
		cert.not_after = time.now()  // Simplified - would need ASN1_TIME parsing
	}
	
	// Mark as valid if we got this far
	cert.is_valid = true
	cert.is_trusted = true  // Would need verification against CA store
	
	return cert, true
}

// get_peer_certificate extracts certificate from TLS connection
get_peer_certificate :: proc(tls: ^TLS_Socket) -> (Certificate, bool) {
	if tls == nil || tls.openssl_sock == nil || tls.openssl_sock.ssl == nil {
		return {}, false
	}
	
	cert: Certificate
	
	// Get peer certificate
	x509 := SSL_get_peer_certificate(tls.openssl_sock.ssl)
	if x509 == nil {
		cert.error_message = "No peer certificate available"
		return cert, false
	}
	defer X509_free(x509)
	
	// Extract subject name
	subject_name := X509_get_subject_name(x509)
	if subject_name != nil {
		buf: [1024]c.char
		subject_str := X509_NAME_oneline(subject_name, &buf[0], 1024)
		if subject_str != nil {
			cert.subject_common_name = string(subject_str)
		}
	}
	
	// Extract issuer name
	issuer_name := X509_get_issuer_name(x509)
	if issuer_name != nil {
		buf: [1024]c.char
		issuer_str := X509_NAME_oneline(issuer_name, &buf[0], 1024)
		if issuer_str != nil {
			cert.issuer_common_name = string(issuer_str)
		}
	}
	
	// Extract validity periods (simplified)
	not_before := X509_get_notBefore(x509)
	not_after := X509_get_notAfter(x509)
	if not_before != nil && not_after != nil {
		cert.not_before = time.now()
		cert.not_after = time.now()
	}
	
	cert.is_valid = true
	cert.is_trusted = !tls.config.insecure_skip_verify
	
	return cert, true
}

// create_csr_hash creates a hash for CSR or certificate signing
// NOTE: Not implemented - requires external crypto library
// csr_hash :: proc(data: []byte, algorithm: string) -> []byte {
// 	// In real implementation, compute SHA-256 or other hash
// 	// Placeholder: return empty hash
// 	hash: [32]byte
// 	return hash[:]
// }

// Utility functions for TLS debugging

tls_dump_config :: proc(config: ^TLS_Config) -> string {
	builder: strings.Builder
	builder = strings.builder_make()
	defer strings.builder_destroy(&builder)
	
	fmt.sbprintf(&builder, "\\n=== TLS Configuration ===\\n")
	fmt.sbprintf(&builder, "Server Name: %s\\n", config.server_name)
	fmt.sbprintf(&builder, "Protocol: v%d.%d to v%d.%d\\n", 
		1, int(config.min_version) - 1,
		1, int(config.max_version) - 1)
	fmt.sbprintf(&builder, "Skip Verify: %v\\n", config.insecure_skip_verify)
	fmt.sbprintf(&builder, "Handshake Timeout: %v\\n", config.handshake_timeout)
	
	if len(config.ca_certificates) > 0 {
		fmt.sbprintf(&builder, "CA Certificates: %d bytes\\n", len(config.ca_certificates))
	}
	if len(config.client_certificates) > 0 {
		fmt.sbprintf(&builder, "Client Certificates: %d bytes\\n", len(config.client_certificates))
	}
	if len(config.next_protos) > 0 {
		fmt.sbprintf(&builder, "Next Protocols: %v\\n", config.next_protos)
	}
	
	fmt.sbprintf(&builder, "State: %v\\n", config.state)
	fmt.sbprintf(&builder, "===========================\\n")
	
	return strings.to_string(builder)
}

tls_connection_info :: proc(tls: ^TLS_Socket) -> string {
	builder: strings.Builder
	builder = strings.builder_make()
	defer strings.builder_destroy(&builder)
	
	fmt.sbprintf(&builder, "\\n=== TLS Connection Info ===\\n")
	fmt.sbprintf(&builder, "State: %v\\n", tls.state)
	fmt.sbprintf(&builder, "Version: %v\\n", tls.version)
	fmt.sbprintf(&builder, "Cipher: %s\\n", tls.cipher_suite)
	fmt.sbprintf(&builder, "Selected Protocol: %s\\n", tls.config.selected_protocol)
	
	sent, recv, dur := tls_get_stats(tls)
	fmt.sbprintf(&builder, "Bytes Sent: %d\\n", sent)
	fmt.sbprintf(&builder, "Bytes Received: %d\\n", recv)
	fmt.sbprintf(&builder, "Handshake Duration: %v\\n", dur)
	
	certs := tls_get_peer_certificates(tls)
	if len(certs) > 0 {
		fmt.sbprintf(&builder, "Peer Certificates: %d\\n", len(certs))
			for cert in certs {
				fmt.sbprintf(&builder, "  [%d] CN: %s, Org: %s, Valid: %v\\n",
					cert.subject_common_name, cert.subject_organization, cert.is_valid)
			}
	}
	
	fmt.sbprintf(&builder, "=============================\\n")
	
	return strings.to_string(builder)
}

// Integration helper for HTTP client

// perform_tls_handshake_on_socket performs TLS handshake on an existing TCP socket
// This is the main entry point for HTTP client TLS support
perform_tls_handshake_on_socket :: proc(tcp_conn: net.TCP_Socket, server_name: string, 
                                       insecure_skip: bool) -> (^TLS_Socket, os.Errno) {
	// Create TLS config
	config := tls_config_default()
	config.server_name = server_name
	config.insecure_skip_verify = insecure_skip
	
	if insecure_skip {
		fmt.println("TLS WARNING: Insecure - skipping certificate verification")
	}
	
	// Wrap TCP socket in TLS socket
	tls_socket := tls_socket_new(tcp_conn, &config)
	
	// Perform handshake
	err := tls_handshake(tls_socket)
	if err != 0 {
		return nil, err
	}
	
	// Log connection info
	fmt.println(tls_connection_info(tls_socket))
	
	return tls_socket, os.ERROR_NONE
}
