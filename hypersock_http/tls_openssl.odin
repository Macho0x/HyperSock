package hypersock_http

/*
 * OpenSSL Foreign Bindings for TLS Support
 * 
 * This module provides foreign bindings to OpenSSL for actual TLS encryption.
 * OpenSSL is widely available on most systems and provides production-ready TLS.
 * 
 * Requirements:
 * - libssl (OpenSSL/BoringSSL/LibreSSL)
 * - libcrypto
 * 
 * Link with: -lssl -lcrypto
 */

import "core:c"
import "core:os"

// OpenSSL Constants
SSL_FILETYPE_PEM :: 1
SSL_VERIFY_NONE :: 0x00
SSL_VERIFY_PEER :: 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT :: 0x02
SSL_VERIFY_CLIENT_ONCE :: 0x04

TLS1_2_VERSION :: 0x0303
TLS1_3_VERSION :: 0x0304

// SSL Error codes
SSL_ERROR_NONE :: 0
SSL_ERROR_SSL :: 1
SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_WANT_X509_LOOKUP :: 4
SSL_ERROR_SYSCALL :: 5
SSL_ERROR_ZERO_RETURN :: 6
SSL_ERROR_WANT_CONNECT :: 7
SSL_ERROR_WANT_ACCEPT :: 8

// Foreign OpenSSL bindings
@(default_calling_convention = "c")
foreign {
	// SSL Library init
	SSL_library_init :: proc() -> c.int ---
	SSL_load_error_strings :: proc() ---
	ERR_load_crypto_strings :: proc() ---
	ERR_load_SSL_strings :: proc() ---
	
	// SSL Context
	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_CTX_set_verify :: proc(ctx: ^SSL_CTX, mode: c.int, callback: SSL_Verify_Callback) ---
	SSL_CTX_set_verify_depth :: proc(ctx: ^SSL_CTX, depth: c.int) ---
	SSL_CTX_load_verify_locations :: proc(ctx: ^SSL_CTX, ca_file: cstring, ca_path: cstring) -> c.int ---
	SSL_CTX_use_certificate_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_check_private_key :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_set_default_verify_paths :: proc(ctx: ^SSL_CTX) -> c.int ---
	
	// SSL Connection
	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_connect :: proc(ssl: ^SSL) -> c.int ---
	SSL_accept :: proc(ssl: ^SSL) -> c.int ---
	SSL_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_read :: proc(ssl: ^SSL, buf: rawptr, num: c.size_t) -> c.int ---
	SSL_write :: proc(ssl: ^SSL, buf: rawptr, num: c.size_t) -> c.int ---
	SSL_get_error :: proc(ssl: ^SSL, ret: c.int) -> c.int ---
	SSL_set_connect_state :: proc(ssl: ^SSL) ---
	SSL_set_accept_state :: proc(ssl: ^SSL) ---
	SSL_do_handshake :: proc(ssl: ^SSL) -> c.int ---
	SSL_get_version :: proc(ssl: ^SSL) -> cstring ---
	SSL_get_cipher :: proc(ssl: ^SSL) -> cstring ---
	SSL_get_peer_certificate :: proc(ssl: ^SSL) -> ^X509 ---
	
	// SSL Methods
	TLS_client_method :: proc() -> ^SSL_METHOD ---
	TLS_server_method :: proc() -> ^SSL_METHOD ---
	
	// Error handling
	ERR_get_error :: proc() -> c.ulong ---
	ERR_error_string :: proc(e: c.ulong, buf: [^]c.char) -> cstring ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]c.char, len: c.int) ---
	ERR_clear_error :: proc() ---
	
	// X509 Certificate
	X509_free :: proc(cert: ^X509) ---
	X509_get_subject_name :: proc(cert: ^X509) -> ^X509_NAME ---
	X509_get_issuer_name :: proc(cert: ^X509) -> ^X509_NAME ---
	X509_get_notBefore :: proc(cert: ^X509) -> ^ASN1_TIME ---
	X509_get_notAfter :: proc(cert: ^X509) -> ^ASN1_TIME ---
	X509_NAME_oneline :: proc(name: ^X509_NAME, buf: [^]c.char, size: c.int) -> cstring ---
	
	// BIO (Basic I/O) for memory buffers
	BIO_new_mem_buf :: proc(buf: rawptr, len: c.int) -> ^BIO ---
	BIO_free :: proc(bio: ^BIO) ---
	PEM_read_bio_X509 :: proc(bp: ^BIO, x: ^^X509, cb: PEM_Password_Callback, u: rawptr) -> ^X509 ---
}

// Opaque types
SSL_METHOD :: struct {}
SSL_CTX :: struct {}
SSL :: struct {}
X509 :: struct {}
X509_NAME :: struct {}
ASN1_TIME :: struct {}
BIO :: struct {}

// Callback types
SSL_Verify_Callback :: proc "c" (preverify_ok: c.int, ctx: ^X509_STORE_CTX) -> c.int
X509_STORE_CTX :: struct {}
PEM_Password_Callback :: proc "c" (buf: [^]c.char, size: c.int, rwflag: c.int, userdata: rawptr) -> c.int

// OpenSSL initialization flag
openssl_initialized := false

// Initialize OpenSSL library
openssl_init :: proc() {
	if openssl_initialized {
		return
	}
	
	SSL_library_init()
	SSL_load_error_strings()
	ERR_load_crypto_strings()
	ERR_load_SSL_strings()
	
	openssl_initialized = true
}

// Get OpenSSL error string
openssl_get_error_string :: proc() -> string {
	err_code := ERR_get_error()
	if err_code == 0 {
		return "Unknown error"
	}
	
	buf: [256]c.char
	ERR_error_string_n(err_code, &buf[0], 256)
	return string(cstring(&buf[0]))
}

// Clear OpenSSL error stack
openssl_clear_errors :: proc() {
	ERR_clear_error()
}

// SSL State
OpenSSL_Socket :: struct {
	ssl:       ^SSL,
	ctx:       ^SSL_CTX,
	socket_fd: os.Socket,
	is_server: bool,
	connected: bool,
}

// Create OpenSSL client context
openssl_client_context_new :: proc() -> (^SSL_CTX, os.Errno) {
	openssl_init()
	
	method := TLS_client_method()
	if method == nil {
		return nil, os.EINVAL
	}
	
	ctx := SSL_CTX_new(method)
	if ctx == nil {
		return nil, os.EINVAL
	}
	
	// Set default verify mode
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
	SSL_CTX_set_verify_depth(ctx, 4)
	
	// Try to load default CA certificates
	SSL_CTX_set_default_verify_paths(ctx)
	
	return ctx, os.ERROR_NONE
}

// Create OpenSSL server context
openssl_server_context_new :: proc(cert_file, key_file: string) -> (^SSL_CTX, os.Errno) {
	openssl_init()
	
	method := TLS_server_method()
	if method == nil {
		return nil, os.EINVAL
	}
	
	ctx := SSL_CTX_new(method)
	if ctx == nil {
		return nil, os.EINVAL
	}
	
	// Load certificate
	cert_cstr := cstring(raw_data(cert_file))
	if SSL_CTX_use_certificate_file(ctx, cert_cstr, SSL_FILETYPE_PEM) != 1 {
		SSL_CTX_free(ctx)
		return nil, os.EINVAL
	}
	
	// Load private key
	key_cstr := cstring(raw_data(key_file))
	if SSL_CTX_use_PrivateKey_file(ctx, key_cstr, SSL_FILETYPE_PEM) != 1 {
		SSL_CTX_free(ctx)
		return nil, os.EINVAL
	}
	
	// Verify private key
	if SSL_CTX_check_private_key(ctx) != 1 {
		SSL_CTX_free(ctx)
		return nil, os.EINVAL
	}
	
	return ctx, os.ERROR_NONE
}

// Create OpenSSL socket wrapper
openssl_socket_new :: proc(ctx: ^SSL_CTX, socket_fd: os.Socket, is_server: bool) -> (^OpenSSL_Socket, os.Errno) {
	ssl := SSL_new(ctx)
	if ssl == nil {
		return nil, os.EINVAL
	}
	
	// Set the socket file descriptor
	if SSL_set_fd(ssl, c.int(socket_fd)) != 1 {
		SSL_free(ssl)
		return nil, os.EINVAL
	}
	
	sock := new(OpenSSL_Socket)
	sock.ssl = ssl
	sock.ctx = ctx  // Note: we don't own the context, don't free it
	sock.socket_fd = socket_fd
	sock.is_server = is_server
	sock.connected = false
	
	if is_server {
		SSL_set_accept_state(ssl)
	} else {
		SSL_set_connect_state(ssl)
	}
	
	return sock, os.ERROR_NONE
}

// Perform TLS handshake
openssl_handshake :: proc(sock: ^OpenSSL_Socket) -> os.Errno {
	if sock == nil || sock.ssl == nil {
		return os.EINVAL
	}
	
	result := SSL_do_handshake(sock.ssl)
	if result == 1 {
		sock.connected = true
		return os.ERROR_NONE
	}
	
	err := SSL_get_error(sock.ssl, result)
	if err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE {
		// Would block, need to retry
		return os.EAGAIN
	}
	
	return os.EIO
}

// Connect (client handshake)
openssl_connect :: proc(sock: ^OpenSSL_Socket) -> os.Errno {
	if sock == nil || sock.ssl == nil {
		return os.EINVAL
	}
	
	result := SSL_connect(sock.ssl)
	if result == 1 {
		sock.connected = true
		return os.ERROR_NONE
	}
	
	err := SSL_get_error(sock.ssl, result)
	if err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE {
		return os.EAGAIN
	}
	
	return os.EIO
}

// Accept (server handshake)
openssl_accept :: proc(sock: ^OpenSSL_Socket) -> os.Errno {
	if sock == nil || sock.ssl == nil {
		return os.EINVAL
	}
	
	result := SSL_accept(sock.ssl)
	if result == 1 {
		sock.connected = true
		return os.ERROR_NONE
	}
	
	err := SSL_get_error(sock.ssl, result)
	if err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE {
		return os.EAGAIN
	}
	
	return os.EIO
}

// Read from TLS connection
openssl_read :: proc(sock: ^OpenSSL_Socket, buf: []byte) -> (int, os.Errno) {
	if sock == nil || sock.ssl == nil || len(buf) == 0 {
		return 0, os.EINVAL
	}
	
	result := SSL_read(sock.ssl, rawptr(raw_data(buf)), c.size_t(len(buf)))
	if result > 0 {
		return int(result), os.ERROR_NONE
	}
	
	err := SSL_get_error(sock.ssl, result)
	switch err {
	case SSL_ERROR_ZERO_RETURN:
		// Connection closed
		return 0, os.ERROR_NONE
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
		return 0, os.EAGAIN
	case SSL_ERROR_SYSCALL:
		return 0, os.EIO
	case SSL_ERROR_SSL:
		return 0, os.EIO
	}
	
	return 0, os.EIO
}

// Write to TLS connection
openssl_write :: proc(sock: ^OpenSSL_Socket, buf: []byte) -> (int, os.Errno) {
	if sock == nil || sock.ssl == nil || len(buf) == 0 {
		return 0, os.EINVAL
	}
	
	result := SSL_write(sock.ssl, rawptr(raw_data(buf)), c.size_t(len(buf)))
	if result > 0 {
		return int(result), os.ERROR_NONE
	}
	
	err := SSL_get_error(sock.ssl, result)
	switch err {
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
		return 0, os.EAGAIN
	case SSL_ERROR_SYSCALL:
		return 0, os.EIO
	case SSL_ERROR_SSL:
		return 0, os.EIO
	}
	
	return 0, os.EIO
}

// Close TLS connection
openssl_close :: proc(sock: ^OpenSSL_Socket) {
	if sock == nil {
		return
	}
	
	if sock.ssl != nil {
		SSL_shutdown(sock.ssl)
		SSL_free(sock.ssl)
		sock.ssl = nil
	}
	
	free(sock)
}

// Get TLS version
openssl_get_version :: proc(sock: ^OpenSSL_Socket) -> string {
	if sock == nil || sock.ssl == nil {
		return ""
	}
	
	version := SSL_get_version(sock.ssl)
	if version == nil {
		return ""
	}
	
	return string(version)
}

// Get cipher name
openssl_get_cipher :: proc(sock: ^OpenSSL_Socket) -> string {
	if sock == nil || sock.ssl == nil {
		return ""
	}
	
	cipher := SSL_get_cipher(sock.ssl)
	if cipher == nil {
		return ""
	}
	
	return string(cipher)
}

// Load CA certificates from file
openssl_load_ca_file :: proc(ctx: ^SSL_CTX, ca_file: string) -> bool {
	if ctx == nil || len(ca_file) == 0 {
		return false
	}
	
	ca_cstr := cstring(raw_data(ca_file))
	result := SSL_CTX_load_verify_locations(ctx, ca_cstr, nil)
	return result == 1
}

// Set certificate verification mode
openssl_set_verify_mode :: proc(ctx: ^SSL_CTX, mode: int) {
	if ctx == nil {
		return
	}
	SSL_CTX_set_verify(ctx, c.int(mode), nil)
}
