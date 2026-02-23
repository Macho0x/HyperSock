<div align="center">
  <img src="Hypersock.png" alt="Hypersock" width="600">
</div>

# HyperSock - HTTP and WebSocket Modules for Odin

High-performance HTTP client/server and WebSocket implementation for Odin, inspired by Go's fasthttp and gorilla/websocket.

## ✅ Feature Checklist

| Feature | Status | Notes |
|---------|--------|-------|
| **Production-Ready HTTP Client** | ✅ Complete | Connection pooling, keep-alive, timeouts |
| **Production-Ready HTTP Server** | ✅ Complete | Concurrent request handling, graceful shutdown |
| **RFC 7230/7231 Compliant** | ✅ Certified | Full HTTP/1.1 specification support |
| **WebSocket RFC 6455** | ✅ Certified | Complete client & server implementation |
| **TLS/SSL Support** | ✅ Complete | OpenSSL bindings with real encryption |
| **SHA-1 WebSocket Handshake** | ✅ Complete | RFC 6455 compliant key computation |
| **Multi-Value Headers** | ✅ Complete | Full Set-Cookie support |
| **URL Percent-Encoding** | ✅ Complete | RFC 3986 compliant |
| **Cookie Jar** | ✅ Complete | Persistent cookie storage with expiry |
| **Redirect Following** | ✅ Complete | Configurable max redirects |
| **Retry Logic** | ✅ Complete | Exponential backoff |
| **Connection Hijacking** | ✅ Complete | HTTP → WebSocket upgrade |
| **X.509 Certificate Parsing** | ✅ Complete | OpenSSL-based cert validation |
| **HTTPS/TLS 1.2-1.3** | ✅ Complete | Production-grade encryption |

## Overview

This repository contains two main packages:
- **`hypersock_http`** - HTTP client and server with connection pooling, TLS support, and fast request handling
- **`hypersock_websocket`** - RFC 6455 compliant WebSocket client and server implementation

---

## HTTP Module (`hypersock_http/`)

A high-performance HTTP client/server library based on fasthttp patterns.

### Files

| File | Purpose | Key Types/Procs |
|------|---------|----------------|
| **http.odin** | Core types and utilities | `Request`, `Response`, `Header`, `URI`, `Method` enum |
| **client.odin** | HTTP client implementation | `Client`, `HostClient`, `do_request()`, `get()`, `post()` |
| **client_advanced.odin** | Advanced client features | `do_with_redirects()`, `do_with_retry()`, `Cookie_Jar`, `cookie_jar_new()`, `cookie_jar_destroy()` |
| **server.odin** | HTTP server implementation | `Server`, `RequestCtx`, `server_new()`, `listen_and_serve()`, `hijack()` |
| **server_io.odin** | Request/response I/O | `read_request()`, `write_response()`, `get_status_text()` |
| **tls.odin** | TLS implementation | `TLS_Config`, `TLS_Socket`, `tls_handshake()`, `tls_read()`, `tls_write()` |
| **tls_openssl.odin** | OpenSSL bindings | Low-level OpenSSL foreign bindings |

### Quick Start

#### HTTP Client - Simple GET

```odin
package main

import http "hypersock_http"
import "core:fmt"
import "core:os"

main :: proc() {
    // Simple GET request
    status, body, err := http.get("https://api.example.com/data")
    if err != os.ERROR_NONE {
        fmt.println("Error:", err)
        return
    }
    
    fmt.println("Status:", status)
    fmt.println("Body:", string(body))
}
```

#### HTTP Client - POST with Headers

```odin
package main

import http "hypersock_http"
import "core:fmt"
import "core:os"

main :: proc() {
    // Create request
    req := http.request_new()
    defer http.request_destroy(&req)

    req.method = .POST
    req.uri, _ = http.uri_parse("https://api.example.com/orders")

    // Set headers
    http.header_set(&req.header, "Content-Type", "application/json")
    http.header_set(&req.header, "Authorization", "Bearer token123")

    // Set body
    req.body = transmute([]byte)`{"symbol": "BTCUSD", "side": "buy"}`

    // Execute request
    resp := http.response_new()
    defer http.response_destroy(&resp)

    client := http.client_new()
    defer http.client_destroy(client)

    err := http.do_request(client, &req, &resp)
    if err != os.ERROR_NONE {
        fmt.println("Request failed:", err)
        return
    }

    fmt.println("Status:", resp.status_code)
    fmt.println("Body:", string(resp.body))
}
```

#### HTTP Server

```odin
package main

import http "hypersock_http"
import "core:fmt"
import "core:os"

// Define request handler
my_handler :: proc(ctx: ^http.RequestCtx) {
    // Set response status
    http.set_status_code(ctx, 200)
    
    // Set content type
    http.set_content_type(ctx, "application/json")
    
    // Write response body
    http.write_string(ctx, `{"status": "ok"}`)
}

main :: proc() {
    // Create server
    server := http.server_new(my_handler)
    defer http.server_destroy(server)
    
    // Configure server
    server.name = "hypersock-server"
    server.concurrency = 100
    server.read_timeout = 30 * os.time.Second
    server.write_timeout = 30 * os.time.Second
    
    // Start listening
    err := http.listen_and_serve(server, ":8080")
    if err != os.ERROR_NONE {
        fmt.println("Server error:", err)
    }
}
```

#### HTTP Client with Redirects and Retries

```odin
package main

import http "hypersock_http"
import "core:fmt"
import "core:os"

main :: proc() {
    client := http.client_new()
    defer http.client_destroy(client)

    req := http.request_new()
    req.method = .GET
    req.uri, _ = http.uri_parse("https://api.example.com/data")

    // With redirect following
    status, body, err := http.do_with_redirects(client, &req, 10)
    if err != os.ERROR_NONE {
        fmt.println("Redirect error:", err)
        return
    }

    // With retry logic
    config := http.Retry_Config {
        max_attempts = 3,
        delay = 1 * os.time.Second,
    }
    status, body, err = http.do_with_retry(client, &req, config)
    if err != os.ERROR_NONE {
        fmt.println("Retry error:", err)
        return
    }

    // With cookies
    jar := http.cookie_jar_new()
    defer http.cookie_jar_destroy(jar)

    status, body, err = http.do_with_jar(client, &req, jar)
    if err != os.ERROR_NONE {
        fmt.println("Cookie error:", err)
        return
    }

    fmt.println("Success:", status)
}
```

---

## WebSocket Module (`hypersock_websocket/`)

RFC 6455 compliant WebSocket implementation with OpenSSL support.

### Files

| File | Purpose | Key Types/Procs |
|------|---------|----------------|
| **websocket.odin** | Core types and utilities | `Conn`, `Opcode`, `Conn_State`, `CloseCode`, `compute_accept_key()` |
| **conn.odin** | WebSocket connection | `new_conn()`, `read_message()`, `write_message()`, `close_connection()` |
| **client.odin** | WebSocket client | `dial()`, `Dialer`, `parse_handshake_response()` |
| **upgrader.odin** | HTTP to WebSocket upgrade | `upgrade()`, `Upgrader`, `is_websocket_upgrade()` |

### Quick Start

#### WebSocket Client

```odin
package main

import websocket "hypersock_websocket"
import "core:fmt"
import "core:os"

main :: proc() {
    // Configure dialer
    dialer := websocket.Dialer {
        read_buffer_size = 1024,
        write_buffer_size = 1024,
    }
    
    // Connect to WebSocket server
    conn, headers, err := websocket.dial("wss://stream.exchange.com/ws", &dialer)
    if err != os.ERROR_NONE {
        fmt.println("Dial error:", err)
        return
    }
    defer websocket.destroy_conn(conn)
    
    fmt.println("Connected!")
    fmt.println("Headers:", headers)
    
    // Send message
    err = websocket.write_message(conn, .Text, transmute([]byte)`{"subscribe": "btcusd"}`)
    if err != os.ERROR_NONE {
        fmt.println("Write error:", err)
        return
    }
    
    // Read messages
    for {
        opcode, data, err := websocket.read_message(conn)
        if err != os.ERROR_NONE {
            fmt.println("Read error:", err)
            break
        }
        
        switch opcode {
        case .Text, .Binary:
            fmt.println("Received:", string(data))
        case .Close:
            fmt.println("Connection closed")
            return
        case .Ping:
            // Pong is automatically sent
            fmt.println("Ping received")
        case .Pong:
            fmt.println("Pong received")
        }
    }
}
```

#### WebSocket Server (HTTP Upgrade)

```odin
package main

import websocket "hypersock_websocket"
import http "hypersock_http"
import "core:fmt"
import "core:os"

http_handler :: proc(ctx: ^http.RequestCtx) {
    // Check if this is a WebSocket upgrade request
    if websocket.is_websocket_upgrade(ctx) {
        // Configure upgrader
        upgrader := websocket.Upgrader {
            read_buffer_size = 1024,
            write_buffer_size = 1024,
        }
        
        // Upgrade to WebSocket
        conn, err := websocket.upgrade(&upgrader, ctx)
        if err != os.ERROR_NONE {
            fmt.println("Upgrade failed:", err)
            http.set_status_code(ctx, 400)
            http.write_string(ctx, "WebSocket upgrade failed")
            return
        }
        defer websocket.destroy_conn(conn)
        
        // Handle WebSocket connection
        handle_websocket(conn)
    } else {
        // Regular HTTP response
        http.set_status_code(ctx, 200)
        http.set_content_type(ctx, "text/plain")
        http.write_string(ctx, "Not a WebSocket request")
    }
}

handle_websocket :: proc(conn: ^websocket.Conn) {
    for {
        opcode, data, err := websocket.read_message(conn)
        if err != os.ERROR_NONE {
            fmt.println("WebSocket error:", err)
            break
        }
        
        // Echo back
        switch opcode {
        case .Text:
            err = websocket.write_message(conn, .Text, data)
            if err != os.ERROR_NONE {
                fmt.println("Write error:", err)
                return
            }
        case .Binary:
            err = websocket.write_message(conn, .Binary, data)
            if err != os.ERROR_NONE {
                fmt.println("Write error:", err)
                return
            }
        case .Close:
            fmt.println("Client closed connection")
            return
        case .Ping:
            fmt.println("Ping received")
        case .Pong:
            fmt.Println("Pong received")
        }
    }
}

main :: proc() {
    server := http.server_new(http_handler)
    defer http.server_destroy(server)
    
    fmt.println("WebSocket server starting on :8080")
    err := http.listen_and_serve(server, ":8080")
    if err != os.ERROR_NONE {
        fmt.println("Server error:", err)
    }
}
```

---

## Package Structure

```
HyperSock/
├── src/
│   ├── hypersock_http/
│   │   ├── http.odin           # Core HTTP types (Request, Response, Header, URI)
│   │   ├── client.odin         # HTTP client (Client, HostClient, do_request)
│   │   ├── client_advanced.odin # Redirects, retries, cookies, cookie jar
│   │   ├── server.odin         # HTTP server (Server, RequestCtx, hijack)
│   │   ├── server_io.odin      # I/O operations (read_request, write_response)
│   │   ├── tls.odin            # TLS implementation (TLS_Config, TLS_Socket)
│   │   └── tls_openssl.odin    # OpenSSL foreign bindings
│   │
│   └── hypersock_websocket/
│       ├── websocket.odin      # Core WebSocket types (Conn, Opcode, close codes)
│       ├── conn.odin           # Connection management (new_conn, read/write, close)
│       ├── client.odin         # WebSocket client (dial, Dialer)
│       └── upgrader.odin       # HTTP upgrade (upgrade, Upgrader)
│
├── tests/
│   ├── http_test.odin          # HTTP module tests
│   └── websocket_test.odin     # WebSocket module tests
│
└── examples/                   # Usage examples
```

## Dependencies

### HTTP Module
- `core:net` - TCP sockets
- `core:os` - Error codes
- `core:strings` - String manipulation
- `core:strconv` - Integer parsing (port numbers, content-length)
- `core:time` - Timeouts and deadlines
- `core:sync` - Mutex and WaitGroup
- `core:mem` - Memory allocation
- `core:c` - Foreign function interface (OpenSSL)
- `core:crypto/legacy/sha1` - WebSocket accept key (used internally)

### WebSocket Module
- `core:net` - TCP sockets
- `core:os` - Error codes
- `core:strings` - String manipulation
- `core:time` - Timeouts and deadlines
- `core:crypto` - Base64 encoding
- `core:encoding/base64` - Base64 for WebSocket key
- `core:encoding/endian` - Byte order for frames
- `core:sync` - Mutex for write operations
- `core:crypto/legacy/sha1` - RFC 6455 accept key computation
- `../http` - HTTP upgrade support

### System Dependencies
- **OpenSSL** (libssl, libcrypto) - Required for HTTPS/TLS support
- Link with: `-lssl -lcrypto`

## Building

### Build as Object Files (Libraries)

```bash
# Build HTTP library
odin build hypersock_http -build-mode:obj -out:http.lib

# Build WebSocket library
odin build hypersock_websocket -build-mode:obj -out:websocket.lib

# Build your project that uses these libraries
# Link with OpenSSL for TLS support
odin build src/main.odin -file -out:my_app
# Then link: clang http.lib websocket.lib my_app.o -lssl -lcrypto -o my_app
```

### Run Tests

```bash
# Run HTTP tests
odin test tests/http_test.odin -file

# Run WebSocket tests
odin test tests/websocket_test.odin -file
```

### Use in Your Project

```odin
package main

import http "hypersock_http"
import websocket "hypersock_websocket"
import "core:fmt"

main :: proc() {
    // Your application code here
    fmt.println("HyperSock starting...")
}
```

## API Reference

### HTTP Client

```odin
// Create/Destroy
client_new :: proc() -> ^Client
client_destroy :: proc(c: ^Client)

// Simple requests
get :: proc(url: string) -> (status: int, body: []byte, err: os.Errno)
post :: proc(url: string, content_type: string, body: []byte) -> (status: int, body: []byte, err: os.Errno)

// Advanced requests
do_request :: proc(c: ^Client, req: ^Request, resp: ^Response) -> os.Errno
do_with_redirects :: proc(c: ^Client, req: ^Request, max_redirects: int) -> (status: int, body: []byte, err: os.Errno)
do_with_retry :: proc(c: ^Client, req: ^Request, config: Retry_Config) -> (status: int, body: []byte, err: os.Errno)
do_with_jar :: proc(c: ^Client, req: ^Request, jar: ^Cookie_Jar) -> (status: int, body: []byte, err: os.Errno)

// Request/Response management
request_new :: proc() -> Request
request_destroy :: proc(r: ^Request)
response_new :: proc() -> Response
response_destroy :: proc(r: ^Response)

// URI parsing
uri_parse :: proc(s: string) -> (URI, bool)

// Headers (multi-value support)
header_set :: proc(h: ^Header, key, value: string)      // Appends value
header_replace :: proc(h: ^Header, key, value: string) // Replaces all values
header_get :: proc(h: ^Header, key: string) -> string    // Gets first value
header_get_all :: proc(h: ^Header, key: string) -> [dynamic]string // Gets all values

// Cookies
cookie_jar_new :: proc() -> ^Cookie_Jar
cookie_jar_destroy :: proc(jar: ^Cookie_Jar)
parse_cookies :: proc(jar: ^Cookie_Jar, header_value: string, url: string)
get_cookies :: proc(jar: ^Cookie_Jar, url: string) -> ([]Cookie, os.Errno)
```

### HTTP Server

```odin
// Create/Destroy
server_new :: proc(handler: RequestHandler) -> ^Server
server_destroy :: proc(s: ^Server)

// Run
listen_and_serve :: proc(s: ^Server, addr: string) -> os.Errno
shutdown :: proc(s: ^Server)

// Connection hijacking (for WebSocket upgrade)
hijack :: proc(ctx: ^RequestCtx) -> (net.TCP_Socket, os.Errno)

// RequestCtx utilities
set_status_code :: proc(ctx: ^RequestCtx, status: int)
set_content_type :: proc(ctx: ^RequestCtx, content_type: string)
set_header :: proc(ctx: ^RequestCtx, name, value: string)
write :: proc(ctx: ^RequestCtx, data: []byte) -> int
write_string :: proc(ctx: ^RequestCtx, data: string) -> int
get_request :: proc(ctx: ^RequestCtx) -> ^Request
get_response :: proc(ctx: ^RequestCtx) -> ^Response
get_conn :: proc(ctx: ^RequestCtx) -> net.TCP_Socket
form_value :: proc(ctx: ^RequestCtx, key: string) -> string
path :: proc(ctx: ^RequestCtx) -> string
query :: proc(ctx: ^RequestCtx) -> string
host :: proc(ctx: ^RequestCtx) -> string
```

### WebSocket

```odin
// Client
dial :: proc(url: string, dialer: ^Dialer) -> (^Conn, http.Header, os.Errno)
destroy_conn :: proc(conn: ^Conn)

// Server upgrade
upgrade :: proc(u: ^Upgrader, ctx: ^http.RequestCtx) -> (^Conn, os.Errno)
is_websocket_upgrade :: proc(ctx: ^http.RequestCtx) -> bool

// Connection operations
read_message :: proc(conn: ^Conn) -> (Opcode, []byte, os.Errno)
write_message :: proc(conn: ^Conn, opcode: Opcode, data: []byte) -> os.Errno
close_connection :: proc(conn: ^Conn, code: CloseCode) -> os.Errno

// Opcodes: .Text, .Binary, .Close, .Ping, .Pong
```

### TLS

```odin
// Configuration
tls_config_default :: proc() -> TLS_Config
tls_socket_new :: proc(tcp_conn: net.TCP_Socket, config: ^TLS_Config) -> ^TLS_Socket

// Operations
tls_handshake :: proc(tls: ^TLS_Socket) -> os.Errno
tls_read :: proc(tls: ^TLS_Socket, p: []byte) -> (n: int, err: os.Errno)
tls_write :: proc(tls: ^TLS_Socket, p: []byte) -> (n: int, err: os.Errno)
tls_close :: proc(tls: ^TLS_Socket) -> os.Errno

// Certificate
get_peer_certificate :: proc(tls: ^TLS_Socket) -> (Certificate, bool)
parse_x509_certificate :: proc(pem_data: []byte) -> (Certificate, bool)
verify_hostname :: proc(cert: ^Certificate, hostname: string) -> bool
```

## Thread Safety

| Component | Thread Safety | Notes |
|-----------|--------------|-------|
| **HTTP Client** | ✅ Thread-safe | Uses connection pooling with mutex protection |
| **HTTP Server** | ✅ Thread-safe | Uses thread-per-connection model |
| **WebSocket Conn** | ⚠️ Partial | Write operations synchronized with mutex; read from one thread only |
| **Cookie Jar** | ⚠️ Not thread-safe | External synchronization required |
| **TLS Socket** | ⚠️ Not thread-safe | One thread for read, one for write max |

## Performance Tips

- **Reuse `Client` instances** - They pool connections automatically
- **Set appropriate buffer sizes** - `read_buffer_size` and `write_buffer_size` in WebSocket
- **Use `RequestCtx` user data** - For request-scoped storage without allocations
- **Close connections explicitly** - When done to free resources promptly
- **Enable keep-alive** - HTTP server supports persistent connections
- **Use connection hijacking** - For WebSocket upgrade without extra overhead

## Implementation Details

### TLS/SSL Implementation
The TLS module now includes **full OpenSSL bindings** for production-grade encryption:
- Real TLS 1.2/1.3 handshake with certificate verification
- Record layer encryption/decryption via OpenSSL
- X.509 certificate parsing and validation
- SNI (Server Name Indication) support
- ALPN (Application-Layer Protocol Negotiation) ready

### WebSocket Handshake
- **RFC 6455 compliant** SHA-1 key computation
- Proper `Sec-WebSocket-Accept` header generation
- Connection hijacking from HTTP server
- Subprotocol negotiation support

### HTTP Compliance
- **RFC 7230**: HTTP/1.1 Message Syntax and Routing
- **RFC 7231**: HTTP/1.1 Semantics and Content
- Multi-value header support (Set-Cookie, etc.)
- URL percent-encoding (RFC 3986)
- Cookie parsing with RFC 1123 date format

## License

These modules are based on patterns from:
- fasthttp (Go) - https://github.com/valyala/fasthttp
- gorilla/websocket (Go) - https://github.com/gorilla/websocket

Ported to Odin with production-grade features.

## Contributing

When adding features:
1. Maintain consistency with existing code style
2. Follow Odin conventions (proper error handling, no `var`)
3. Test compilation with `odin build src/<package> -build-mode:obj`
4. Update this README with new functionality
5. Add tests for new features

---

**HyperSock** - Production-ready HTTP & WebSocket for Odin 🚀
