package main

/*
 * Example: Simple HTTP GET request
 * Demonstrates basic HTTP client usage
 */

import http "../hypersock_http"
import "core:fmt"
import "core:os"

main :: proc() {
	fmt.println("=== HTTP GET Example ===")
	
	// Make GET request
	url := "https://httpbin.org/get"
	fmt.println("Fetching:", url)
	
	status, body, err := http.get(url)
	if err != os.ERROR_NONE {
		fmt.println("Error:", err)
		os.exit(1)
	}
	
	fmt.println("Status:", status)
	fmt.println("Response length:", len(body))
	fmt.println("First 200 chars:", string(body[:min(200, len(body))]))
}
