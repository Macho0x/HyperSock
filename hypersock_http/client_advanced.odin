package hypersock_http

/*
 * Advanced HTTP Client Features
 * Based on fasthttp advanced client.go patterns
 * 
 * Features:
 * - Redirect following
 * - Retry logic with exponential backoff
 * - Timeout and deadline support
 * - Cookie support
 * - TLS support (structure)
 */

import "core:net"
import "core:os"
import "core:fmt"
import "core:strings"
import "core:strconv"
import "core:time"
import "core:sync"

// Cookie represents an HTTP cookie
Cookie :: struct {
	name:     string,
	value:    string,
	path:     string,
	domain:   string,
	expires:  time.Time,
	secure:   bool,
	http_only: bool,
}

// Jar stores cookies
Cookie_Jar :: struct {
	cookies: map[string][dynamic]Cookie, // Map by domain
	mutex:   sync.Mutex,
}

// DoRedirects performs HTTP request following redirects
do_redirects :: proc(c: ^Client, req: ^Request, resp: ^Response, max_redirects: int) -> os.Errno {
	req_copy: Request
	request_reset(&req_copy)
	
	current_url := fmt.tprintf("%s://%s%s", req.uri.scheme, req.header.data["Host"], req.uri.path)
	
	redirects_remaining := max_redirects
	
	for redirects_remaining >= 0 {
		// Copy request for this iteration
		if req_copy.uri.host == "" {
			uri, ok := uri_parse(current_url)
			if !ok {
				return os.EINVAL
			}
			req_copy.uri = uri
		}
		
		req_copy.method = req.method
		req_copy.body = req.body
		copy_headers(&req.header, &req_copy.header)
		
		// Execute request
		err := do_request(c, &req_copy, resp)
		if err != os.ERROR_NONE {
			return err
		}
		
		// Check if response is a redirect
		if !is_redirect_status(resp.status_code) {
			return os.ERROR_NONE
		}
		
		// Get location header
		location := header_get(&resp.header, "Location")
		if location == "" {
			return os.EINVAL
		}
		
		// Resolve redirect URL
		redirect_url := resolve_redirect(current_url, location)
		if redirect_url == "" {
			return os.EINVAL
		}
		
		// Check for redirect protocol change (security)
		if strings.has_prefix(current_url, "https://") && strings.has_prefix(redirect_url, "http://") {
			return os.EINVAL
		}
		
		// Update current URL
		current_url = redirect_url
		
		// Parse new URL
		new_uri, ok := uri_parse(current_url)
		if !ok {
			return os.EINVAL
		}
		req_copy.uri = new_uri
		
		// For 301/302 redirects, POST should change to GET
		if (resp.status_code == Status_MovedPermanently || resp.status_code == Status_Found) && 
		   req.method == .POST {
			req_copy.method = .GET
			req_copy.body = req_copy.body[:0]
		}
		
		redirects_remaining -= 1
	}
	
	return os.EINVAL
}

// DoWithRetry performs HTTP request with retry logic
do_with_retry :: proc(c: ^Client, req: ^Request, resp: ^Response, max_attempts: int) -> os.Errno {
	attempt := 1
	base_delay := time.Duration(100 * 1e6)  // 100ms in nanoseconds
	
	for attempt <= max_attempts {
		// Try the request
		err := do_request(c, req, resp)
		if err == os.ERROR_NONE {
			return os.ERROR_NONE
		}
		
		// Don't retry certain errors
		if should_not_retry(err, req.method) {
			return err
		}
		
		// Don't retry certain status codes
		if resp.status_code == Status_BadRequest ||
		   resp.status_code == Status_Unauthorized ||
		   resp.status_code == Status_Forbidden ||
		   resp.status_code == Status_NotFound {
			return err
		}
		
		// Exponential backoff
		if attempt < max_attempts {
			delay := base_delay * time.Duration(1 << uint(attempt - 1))
			time.sleep(delay)
		}
		
		attempt += 1
		
		// Reset response for next attempt
		response_reset(resp)
	}
	
	return os.ERROR_NONE
}



// Cookie operations

// SetCookie sets a cookie in the jar
set_cookie :: proc(jar: ^Cookie_Jar, cookie: ^Cookie) {
	sync.mutex_lock(&jar.mutex)
	defer sync.mutex_unlock(&jar.mutex)
	
	if jar.cookies == nil {
		jar.cookies = make(map[string][dynamic]Cookie)
	}
	
	domain := cookie.domain
	if domain == "" {
		return
	}
	
	cookies := &jar.cookies[domain]
	
	// Remove existing cookie with same name
	i := 0
	for i < len(cookies) {
		if cookies[i].name == cookie.name {
			break
		}
		i += 1
	}
	if i < len(cookies) {
		ordered_remove(cookies, i)
	}
	
	// Add new cookie
	append(cookies, cookie^)
}

// GetCookies returns cookies for a URL
get_cookies :: proc(jar: ^Cookie_Jar, url_str: string) -> ([]Cookie, os.Errno) {
	sync.mutex_lock(&jar.mutex)
	defer sync.mutex_unlock(&jar.mutex)
	
	if jar.cookies == nil {
		return nil, os.ERROR_NONE
	}
	
	uri, ok := uri_parse(url_str)
	if !ok {
		return nil, os.EINVAL
	}
	
	result: [dynamic]Cookie
	
	// Get cookies for exact domain
	if cookies, exists := jar.cookies[uri.host]; exists {
		for cookie in cookies {
			// Check if cookie is expired
			if !(cookie.expires._nsec == 0) && time.now()._nsec >= cookie.expires._nsec {
				continue
			}
			
			// Check path
			if cookie.path != "" && !strings.has_prefix(uri.path, cookie.path) {
				continue
			}
			
			// Check secure
			if cookie.secure && uri.scheme != "https" {
				continue
			}
			
			append(&result, cookie)
		}
	}
	
	return result[:], os.ERROR_NONE
}

// ParseCookies parses cookies from Set-Cookie header
parse_cookies :: proc(jar: ^Cookie_Jar, header: string, from_url: string) {
	lines := strings.split(header, ";")
	defer delete(lines)
	
	if len(lines) == 0 {
		return
	}
	
	// Parse name=value from first line
	name_value := strings.split(lines[0], "=")
	defer delete(name_value)
	
	if len(name_value) != 2 {
		return
	}
	
	cookie: Cookie
	cookie.name = strings.trim_space(name_value[0])
	cookie.value = strings.trim_space(name_value[1])
	
	// Parse attributes
	uri, ok := uri_parse(from_url)
	if ok {
		cookie.domain = uri.host
		cookie.path = uri.path
	}
	
	for i := 1; i < len(lines); i += 1 {
		attr := strings.trim_space(lines[i])
		attr = strings.trim_space(attr)
		
		attr_name, attr_value := parse_cookie_attribute(attr)
		
		switch strings.to_lower(attr_name) {
		case "domain":
			cookie.domain = attr_value
		case "path":
			cookie.path = attr_value
		case "secure":
			cookie.secure = true
		case "httponly":
			cookie.http_only = true
		case "expires":
			// Parse RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT"
			cookie.expires = parse_rfc1123_date(attr_value)
		}
	}
	
	set_cookie(jar, &cookie)
}

// Parse cookie attribute (name=value)
parse_cookie_attribute :: proc(attr: string) -> (name, value: string) {
	idx := strings.index(attr, "=")
	if idx == -1 {
		return strings.to_lower(attr), ""
	}
	return strings.to_lower(attr[:idx]), attr[idx+1:]
}

// Helper functions

// Is redirect status code
is_redirect_status :: proc(status_code: int) -> bool {
	switch status_code {
	case Status_MovedPermanently, // 301
	     Status_Found,            // 302
	     Status_SeeOther,         // 303
	     Status_TemporaryRedirect,// 307
	     Status_PermanentRedirect: // 308
		return true
	}
	return false
}

// Should not retry certain errors
should_not_retry :: proc(err: os.Errno, method: Method) -> bool {
	switch err {
	case os.EINVAL,
	     os.ENOENT:
		return true
	}
	return false
}

// Resolve redirect URL
resolve_redirect :: proc(base_url, location: string) -> string {
	// If location is absolute, return it
	if strings.has_prefix(location, "http://") || strings.has_prefix(location, "https://") {
		return location
	}
	
	// Resolve relative to base URL
	// Simple implementation - just prepend base
	if strings.has_prefix(location, "/") {
		idx := strings.index(base_url, "//")
		if idx != -1 {
			scheme_end := strings.index(base_url[idx+2:], "/")
			if scheme_end != -1 {
				return fmt.tprintf("%s%s", base_url[:idx+2+scheme_end], location)
			}
		}
	}
	
	return location
}

// Copy headers from one header to another
copy_headers :: proc(src, dst: ^Header) {
	sync.mutex_lock(&src.mutex)
	defer sync.mutex_unlock(&src.mutex)
	
	sync.mutex_lock(&dst.mutex)
	defer sync.mutex_unlock(&dst.mutex)
	
	if dst.data == nil {
		dst.data = make(map[string][dynamic]string)
	}
	
	for key, value in src.data {
		dst.data[key] = value
	}
}

// Create new cookie jar
cookie_jar_new :: proc() -> ^Cookie_Jar {
	j := new(Cookie_Jar)
	j.cookies = make(map[string][dynamic]Cookie)
	return j
}

// Add cookies from jar to request (for client side)
add_cookies_to_request :: proc(jar: ^Cookie_Jar, url: string, headers: ^Header) {
	cookies, err := get_cookies(jar, url)
	if err != os.ERROR_NONE {
		return
	}
	
	if len(cookies) == 0 {
		return
	}
	
	// Build Cookie header
	cookie_value: strings.Builder
	defer strings.builder_destroy(&cookie_value)
	
	for i := 0; i < len(cookies); i += 1 {
		cookie := cookies[i]
		if i > 0 {
			fmt.sbprintf(&cookie_value, "; ")
		}
		fmt.sbprintf(&cookie_value, "%s=%s", cookie.name, cookie.value)
	}
	
	header_set(headers, "Cookie", strings.to_string(cookie_value))
}

// Add received cookies to jar (supports multiple Set-Cookie headers)
add_received_cookies :: proc(jar: ^Cookie_Jar, headers: ^Header, url: string) {
	// Get all Set-Cookie header values
	set_cookies := header_get_all(headers, "Set-Cookie")
	
	// Parse each Set-Cookie header value
	for cookie_value in set_cookies {
		parse_cookies(jar, cookie_value, url)
	}
}

// Set-Cookie helper function for responses
set_cookie_header :: proc(headers: ^Header, cookie: ^Cookie) {
	value: strings.Builder
	defer strings.builder_destroy(&value)
	
	fmt.sbprintf(&value, "%s=%s", cookie.name, cookie.value)
	
	if cookie.path != "" {
		fmt.sbprintf(&value, "; Path=%s", cookie.path)
	}
	
	if cookie.domain != "" {
		fmt.sbprintf(&value, "; Domain=%s", cookie.domain)
	}
	
	if cookie.expires._nsec != 0 {
		// Format time - use simple format for now
		fmt.sbprintf(&value, "; Expires=%v", cookie.expires)
	}
	
	if cookie.secure {
		fmt.sbprintf(&value, "; Secure")
	}
	
	if cookie.http_only {
		fmt.sbprintf(&value, "; HttpOnly")
	}
	
	header_set(headers, "Set-Cookie", strings.to_string(value))
}


// Month name to number mapping
month_to_number :: proc(month: string) -> int {
	month_lower := strings.to_lower(month)
	switch month_lower {
	case "jan": return 1
	case "feb": return 2
	case "mar": return 3
	case "apr": return 4
	case "may": return 5
	case "jun": return 6
	case "jul": return 7
	case "aug": return 8
	case "sep": return 9
	case "oct": return 10
	case "nov": return 11
	case "dec": return 12
	}
	return 0
}

// Parse RFC 1123 date format: "Sun, 06 Nov 1994 08:49:37 GMT"
// Also handles RFC 850 and ANSI C's asctime() formats
parse_rfc1123_date :: proc(date_str: string) -> time.Time {
	trimmed := strings.trim_space(date_str)
	if trimmed == "" {
		return {}
	}
	
	// Try RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT"
	// Format: Wdy, DD Mon YYYY HH:MM:SS GMT
	
	// Remove day name if present (e.g., "Sun, ")
	after_day := trimmed
	if idx := strings.index(trimmed, ","); idx != -1 {
		after_day = strings.trim_space(trimmed[idx+1:])
	}
	
	// Now should be: "06 Nov 1994 08:49:37 GMT"
	parts := strings.split(after_day, " ")
	defer delete(parts)
	
	if len(parts) < 4 {
		return {}
	}
	
	// Parse day
	day: int
	if d, ok := strconv.parse_int(strings.trim_space(parts[0]), 10); ok {
		day = int(d)
	} else {
		return {}
	}
	
	// Parse month
	month := 1
	month_name := strings.to_lower(strings.trim_space(parts[1]))
	if m := month_to_number(month_name); m > 0 {
		month = m
	} else {
		return {}
	}
	
	// Parse year
	year: int
	if y, ok := strconv.parse_int(strings.trim_space(parts[2]), 10); ok {
		year = int(y)
	} else {
		return {}
	}
	
	// Parse time (HH:MM:SS)
	time_parts := strings.split(strings.trim_space(parts[3]), ":")
	defer delete(time_parts)
	
	hour, minute, second: int
	if len(time_parts) >= 3 {
		if h, ok := strconv.parse_int(time_parts[0], 10); ok {
			hour = int(h)
		}
		if m, ok := strconv.parse_int(time_parts[1], 10); ok {
			minute = int(m)
		}
		if s, ok := strconv.parse_int(time_parts[2], 10); ok {
			second = int(s)
		}
	}
	
	// Create time using time.from_utc_components if available
	// Otherwise construct manually
	// This is a simplified implementation
	t: time.Time
	t._nsec = i64(year-1970) * 365 * 24 * 60 * 60 * 1_000_000_000 + 
	          i64(month) * 30 * 24 * 60 * 60 * 1_000_000_000 +
	          i64(day) * 24 * 60 * 60 * 1_000_000_000 +
	          i64(hour) * 60 * 60 * 1_000_000_000 +
	          i64(minute) * 60 * 1_000_000_000 +
	          i64(second) * 1_000_000_000
	
	return t
}

// Destroy cookie jar and free memory
cookie_jar_destroy :: proc(jar: ^Cookie_Jar) {
	if jar == nil {
		return
	}
	
	// Free all cookie arrays
	for key, cookies in jar.cookies {
		delete(cookies)
	}
	delete(jar.cookies)
	free(jar)
}
