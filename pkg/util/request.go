package util

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SanitizeHost sanitizes the host of the request, removing the port if it is the default
// one for the request's scheme.
func SanitizeHost(req *http.Request) {
	host := GetHost(req)
	_, port := splitHostPort(host)

	if port != "" && isDefaultPort(req.URL.Scheme, port) {
		req.Host, _ = splitHostPort(host)
	}
}

// GetHost returns the host for the request, preferring the req.Host value if set, falling
// back to the host of the URL if defined.
func GetHost(req *http.Request) string {
	if len(req.Host) > 0 {
		return req.Host
	}

	if req.URL == nil {
		return ""
	}

	return req.URL.Host
}

// GetURLPath returns the path for a given URL, preferring the url.Opaque value if defined,
// falling back to the value of url.EscapedPath().
//
// If defined, url.Opaque must be in the form of:
//
//     "//<hostname>/<path>"
func GetURLPath(u *url.URL) string {
	if len(u.Opaque) > 0 {
		return fmt.Sprintf("/%s", strings.Join(strings.Split(u.Opaque, "/")[3:], "/"))
	}

	url := u.EscapedPath()
	if len(url) == 0 {
		url = "/"
	}

	return url
}

// splitHostPort splits the host and port of a string, returning an empty string for port
// if non was specified in the string passed.
func splitHostPort(hostport string) (host, port string) {
	host = hostport

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// validOptionalPort checks whether the port string is a valid optional port, allowing empty
// ports and requiring all characters to be numeric otherwise.
func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// isDefaultPort checks whether the given port is the default one for the specified scheme.
func isDefaultPort(scheme string, port string) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == "80"
	case "https":
		return port == "443"
	default:
		return false
	}
}
