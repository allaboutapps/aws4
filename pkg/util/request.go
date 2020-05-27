package util

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func SanitizeHost(req *http.Request) {
	host := GetHost(req)
	_, port := splitHostPort(host)

	if port != "" && isDefaultPort(req.URL.Scheme, port) {
		req.Host, _ = splitHostPort(host)
	}
}

func GetHost(req *http.Request) string {
	if len(req.Host) > 0 {
		return req.Host
	}

	if req.URL == nil {
		return ""
	}

	return req.URL.Host
}

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
