package wisp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func validateProxyURL(rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("proxy must be a valid URL")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("proxy URL cannot contain a path, query, or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "http", "https":
		return nil
	default:
		return fmt.Errorf("proxy scheme must be socks5, socks5h, http, or https")
	}
}

func dialProxy(dialer *net.Dialer, rawURL, destination string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(dialer, u, destination)
	case "http", "https":
		return dialHTTPConnect(dialer, u, destination)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}

func dialSOCKS5(dialer *net.Dialer, u *url.URL, destination string) (net.Conn, error) {
	var auth *proxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: password}
	}
	proxyDialer, err := proxy.SOCKS5("tcp", withDefaultPort(u, "1080"), auth, dialer)
	if err != nil {
		return nil, err
	}
	return proxyDialer.Dial("tcp", destination)
}

func dialHTTPConnect(dialer *net.Dialer, u *url.URL, destination string) (net.Conn, error) {
	defaultPort := "80"
	if strings.EqualFold(u.Scheme, "https") {
		defaultPort = "443"
	}
	conn, err := dialer.Dial("tcp", withDefaultPort(u, defaultPort))
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	if strings.EqualFold(u.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		setProxyDeadline(tlsConn, dialer.Timeout)
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}

	headers := make(http.Header)
	headers.Set("Proxy-Connection", "Keep-Alive")
	if u.User != nil {
		password, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + password))
		headers.Set("Proxy-Authorization", "Basic "+token)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: destination},
		Host:   destination,
		Header: headers,
	}
	setProxyDeadline(conn, dialer.Timeout)
	if err := request.Write(conn); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", response.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func setProxyDeadline(conn net.Conn, timeout time.Duration) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
}

func withDefaultPort(u *url.URL, defaultPort string) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), defaultPort)
}
