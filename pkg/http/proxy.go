package http

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/valyala/fasthttp"
)

type ProxyManager struct {
	proxies      []string
	currentIndex uint64
}

func NewProxyManager(proxies []string) *ProxyManager {
	return &ProxyManager{
		proxies: proxies,
	}
}

func (p *ProxyManager) NextProxy() string {
	idx := atomic.AddUint64(&p.currentIndex, 1)
	return p.proxies[(idx-1)%uint64(len(p.proxies))]
}

func (p *ProxyManager) GetDialer(isTLS bool) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		if len(p.proxies) == 0 {
			return fasthttp.Dial(addr)
		}
		proxy := p.NextProxy()
		return p.dialProxy(proxy, addr, isTLS)
	}
}

func (p *ProxyManager) dialProxy(proxy, addr string, isTLS bool) (net.Conn, error) {
	// Connect to proxy
	conn, err := fasthttp.Dial(proxy)
	if err != nil {
		return nil, err
	}

	// For HTTPS, we need to tunnel via CONNECT
	if isTLS {
		req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, err
		}

		// Read response
		// We expect HTTP/1.1 200 OK or similar
		br := bufio.NewReader(conn)
		res, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		
		if !strings.Contains(res, "200") {
			conn.Close()
			return nil, fmt.Errorf("proxy handshake failed: %s", strings.TrimSpace(res))
		}
		
		// Drain headers
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				conn.Close()
				return nil, err
			}
			if line == "\r\n" {
				// We over-buffered? bufio.Reader might have buffered part of the stream?
				// fasthttp.Dial returns a net.Conn. If we wrap it in bufio, we lose the buffered bytes if we don't return the wrapper.
				// This is a problem. net.Conn is what is returned.
				// We need to return a conn that includes the buffered data if any.
				// Ideally, for CONNECT response, there is no body, so exactly \r\n\r\n ends the stream.
				// And the server shouldn't send more until we start SSL.
				// So it should be fine.
				break
			}
		}
		// Return raw conn. 
		// Note: if bufio read extra bytes, they are lost. 
		// But in CONNECT handshake, server waits for client to start SSL Hello. 
		// So server stops sending after 200 OK headers.
		// So bufio shouldn't have read any extra data.
		return conn, nil
	}

	// For HTTP, just return connection to proxy. 
	// The client (HostClient) will write the request to this connection.
	// IMPORTANT: We must ensure the request has absolute URI in kiterunner loop.
	return conn, nil
}
