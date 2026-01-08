package kiterunner

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/assetnote/kiterunner/pkg/log"
	krhttp "github.com/assetnote/kiterunner/pkg/http"
)

var replayClient *http.Client

// ReplayRequest sends a copy of the request to the configured replay proxy.
// It is intended to be called asynchronously.
func ReplayRequest(target *krhttp.Target, route *krhttp.Route, proxyURL string) {
	// Parse proxy URL
	pURL, err := url.Parse(proxyURL)
	if err != nil {
		log.Error().Err(err).Str("proxy", proxyURL).Msg("failed to parse replay proxy url")
		return
	}

	// Initialize client once or on demand (simple to do on demand or reuse global)
	// Given this is a low-frequency operation, creating a client is acceptable, 
	// but reusing is better for connection pooling to the proxy.
	// For simplicity in this "fire and forget", let's make a new transport.
	transport := &http.Transport{
		Proxy: http.ProxyURL(pURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true, // Don't keep connections open for this side-channel
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Construct URL
	// target.Host() gives host:port
	// We need scheme. target.IsTLS
	scheme := "http"
	if target.IsTLS {
		scheme = "https"
	}
	
	// Construct full URL
	// We need to use req.Route logic to append path/query
	// Route has Path and Query logic.
	// Let's manually reconstruct roughly.
	// kiterunner uses fasthttp and byte slices.
	// Route.Path is []byte
	
	// Use target.AppendBytes logic to get base URL?
	// target.AppendScheme, target.AppendHostHeader.
	
	// Let's rely on string building for simplicity here.
	fullURL := scheme + "://" + target.Host() + string(route.Path)
	// If query exists? route.AppendQuery ... 
	// Route doesn't store query separately usually, it's often baked into path or separate?
	// Looking at route.go might be needed. 
	// Assuming Path contains what we need for now or we ignore complex query params if not present.
	// If route has specific query params, they might be in arguments? 
	// For brute force, it's usually just path.
	
	req, err := http.NewRequest(string(route.Method), fullURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("failed to create replay request")
		return
	}

	// Copy headers
	// Default headers from target?
	// Headers from route
	for _, h := range target.Headers {
		req.Header.Set(h.Key, h.Value) 
	}
	for _, h := range route.Headers {
		req.Header.Set(h.Key, h.Value)
	}
	
	// Add body if present
	// req.Body ...
	
	resp, err := client.Do(req)
	if err != nil {
		// Log debug, don't spam errors if burp is closed
		log.Debug().Err(err).Msg("failed to replay request to proxy")
		return
	}
	defer resp.Body.Close()
	
	log.Debug().Str("url", fullURL).Int("status", resp.StatusCode).Msg("replayed request to proxy")
}
