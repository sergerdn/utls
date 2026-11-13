package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/enetx/g"
	surfhttp "github.com/enetx/http"
	"github.com/enetx/surf"
)

func main() {
	target := flag.String("url", "https://example.com/", "HTTPS URL to request")
	network := flag.String("network", "tcp6", "address family: tcp, tcp4, or tcp6")
	flag.Parse()

	if err := run(*target, *network); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(target, network string) error {
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("url must be an absolute HTTPS URL")
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("unsupported network %q: use tcp, tcp4, or tcp6", network)
	}

	client := surf.NewClient()
	transport := client.GetTransport().(*surfhttp.Transport)
	dialer := client.GetDialer()
	transport.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	client, err = client.Builder().
		SecureTLS().
		Proxy("").
		NotFollowRedirects().
		Timeout(20 * time.Second).
		JA().
		Safari26_3().
		Build().
		Result()
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}
	defer client.Close()

	fmt.Printf("Safari 26.3; network=%s; certificate verification enabled; proxy disabled\n", network)
	response, err := client.Get(g.String(target)).Do().Result()
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer response.Body.Close()

	fmt.Printf("HTTP status: %d\n", response.StatusCode)
	if state := response.GetResponse().TLS; state != nil {
		fmt.Printf("TLS: %s; ALPN: %q\n", tls.VersionName(state.Version), state.NegotiatedProtocol)
	}
	return nil
}
