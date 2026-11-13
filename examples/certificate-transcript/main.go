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
	flag.Parse()

	if err := run(*target); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(target string) error {
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("url must be an absolute HTTPS URL")
	}

	client := surf.NewClient()
	transport := client.GetTransport().(*surfhttp.Transport)
	dialer := client.GetDialer()
	transport.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", addr)
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

	fmt.Println("Safari 26.3; network=tcp4; certificate verification enabled; proxy disabled")
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
