package util

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSAccount01Label(t *testing.T) {
	accountURL := "https://example.com/acme/acct/ExampleAccount"
	want := "ujmmovf2vn55tgye"
	got := DNSAccount01Label(accountURL)
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestLookupFQDN(t *testing.T) {
	accountURL := "https://example.com/acme/acct/ExampleAccount"
	label := DNSAccount01Label(accountURL)
	tests := []struct {
		name   string
		lookup func(context.Context) (string, error)
		want   string
	}{
		{
			name: "dns-01",
			lookup: func(ctx context.Context) (string, error) {
				return DNS01LookupFQDN(ctx, "example.org", false)
			},
			want: "_acme-challenge.example.org.",
		},
		{
			name: "dns-account-01",
			lookup: func(ctx context.Context) (string, error) {
				return DNSAccount01LookupFQDN(ctx, "example.org", accountURL, false)
			},
			want: fmt.Sprintf("_%s._acme-challenge.example.org.", label),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.lookup(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestLookupFQDNCNAME(t *testing.T) {
	accountURL := "https://example.com/acme/acct/ExampleAccount"
	label := DNSAccount01Label(accountURL)
	records := map[string]string{
		"_acme-challenge.example.org.":                         "_acme-challenge.target.org.",
		fmt.Sprintf("_%s._acme-challenge.example.org.", label): fmt.Sprintf("_%s._acme-challenge.target.org.", label),
	}
	addr, shutdown := runDNSServer(t, records)
	defer shutdown()

	tests := []struct {
		name   string
		lookup func(context.Context) (string, error)
		want   string
	}{
		{
			name: "dns-01",
			lookup: func(ctx context.Context) (string, error) {
				return DNS01LookupFQDN(ctx, "example.org", true, addr)
			},
			want: "_acme-challenge.target.org.",
		},
		{
			name: "dns-account-01",
			lookup: func(ctx context.Context) (string, error) {
				return DNSAccount01LookupFQDN(ctx, "example.org", accountURL, true, addr)
			},
			want: fmt.Sprintf("_%s._acme-challenge.target.org.", label),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.lookup(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestFindBestMatch(t *testing.T) {
	domains := []string{
		"foo.example.com",
		"foo.bar.example.com",
		"example.com",
		"baz.com",
	}
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{name: "exact match tld", query: "example.com", want: "example.com"},
		{name: "exact match subdomain", query: "foo.example.com", want: "foo.example.com"},
		{name: "exact match subdomain two levels", query: "foo.bar.example.com", want: "foo.bar.example.com"},
		{name: "partial match tld", query: "baz.example.com", want: "example.com"},
		{name: "partial match subdomain", query: "baz.foo.example.com", want: "foo.example.com"},
		{name: "no match reversed order", query: "com.example.foo", want: ""},
		{name: "no matches", query: "bar.com", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := FindBestMatch(tt.query, domains...)
			if got != tt.want {
				t.Fatalf("query %s: expected %s, got %s", tt.query, tt.want, got)
			}
		})
	}
}

func runDNSServer(t *testing.T, records map[string]string) (string, func()) {
	mux := dns.NewServeMux()
	for name, target := range records {
		handler := func(target string) dns.HandlerFunc {
			return func(w dns.ResponseWriter, r *dns.Msg) {
				m := &dns.Msg{}
				m.SetReply(r)
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0},
					Target: target,
				})
				_ = w.WriteMsg(m)
			}
		}
		mux.HandleFunc(name, handler(target))
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() {
		_ = server.ActivateAndServe()
	}()
	return pc.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = pc.Close()
	}
}
