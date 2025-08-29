package util

import (
	"context"
	"fmt"
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

	t.Run("dns-01", func(t *testing.T) {
		withMockDNSQuery(t, []interaction{
			{"CNAME _acme-challenge.example.org.", &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.example.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0}, Target: "_acme-challenge.target.org."},
				},
			}},
			{"CNAME _acme-challenge.target.org.", &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{},
			}},
		})
		got, err := DNS01LookupFQDN(context.Background(), "example.org", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "_acme-challenge.target.org."
		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	})

	t.Run("dns-account-01", func(t *testing.T) {
		withMockDNSQuery(t, []interaction{
			{fmt.Sprintf("CNAME _%s._acme-challenge.example.org.", label), &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.CNAME{Hdr: dns.RR_Header{Name: fmt.Sprintf("_%s._acme-challenge.example.org.", label), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0}, Target: fmt.Sprintf("_%s._acme-challenge.target.org.", label)},
				},
			}},
			{fmt.Sprintf("CNAME _%s._acme-challenge.target.org.", label), &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{},
			}},
		})
		got, err := DNSAccount01LookupFQDN(context.Background(), "example.org", accountURL, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := fmt.Sprintf("_%s._acme-challenge.target.org.", label)
		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	})
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
