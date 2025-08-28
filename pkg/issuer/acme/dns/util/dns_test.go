package util

import (
	"context"
	"testing"
)

func TestDNSAccount01LookupFQDN(t *testing.T) {
	accountURL := "https://example.com/acme/acct/ExampleAccount"
	fqdn, err := DNSAccount01LookupFQDN(context.Background(), "example.org", accountURL, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "_ujmmovf2vn55tgye._acme-challenge.example.org."
	if fqdn != want {
		t.Fatalf("expected %s, got %s", want, fqdn)
	}
}
