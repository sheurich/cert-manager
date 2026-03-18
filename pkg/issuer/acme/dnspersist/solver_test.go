/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dnspersist

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestPresent(t *testing.T) {
	s := &Solver{}
	err := s.Present(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Present returned error: %v", err)
	}
}

func TestCleanUp(t *testing.T) {
	s := &Solver{}
	err := s.CleanUp(context.Background(), nil)
	if err != nil {
		t.Fatalf("CleanUp returned error: %v", err)
	}
}

func TestCheck(t *testing.T) {
	const (
		accountURI = "https://acme.example/acct/1"
		domain     = "example.com"
	)

	tests := []struct {
		name                string
		domain              string
		wildcard            bool
		emptyDNSName        bool
		accountURI          string // issuer account URI
		challengeAccountURI string // challenge object accounturi (if set)
		nilACMEStatus       bool   // simulate issuer without completed ACME registration
		issuerDomains       []string
		txtRecords          []string
		txtErr              error
		wantErr             bool
		wantErrSubstring    string
		wantFQDN            string
	}{
		{
			name:          "matching record",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "no TXT records",
			accountURI:       accountURI,
			issuerDomains:    []string{"letsencrypt.org"},
			txtRecords:       nil,
			wantErr:          true,
			wantErrSubstring: "no matching _validation-persist TXT record found",
		},
		{
			name:             "wrong accounturi",
			accountURI:       accountURI,
			issuerDomains:    []string{"letsencrypt.org"},
			txtRecords:       []string{"letsencrypt.org; accounturi=https://acme.example/acct/999"},
			wantErr:          true,
			wantErrSubstring: "no matching _validation-persist TXT record found",
		},
		{
			name:             "wrong issuer-domain-name",
			accountURI:       accountURI,
			issuerDomains:    []string{"letsencrypt.org"},
			txtRecords:       []string{"other-ca.example; accounturi=https://acme.example/acct/1"},
			wantErr:          true,
			wantErrSubstring: "no matching _validation-persist TXT record found",
		},
		{
			name:             "empty account URI on both challenge and issuer",
			accountURI:       "",
			issuerDomains:    []string{"letsencrypt.org"},
			wantErr:          true,
			wantErrSubstring: "no account URI available",
		},
		{
			name:             "nil ACMEStatus on issuer with no challenge accounturi",
			nilACMEStatus:    true,
			issuerDomains:    []string{"letsencrypt.org"},
			wantErr:          true,
			wantErrSubstring: "no account URI available",
		},
		{
			name:                "nil ACMEStatus on issuer with challenge accounturi",
			nilACMEStatus:       true,
			challengeAccountURI: accountURI,
			issuerDomains:       []string{"letsencrypt.org"},
			txtRecords:          []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "empty IssuerDomainNames",
			accountURI:       accountURI,
			issuerDomains:    nil,
			wantErr:          true,
			wantErrSubstring: "challenge has no issuer-domain-names",
		},
		{
			name:          "extra parameters in record (forward compat)",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1; policy=wildcard"},
		},
		{
			name:          "multiple IssuerDomainNames matches second",
			accountURI:    accountURI,
			issuerDomains: []string{"buypass.com", "letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "DNS lookup error",
			accountURI:       accountURI,
			issuerDomains:    []string{"letsencrypt.org"},
			txtErr:           fmt.Errorf("network error"),
			wantErr:          true,
			wantErrSubstring: "failed to query TXT records",
		},
		{
			name:          "no space after semicolon",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org;accounturi=https://acme.example/acct/1"},
		},
		{
			name:          "case-insensitive issuer domain match",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{"LetsEncrypt.Org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "empty DNSName",
			emptyDNSName:     true,
			accountURI:       accountURI,
			issuerDomains:    []string{"letsencrypt.org"},
			wantErr:          true,
			wantErrSubstring: "challenge DNSName is empty",
		},
		{
			name:          "wildcard domain",
			domain:        domain,
			wildcard:      true,
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
			wantFQDN:      "_validation-persist.example.com.",
		},
		{
			name:          "IssuerDomainNames with empty entries",
			accountURI:    accountURI,
			issuerDomains: []string{"", " ", "letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "IssuerDomainNames all empty/whitespace",
			accountURI:       accountURI,
			issuerDomains:    []string{"", " "},
			wantErr:          true,
			wantErrSubstring: "no valid issuer-domain-names",
		},
		{
			name:          "IssuerDomainNames bare dot skipped",
			accountURI:    accountURI,
			issuerDomains: []string{".", "letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "IssuerDomainNames all bare dots",
			accountURI:       accountURI,
			issuerDomains:    []string{".", " . "},
			wantErr:          true,
			wantErrSubstring: "no valid issuer-domain-names",
		},
		{
			name:          "quoted accounturi value",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{`letsencrypt.org; accounturi="https://acme.example/acct/1"`},
		},
		{
			name:          "issuer domain with trailing dot",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org"},
			txtRecords:    []string{"letsencrypt.org.; accounturi=https://acme.example/acct/1"},
		},
		{
			name:          "issuerDomainNames with trailing dot",
			accountURI:    accountURI,
			issuerDomains: []string{"letsencrypt.org."},
			txtRecords:    []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:             "unbalanced quote on accounturi",
			accountURI:       accountURI,
			issuerDomains:    []string{"letsencrypt.org"},
			txtRecords:       []string{`letsencrypt.org; accounturi="https://acme.example/acct/1`},
			wantErr:          true,
			wantErrSubstring: "no matching _validation-persist TXT record found",
		},
		{
			name:                "challenge accounturi used instead of issuer URI",
			accountURI:          "https://acme.example/acct/old",
			challengeAccountURI: accountURI,
			issuerDomains:       []string{"letsencrypt.org"},
			txtRecords:          []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:                "challenge accounturi fallback to issuer",
			accountURI:          accountURI,
			challengeAccountURI: "",
			issuerDomains:       []string{"letsencrypt.org"},
			txtRecords:          []string{"letsencrypt.org; accounturi=https://acme.example/acct/1"},
		},
		{
			name:                "case-insensitive accounturi tag in TXT record",
			accountURI:          accountURI,
			issuerDomains:       []string{"letsencrypt.org"},
			txtRecords:          []string{"letsencrypt.org; AccountURI=https://acme.example/acct/1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotFQDN string
			s := &Solver{
				dns01Nameservers: []string{"8.8.8.8:53"},
				lookupTXT: func(_ context.Context, fqdn string, _ []string) ([]string, error) {
					gotFQDN = fqdn
					return tt.txtRecords, tt.txtErr
				},
			}

			issuer := &cmapi.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-issuer"},
			}
			if !tt.nilACMEStatus {
				issuer.Status.ACME = &cmacme.ACMEIssuerStatus{URI: tt.accountURI}
			}

			dnsName := tt.domain
			if dnsName == "" && !tt.emptyDNSName {
				dnsName = domain
			}
			ch := &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					DNSName:           dnsName,
					Wildcard:          tt.wildcard,
					IssuerDomainNames: tt.issuerDomains,
					AccountURI:        tt.challengeAccountURI,
				},
			}

			err := s.Check(context.Background(), issuer, ch)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.wantErrSubstring != "" && !strings.Contains(err.Error(), tt.wantErrSubstring) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrSubstring)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantFQDN != "" && gotFQDN != tt.wantFQDN {
				t.Fatalf("lookupTXT called with fqdn %q, want %q", gotFQDN, tt.wantFQDN)
			}
		})
	}
}

func TestParseIssueValue(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantDomain     string
		wantAccountURI string
	}{
		{
			name:           "standard format",
			input:          "letsencrypt.org; accounturi=https://acme.example/acct/1",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "no space after semicolon",
			input:          "letsencrypt.org;accounturi=https://acme.example/acct/1",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "quoted accounturi",
			input:          `letsencrypt.org; accounturi="https://acme.example/acct/1"`,
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "trailing dot on issuer domain",
			input:          "letsencrypt.org.; accounturi=https://acme.example/acct/1",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "extra parameters",
			input:          "letsencrypt.org; accounturi=https://acme.example/acct/1; policy=wildcard",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:       "empty input",
			input:      "",
			wantDomain: "",
		},
		{
			name:       "semicolons only",
			input:      ";;;",
			wantDomain: "",
		},
		{
			name:       "domain only, no parameters",
			input:      "letsencrypt.org",
			wantDomain: "letsencrypt.org",
		},
		{
			name:           "extra whitespace",
			input:          "  letsencrypt.org ;  accounturi=https://acme.example/acct/1  ",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "unbalanced opening quote on accounturi",
			input:          `letsencrypt.org; accounturi="https://acme.example/acct/1`,
			wantDomain:     "letsencrypt.org",
			wantAccountURI: `"https://acme.example/acct/1`,
		},
		{
			name:           "multiple trailing dots (malformed)",
			input:          "letsencrypt.org...; accounturi=https://acme.example/acct/1",
			wantDomain:     "letsencrypt.org..",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "case-insensitive AccountURI tag",
			input:          "letsencrypt.org; AccountURI=https://acme.example/acct/1",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
		{
			name:           "mixed-case ACCOUNTURI tag",
			input:          "letsencrypt.org; ACCOUNTURI=https://acme.example/acct/1",
			wantDomain:     "letsencrypt.org",
			wantAccountURI: "https://acme.example/acct/1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDomain, gotURI := parseIssueValue(tt.input)
			if gotDomain != tt.wantDomain {
				t.Errorf("issuerDomain = %q, want %q", gotDomain, tt.wantDomain)
			}
			if gotURI != tt.wantAccountURI {
				t.Errorf("accountURI = %q, want %q", gotURI, tt.wantAccountURI)
			}
		})
	}
}
