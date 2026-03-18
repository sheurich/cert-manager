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

	"github.com/miekg/dns"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	dnsutil "github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// lookupTXTFunc queries TXT records for the given FQDN using the provided nameservers.
type lookupTXTFunc func(ctx context.Context, fqdn string, nameservers []string) ([]string, error)

// Solver implements the dns-persist-01 challenge type. Present and CleanUp are
// no-ops because the persistent TXT record is provisioned out-of-band. Check
// verifies the record exists and matches the ACME account URI and issuer domain.
type Solver struct {
	dns01Nameservers []string
	lookupTXT        lookupTXTFunc
}

// NewSolver constructs a Solver from the controller context.
func NewSolver(ctx *controllerpkg.Context) (*Solver, error) {
	nameservers := ctx.ACMEOptions.DNS01Nameservers
	if len(nameservers) == 0 {
		nameservers = dnsutil.RecursiveNameservers
	}
	return &Solver{
		dns01Nameservers: nameservers,
		lookupTXT:        defaultLookupTXT,
	}, nil
}

// defaultLookupTXT queries TXT records using dnsutil.DNSQuery.
func defaultLookupTXT(ctx context.Context, fqdn string, nameservers []string) ([]string, error) {
	msg, err := dnsutil.DNSQuery(ctx, fqdn, dns.TypeTXT, nameservers, true)
	if err != nil {
		return nil, err
	}
	var records []string
	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}
	return records, nil
}

// Present is a no-op; the dns-persist-01 record is provisioned out-of-band.
func (s *Solver) Present(ctx context.Context, _ cmapi.GenericIssuer, _ *cmacme.Challenge) error {
	logf.FromContext(ctx).V(logf.DebugLevel).Info("dns-persist-01 Present is a no-op; record is provisioned out-of-band")
	return nil
}

// Check verifies that a _validation-persist TXT record exists for the challenge
// domain and that it matches the ACME account URI and one of the issuer domain names.
func (s *Solver) Check(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
	// Prefer the accounturi from the challenge object (I-D §3);
	// fall back to the issuer's registered account URI.
	acmeStatus := issuer.GetStatus().ACMEStatus()
	accountURI := ch.Spec.AccountURI
	if accountURI == "" && acmeStatus != nil {
		accountURI = acmeStatus.URI
	}
	if accountURI == "" {
		return fmt.Errorf("no account URI available; neither challenge object nor issuer status provides one")
	}
	if ch.Spec.AccountURI != "" && acmeStatus != nil && acmeStatus.URI != "" && ch.Spec.AccountURI != acmeStatus.URI {
		logf.FromContext(ctx).Info("WARNING: challenge accounturi differs from issuer account URI; using challenge value per I-D §3",
			"challengeAccountURI", ch.Spec.AccountURI,
			"issuerAccountURI", acmeStatus.URI)
	}
	if len(ch.Spec.IssuerDomainNames) == 0 {
		return fmt.Errorf("challenge has no issuer-domain-names; ACME server did not provide them")
	}

	// Filter empty/whitespace entries and normalize trailing dots from IssuerDomainNames.
	//
	// TODO(Beta): Implement full I-D §3 4-step normalization for issuer
	// domain names: case-fold → NFC → Punycode (A-label) → strip trailing
	// dot. Currently we only strip trailing dots and rely on EqualFold for
	// case-insensitive comparison, which is sufficient for ASCII domains but
	// incomplete for internationalized domain names.
	validDomains := make([]string, 0, len(ch.Spec.IssuerDomainNames))
	for _, name := range ch.Spec.IssuerDomainNames {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			if normalized := strings.TrimSuffix(trimmed, "."); normalized != "" {
				validDomains = append(validDomains, normalized)
			}
		}
	}
	if len(validDomains) == 0 {
		return fmt.Errorf("challenge has no valid issuer-domain-names; all entries are empty, whitespace, or bare dots")
	}

	if ch.Spec.DNSName == "" {
		return fmt.Errorf("challenge DNSName is empty")
	}

	log := logf.FromContext(ctx).V(logf.DebugLevel)

	fqdn := fmt.Sprintf("_validation-persist.%s.", ch.Spec.DNSName)
	records, err := s.lookupTXT(ctx, fqdn, s.dns01Nameservers)
	if err != nil {
		return fmt.Errorf("failed to query TXT records for %s: %w", fqdn, err)
	}

	for _, record := range records {
		issuerDomain, recordURI := parseIssueValue(record)
		if recordURI != accountURI {
			log.Info("TXT record accounturi mismatch", "record", record, "expected", accountURI, "got", recordURI)
			continue
		}
		domainMatch := false
		for _, allowed := range validDomains {
			if strings.EqualFold(issuerDomain, allowed) {
				domainMatch = true
				break
			}
		}
		if domainMatch {
			return nil
		}
		log.Info("TXT record issuer-domain mismatch", "record", record, "issuerDomain", issuerDomain, "allowed", validDomains)
	}

	return fmt.Errorf(
		"no matching _validation-persist TXT record found for %s (expected accounturi=%s with issuer-domain-name matching one of %v)",
		ch.Spec.DNSName, accountURI, validDomains,
	)
}

// CleanUp is a no-op; the persistent dns-persist-01 record is retained by design.
func (s *Solver) CleanUp(ctx context.Context, _ *cmacme.Challenge) error {
	logf.FromContext(ctx).V(logf.DebugLevel).Info("dns-persist-01 CleanUp is a no-op; persistent record retained by design")
	return nil
}

// parseIssueValue parses a CAA/dns-persist-01 issue-value string in the format:
//
//	"issuer-domain-name; accounturi=https://..."
//
// It returns the issuer domain name (with any trailing dot removed) and the
// account URI (with balanced surrounding double quotes stripped). Extra
// parameters are ignored.
//
// Per RFC 8659 §4.2, property tags are case-insensitive, so "accounturi",
// "AccountURI", etc. all match.
func parseIssueValue(value string) (issuerDomain, accountURI string) {
	tokens := strings.Split(value, ";")
	issuerDomain = strings.TrimSuffix(strings.TrimSpace(tokens[0]), ".")
	for _, token := range tokens[1:] {
		token = strings.TrimSpace(token)
		// RFC 8659 §4.2: property tags are case-insensitive.
		if len(token) >= len("accounturi=") && strings.EqualFold(token[:len("accounturi=")], "accounturi=") {
			v := token[len("accounturi="):]
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			accountURI = v
			break
		}
	}
	return issuerDomain, accountURI
}
