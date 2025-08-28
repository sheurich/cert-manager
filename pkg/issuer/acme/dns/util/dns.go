// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package util

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DNS01LookupFQDN returns a DNS name which will be updated to solve the dns-01
// challenge
// TODO: move this into the pkg/acme package
func DNS01LookupFQDN(ctx context.Context, domain string, followCNAME bool, nameservers ...string) (string, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	// Check if the domain has CNAME then return that
	if followCNAME {
		var err error
		fqdn, err = followCNAMEs(ctx, fqdn, nameservers)
		if err != nil {
			return "", err
		}
	}

	return fqdn, nil
}

// DNSAccount01LookupFQDN returns the FQDN for a dns-account-01 challenge.
// The accountURL is the ACME account identifier used to generate the label.
func DNSAccount01LookupFQDN(ctx context.Context, domain, accountURL string, followCNAME bool, nameservers ...string) (string, error) {
	sum := sha256.Sum256([]byte(accountURL))
	// Use first 10 bytes and base32 encode without padding, lowercase
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]))
	fqdn := fmt.Sprintf("_%s._acme-challenge.%s.", label, domain)

	if followCNAME {
		var err error
		fqdn, err = followCNAMEs(ctx, fqdn, nameservers)
		if err != nil {
			return "", err
		}
	}

	return fqdn, nil
}

// FindBestMatch returns the longest match for a given domain within a list of domains
func FindBestMatch(query string, domains ...string) (string, error) {
	var maxSoFar int
	var longest string

	for _, domain := range domains {
		if query == domain {
			// Found exact match
			return domain, nil
		}

		maxHere := dns.CompareDomainName(query, domain)
		if maxHere > maxSoFar && dns.IsSubDomain(domain, query) {
			maxSoFar = maxHere
			longest = domain
		}
	}

	if len(longest) == 0 {
		return "", fmt.Errorf("query: %v has no matches", query)
	}
	return longest, nil
}
