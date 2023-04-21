package whois

import (
	"fmt"
	"github.com/likexian/whois"
	whoisParser "github.com/likexian/whois-parser"
	"regexp"
)

// Status is a domain registration status.
type Status string

var (
	// GivenDomain is the status for given domains.
	GivenDomain Status = "domain is given"
	// NotFoundDomain is the status if the domain wasn't found.
	NotFoundDomain Status = "domain not found"
	// ReservedDomain is the status if the domain is reserved to register.
	ReservedDomain Status = "domain is reserved to register"
	// PremiumDomain is the status if the domain is available at premium price.
	PremiumDomain Status = "domain is available at premium price"
	// BlockedDomain is the status if the domain is blocked due to brand protection.
	BlockedDomain Status = "domain is blocked due to brand protection"
	// UnknownStatus is the status if the status is unknown.
	UnknownStatus Status = "status is unknown"
)

// WhoisClient defines a whois client interface.
type WhoisClient interface {
	// Whois returns the whois result for a given domain, requested from specific servers.
	Whois(domain string, servers ...string) (result string, err error)
}

// WhoisParse parses a whois result.
type WhoisParse func(text string) (whoisInfo whoisParser.WhoisInfo, err error)

var (
	// DefaultClient contains the default WhoisClient implementation.
	DefaultClient = whois.DefaultClient
	// DefaultParse contains the default WhoisParse implementation.
	DefaultParse = whoisParser.Parse
)

// Whois defines a whois interface.
type Whois struct {
	whoisClient WhoisClient
	whoisParse  WhoisParse
}

// New initializes a Whois pointer by a given WhoisClient and WhoisParse.
func New(whoisClient WhoisClient, whoisParse WhoisParse) *Whois {
	return &Whois{
		whoisClient: whoisClient,
		whoisParse:  whoisParse,
	}
}

// GetDomainStatus returns the Status of a given domain.
func (w *Whois) GetDomainStatus(domain string) (Status, error) {
	result, err := w.whoisClient.Whois(domain)
	if err != nil {
		return "", fmt.Errorf("whois query error: %w", err)
	}

	data, err := w.whoisParse(result)
	if err != nil {
		return mapParseError(err)
	}

	if isGiven(data.Domain.Status) {
		return GivenDomain, nil
	}

	return UnknownStatus, nil
}

func mapParseError(parseError error) (Status, error) {
	switch parseError {
	case whoisParser.ErrNotFoundDomain:
		return NotFoundDomain, nil
	case whoisParser.ErrReservedDomain:
		return ReservedDomain, nil
	case whoisParser.ErrPremiumDomain:
		return PremiumDomain, nil
	case whoisParser.ErrBlockedDomain:
		return BlockedDomain, nil
	default:
		return UnknownStatus, parseError
	}
}

var patterns = []*regexp.Regexp{
	// DENIC
	regexp.MustCompile(`^connect$`),

	// ICANN
	// Source: https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
	regexp.MustCompile(`^inactive$`),
	regexp.MustCompile(`^ok$`),
	regexp.MustCompile(`^(?i)pending(?:Create|Renew|Restore|Transfer|Update)$`),
	regexp.MustCompile(`^(?i)(?:add|autoRenew|renew|transfer)Period$`),
	regexp.MustCompile(`^(?i)(?:server|client)Hold$`),
	regexp.MustCompile(`^(?i)(?:server|client)(?:Delete|Renew|Transfer|Update)Prohibited$`),

	// IANA
	regexp.MustCompile(`^ACTIVE$`),

	// Other
	regexp.MustCompile(`^registered$`),
}

func isGiven(status []string) bool {
	for _, currentStatus := range status {
		currentStatus := currentStatus

		for _, pattern := range patterns {
			if pattern.MatchString(currentStatus) {
				return true
			}
		}
	}

	return false
}
