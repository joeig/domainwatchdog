package whois

import (
	"fmt"
	"github.com/likexian/whois"
	whoisParser "github.com/likexian/whois-parser"
	"regexp"
)

type Status string

var (
	GivenDomain    Status = "domain is given"
	NotFoundDomain Status = "domain not found"
	ReservedDomain Status = "domain is reserved to register"
	PremiumDomain  Status = "domain is available at premium price"
	BlockedDomain  Status = "domain is blocked due to brand protection"
	UnknownStatus  Status = "status is unknown"
)

type WhoisClient interface {
	Whois(domain string, servers ...string) (result string, err error)
}

type WhoisParse func(text string) (whoisInfo whoisParser.WhoisInfo, err error)

var (
	DefaultClient = whois.DefaultClient
	DefaultParse  = whoisParser.Parse
)

type Whois struct {
	whoisClient WhoisClient
	whoisParse  WhoisParse
}

func New(whoisClient WhoisClient, whoisParse WhoisParse) *Whois {
	return &Whois{
		whoisClient: whoisClient,
		whoisParse:  whoisParse,
	}
}

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
