package main

import (
	"flag"
	"github.com/joeig/domainwatchdog/pkg/whois"
	"log"
	"os"
	"strings"
)

const (
	ExitOK           = 0
	ExitFatalError   = 1
	ExitAvailable    = 2
	ExitUnknownError = 3
)

type WhoisClient interface {
	GetDomainStatus(domain string) (whois.Status, error)
}

func run(domainsList *string, whoisClient WhoisClient) int {
	if *domainsList == "" {
		log.Println("no domains given")
		return ExitFatalError
	}

	domains := strings.Split(*domainsList, ",")
	exitCode := ExitOK

	for _, domain := range domains {
		domain := domain

		status, err := whoisClient.GetDomainStatus(domain)
		if err != nil {
			log.Printf("cannot determine status of domain %q: %q", domain, err)

			if exitCode != ExitAvailable {
				exitCode = ExitUnknownError
			}

			continue
		}

		if status != whois.GivenDomain {
			log.Printf("domain %q is available: %q", domain, status)
			exitCode = ExitAvailable
			continue
		}

		log.Printf("status of domain %q: %q", domain, status)
	}

	return exitCode
}

func main() {
	domainsList := flag.String("domains", "", "Domains (comma separated)")
	flag.Parse()

	whoisClient := whois.New(whois.DefaultClient, whois.DefaultParse)
	os.Exit(run(domainsList, whoisClient))
}
