package main

import (
	"flag"
	"github.com/joeig/domainwatchdog/pkg/whois"
	"log"
	"os"
	"strings"
)

const (
	// ExitOK returns if all domains are given.
	ExitOK = 0
	// ExitFatalError returns if the application couldn't be executed.
	ExitFatalError = 1
	// ExitAvailable returns if there is at least one domain which is available. This exit code has precedence over other exit codes.
	ExitAvailable = 2
	// ExitUnknownError returns if an unknown error occurred for at least one domain.
	ExitUnknownError = 3
)

// WhoisClient defines a whois client interface.
type WhoisClient interface {
	// GetDomainStatus returns a registration status for a given domain.
	GetDomainStatus(domain string) (whois.Status, error)
}

type appContext struct {
	// WhoisClient holds an instance of WhoisClient.
	WhoisClient WhoisClient
}

func (a *appContext) Run(domainsList *string) int {
	if *domainsList == "" {
		log.Println("no domains given")
		return ExitFatalError
	}

	domains := strings.Split(*domainsList, ",")
	exitCode := ExitOK

	for _, domain := range domains {
		domain := domain

		newExitCode := a.processDomain(domain)
		if exitCode != ExitAvailable {
			if newExitCode != ExitOK {
				exitCode = newExitCode
			}
		}
	}

	return exitCode
}

func (a *appContext) processDomain(domain string) int {
	status, err := a.WhoisClient.GetDomainStatus(domain)
	if err != nil {
		log.Printf("cannot determine status of domain %q: %q", domain, err)
		return ExitUnknownError
	}

	if status != whois.GivenDomain {
		log.Printf("domain %q is available: %q", domain, status)
		return ExitAvailable
	}

	log.Printf("status of domain %q: %q", domain, status)
	return ExitOK
}

func main() {
	domainsList := flag.String("domains", "", "Domains (comma separated)")
	flag.Parse()

	app := &appContext{
		WhoisClient: whois.New(whois.DefaultClient, whois.DefaultParse),
	}

	os.Exit(app.Run(domainsList))
}
