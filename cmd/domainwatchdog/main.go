package main

import (
	"flag"
	"github.com/joeig/domainwatchdog/pkg/whois"
	"io"
	"log/slog"
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

	logger *slog.Logger
}

func newAppContext(whoisClient WhoisClient, stdout io.Writer) *appContext {
	return &appContext{
		WhoisClient: whoisClient,
		logger:      slog.New(slog.NewTextHandler(stdout, nil)),
	}
}

func (a *appContext) Run(domainsList *string) int {
	if *domainsList == "" {
		a.logger.Error("no domains given")
		return ExitFatalError
	}

	domains := strings.Split(*domainsList, ",")
	exitCode := ExitOK

	for _, domain := range domains {
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
		a.logger.Warn("cannot determine status of domain %q: %q", domain, err)
		return ExitUnknownError
	}

	if status != whois.GivenDomain {
		a.logger.Info("domain %q is available: %q", domain, status)
		return ExitAvailable
	}

	a.logger.Info("status of domain %q: %q", domain, status)
	return ExitOK
}

func runWithFlags(app *appContext, stderr io.Writer, args []string) int {
	flagSet := flag.NewFlagSet(args[0], flag.ExitOnError)
	flagSet.SetOutput(stderr)
	domainsList := flagSet.String("domains", "", "Domains (comma separated)")
	_ = flagSet.Parse(args[1:])

	return app.Run(domainsList)
}

func main() {
	app := newAppContext(whois.New(whois.DefaultClient, whois.DefaultParse), os.Stdout)
	os.Exit(runWithFlags(app, os.Stderr, os.Args))
}
