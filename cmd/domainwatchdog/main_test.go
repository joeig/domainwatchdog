package main

import (
	"bytes"
	"errors"
	"github.com/joeig/domainwatchdog/pkg/whois"
	"testing"
)

type mockWhoisClient struct {
	WhoisStatus whois.Status
	WhoisErr    error
}

func (m *mockWhoisClient) GetDomainStatus(_ string) (whois.Status, error) {
	return m.WhoisStatus, m.WhoisErr
}

func TestAppContext_Run(t *testing.T) {
	app := newAppContext(&mockWhoisClient{WhoisStatus: whois.GivenDomain}, new(bytes.Buffer))
	domains := "example.com"

	code := app.Run(&domains)

	if code != ExitOK {
		t.Error("wrong code")
	}
}

func TestAppContext_Run_noDomainsGiven(t *testing.T) {
	app := newAppContext(&mockWhoisClient{WhoisStatus: whois.UnknownStatus}, new(bytes.Buffer))
	domains := ""

	code := app.Run(&domains)

	if code != ExitFatalError {
		t.Error("wrong code")
	}
}

func TestAppContext_Run_statusErr(t *testing.T) {
	app := newAppContext(&mockWhoisClient{WhoisErr: errors.New("mock")}, new(bytes.Buffer))
	domains := "example.com"

	code := app.Run(&domains)

	if code != ExitUnknownError {
		t.Error("wrong code")
	}
}

func TestAppContext_Run_statusAvailable(t *testing.T) {
	app := newAppContext(&mockWhoisClient{WhoisStatus: whois.UnknownStatus}, new(bytes.Buffer))
	domains := "example.com"

	code := app.Run(&domains)

	if code != ExitAvailable {
		t.Error("wrong code")
	}
}

func TestRunWithFlags(t *testing.T) {
	stdout := new(bytes.Buffer)
	app := newAppContext(&mockWhoisClient{WhoisStatus: whois.GivenDomain}, stdout)
	stderr := new(bytes.Buffer)

	code := runWithFlags(app, stderr, []string{"main.go", "-domains", "example.com,example.net"})

	if code != 0 {
		t.Error("wrong code")
	}

	if stdout.String() == "" {
		t.Error("missing stdout")
	}

	if stderr.String() != "" {
		t.Error("unexpected stderr")
	}
}
