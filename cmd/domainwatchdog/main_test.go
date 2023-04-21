package main

import (
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

func Test_Run(t *testing.T) {
	app := appContext{WhoisClient: &mockWhoisClient{WhoisStatus: whois.GivenDomain}}
	domains := "example.com"

	code := app.Run(&domains)

	if code != ExitOK {
		t.Error("wrong code")
	}
}

func Test_Run_noDomainsGiven(t *testing.T) {
	app := appContext{WhoisClient: &mockWhoisClient{WhoisStatus: whois.UnknownStatus}}
	domains := ""

	code := app.Run(&domains)

	if code != ExitFatalError {
		t.Error("wrong code")
	}
}

func Test_Run_statusErr(t *testing.T) {
	app := appContext{WhoisClient: &mockWhoisClient{WhoisErr: errors.New("mock")}}
	domains := "example.com"

	code := app.Run(&domains)

	if code != ExitUnknownError {
		t.Error("wrong code")
	}
}

func Test_Run_statusAvailable(t *testing.T) {
	app := appContext{WhoisClient: &mockWhoisClient{WhoisStatus: whois.UnknownStatus}}
	domains := "example.com"

	code := app.Run(&domains)

	if code != ExitAvailable {
		t.Error("wrong code")
	}
}
