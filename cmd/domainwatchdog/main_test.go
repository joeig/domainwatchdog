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

func Test_run(t *testing.T) {
	domains := "example.com"
	whoisClient := &mockWhoisClient{WhoisStatus: whois.GivenDomain}

	code := run(&domains, whoisClient)

	if code != ExitOK {
		t.Error("wrong code")
	}
}

func Test_run_noDomaisGiven(t *testing.T) {
	domains := ""
	whoisClient := &mockWhoisClient{WhoisStatus: whois.UnknownStatus}

	code := run(&domains, whoisClient)

	if code != ExitFatalError {
		t.Error("wrong code")
	}
}

func Test_run_statusErr(t *testing.T) {
	domains := "example.com"
	whoisClient := &mockWhoisClient{WhoisErr: errors.New("mock")}

	code := run(&domains, whoisClient)

	if code != ExitUnknownError {
		t.Error("wrong code")
	}
}

func Test_run_statusAvailable(t *testing.T) {
	domains := "example.com"
	whoisClient := &mockWhoisClient{WhoisStatus: whois.UnknownStatus}

	code := run(&domains, whoisClient)

	if code != ExitAvailable {
		t.Error("wrong code")
	}
}
