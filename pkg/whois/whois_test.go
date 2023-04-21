package whois

import (
	"errors"
	whoisParser "github.com/likexian/whois-parser"
	"testing"
)

type mockClient struct {
	WhoisErr error
}

func (m *mockClient) Whois(_ string, _ ...string) (result string, err error) {
	return "", m.WhoisErr
}

func newMockParse(status []string, parseErr error) WhoisParse {
	return func(text string) (whoisInfo whoisParser.WhoisInfo, err error) {
		return whoisParser.WhoisInfo{
			Domain: &whoisParser.Domain{
				Status: status,
			},
		}, parseErr
	}
}

func TestWhois_GetDomainStatus(t *testing.T) {
	whois := New(&mockClient{}, newMockParse([]string{"connect"}, nil))

	status, err := whois.GetDomainStatus("example.com")

	if status != GivenDomain {
		t.Error("wrong status")
	}
	if err != nil {
		t.Error("nil returned")
	}
}

func TestWhois_GetDomainStatus_handleWhoisError(t *testing.T) {
	whois := New(&mockClient{WhoisErr: errors.New("mock")}, newMockParse([]string{"connect"}, nil))

	status, err := whois.GetDomainStatus("example.com")

	if status != "" {
		t.Error("status not empty")
	}
	if err.Error() != "whois query error: mock" {
		t.Error("wrong error")
	}
}

func TestWhois_GetDomainStatus_handleParseError(t *testing.T) {
	whois := New(&mockClient{}, newMockParse([]string{"connect"}, errors.New("mock")))

	status, err := whois.GetDomainStatus("example.com")

	if status != UnknownStatus {
		t.Error("wrong status")
	}
	if err.Error() != "mock" {
		t.Error("wrong error")
	}
}

func TestWhois_GetDomainStatus_handleUnknownStatus(t *testing.T) {
	whois := New(&mockClient{}, newMockParse([]string{"free"}, nil))

	status, err := whois.GetDomainStatus("example.com")

	if status != UnknownStatus {
		t.Error("wrong status")
	}
	if err != nil {
		t.Error("error not nil")
	}
}

func Test_mapParseError(t *testing.T) {
	type args struct {
		parseError error
	}
	tests := []struct {
		name    string
		args    args
		want    Status
		wantErr bool
	}{
		{
			name:    "ErrNotFoundDomain",
			args:    args{parseError: whoisParser.ErrNotFoundDomain},
			want:    NotFoundDomain,
			wantErr: false,
		},
		{
			name:    "ErrReservedDomain",
			args:    args{parseError: whoisParser.ErrReservedDomain},
			want:    ReservedDomain,
			wantErr: false,
		},
		{
			name:    "ErrPremiumDomain",
			args:    args{parseError: whoisParser.ErrPremiumDomain},
			want:    PremiumDomain,
			wantErr: false,
		},
		{
			name:    "ErrBlockedDomain",
			args:    args{parseError: whoisParser.ErrBlockedDomain},
			want:    BlockedDomain,
			wantErr: false,
		},
		{
			name:    "unknown",
			args:    args{parseError: errors.New("unknown")},
			want:    UnknownStatus,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mapParseError(tt.args.parseError)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapParseError() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mapParseError() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isGiven(t *testing.T) {
	type args struct {
		status []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "connect",
			args: args{status: []string{"connect"}},
			want: true,
		},
		{
			name: "clientDeleteProhibited",
			args: args{status: []string{"clientDeleteProhibited"}},
			want: true,
		},
		{
			name: "clientdeleteprohibited and servertransferprohibited",
			args: args{status: []string{"clientdeleteprohibited", "servertransferprohibited"}},
			want: true,
		},
		{
			name: "unknown",
			args: args{status: []string{"unknown"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGiven(tt.args.status); got != tt.want {
				t.Errorf("isGiven() = %v, want %v", got, tt.want)
			}
		})
	}
}
