package server

import (
	"testing"

	parser "github.com/darkqiank/whois/parsers"
)

func TestConvertToTipResponseRegistrantOrganization(t *testing.T) {
	result, err := convertToTipResponse(parser.WhoisInfo{
		Domain: &parser.Domain{
			Domain: "example.com",
		},
		Registrant: &parser.Contact{
			Name:         "Example Registrant",
			Organization: "Example Org",
		},
	})
	if err != nil {
		t.Fatalf("convert to tip response: %v", err)
	}

	if result.RegistrantOrganization != "Example Org" {
		t.Fatalf("unexpected registrant organization: %s", result.RegistrantOrganization)
	}
}
