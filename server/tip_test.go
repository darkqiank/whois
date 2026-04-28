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
	if result.Registrant != "Example Registrant" {
		t.Fatalf("unexpected registrant: %s", result.Registrant)
	}
}

func TestConvertToTipResponseDoesNotMixRegistrarAndRegistrant(t *testing.T) {
	t.Run("registrar does not fall back to registrant", func(t *testing.T) {
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
		if result.Registrar != "" {
			t.Fatalf("registrar should not fall back to registrant, got: %s", result.Registrar)
		}
	})

	t.Run("registrant does not fall back to registrar", func(t *testing.T) {
		result, err := convertToTipResponse(parser.WhoisInfo{
			Domain: &parser.Domain{
				Domain: "example.com",
			},
			Registrar: &parser.Contact{
				Name:         "Example Registrar",
				Organization: "Registrar Org",
				Email:        "registrar@example.com",
				Phone:        "+1.555",
			},
		})
		if err != nil {
			t.Fatalf("convert to tip response: %v", err)
		}
		if result.Registrant != "" {
			t.Fatalf("registrant should not fall back to registrar, got: %s", result.Registrant)
		}
		if result.RegistrantOrganization != "" {
			t.Fatalf("registrant organization should not fall back to registrar, got: %s", result.RegistrantOrganization)
		}
		if result.ContactEmail != "registrar@example.com" {
			t.Fatalf("contact email should fall back to registrar, got: %s", result.ContactEmail)
		}
		if result.ContactPhone != "+1.555" {
			t.Fatalf("contact phone should fall back to registrar, got: %s", result.ContactPhone)
		}
	})
}
