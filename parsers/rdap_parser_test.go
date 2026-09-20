package parsers

import (
	"encoding/json"
	"testing"
)

func TestParseRDAPResponseEvents(t *testing.T) {
	const registrationDate = "2020-07-23T10:14:00Z"
	const changedDate = "2024-01-02T03:04:05Z"

	tests := []struct {
		name        string
		events      string
		wantUpdated string
	}{
		{
			name:   "missing last changed date from AFRINIC",
			events: `[{"eventAction":"registration","eventDate":"2020-07-23T10:14:00Z"},{"eventAction":"last changed"}]`,
		},
		{
			name:   "null last changed date",
			events: `[{"eventAction":"registration","eventDate":"2020-07-23T10:14:00Z"},{"eventAction":"last changed","eventDate":null}]`,
		},
		{
			name:   "non-string last changed date",
			events: `[{"eventAction":"registration","eventDate":"2020-07-23T10:14:00Z"},{"eventAction":"last changed","eventDate":123}]`,
		},
		{
			name:        "valid last changed date",
			events:      `[{"eventAction":"registration","eventDate":"2020-07-23T10:14:00Z"},{"eventAction":"last changed","eventDate":"2024-01-02T03:04:05Z"}]`,
			wantUpdated: changedDate,
		},
	}

	for _, objectClass := range []string{"ip network", "domain", "autnum"} {
		for _, tt := range tests {
			t.Run(objectClass+"/"+tt.name, func(t *testing.T) {
				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(`{"events":`+tt.events+`}`), &raw); err != nil {
					t.Fatal(err)
				}
				raw["objectClassName"] = objectClass

				parsed, err := ParseRDAPResponse(raw)
				if err != nil {
					t.Fatal(err)
				}

				var created, updated string
				switch data := parsed.Data.(type) {
				case IPInfo:
					created, updated = data.CreationDate, data.UpdatedDate
				case DomainInfo:
					created, updated = data.CreatedDate, data.UpdatedDate
				case ASNInfo:
					created, updated = data.CreationDate, data.UpdatedDate
				default:
					t.Fatalf("unexpected parsed data type: %T", parsed.Data)
				}
				if created != registrationDate || updated != tt.wantUpdated {
					t.Fatalf("event dates = (%q, %q), want (%q, %q)", created, updated, registrationDate, tt.wantUpdated)
				}
			})
		}
	}
}

func TestParseRDAPResponseMalformedFields(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		check func(*testing.T, RDAPInfo)
	}{
		{
			name: "domain",
			raw: `{
				"objectClassName":"domain", "handle":null, "ldhName":123,
				"status":[null,"active",42],
				"entities":[null,{"roles":[null,"registrar"],"vcardArray":["vcard",[["fn",{},"text",null],["fn",{},"text","Example Registrar"]]],"publicIds":[]}],
				"nameservers":[null,{"ldhName":null},{"ldhName":"ns.example.com"}],
				"secureDNS":{"dsData":[{"keytag":"invalid","algorithm":8,"digestType":2,"digest":"ABCD"}]}
			}`,
			check: func(t *testing.T, parsed RDAPInfo) {
				data, ok := parsed.Data.(DomainInfo)
				if !ok {
					t.Fatalf("data type = %T, want DomainInfo", parsed.Data)
				}
				if data.Registrar != "Example Registrar" || data.RegistrarIANAID != "" || data.DNSSec != "unsigned" {
					t.Fatalf("unexpected domain data: %+v", data)
				}
				if len(data.Status) != 1 || data.Status[0] != "active" || len(data.NameServers) != 1 || data.NameServers[0] != "ns.example.com" {
					t.Fatalf("valid domain fields were lost: %+v", data)
				}
			},
		},
		{
			name: "ip network",
			raw: `{
				"objectClassName":"ip network", "handle":null, "startAddress":"192.0.2.0", "endAddress":123,
				"name":null, "cidr0_cidrs":[null,{"v4prefix":"192.0.2.0","length":null},{"v4prefix":"192.0.2.0","length":24}],
				"type":42, "country":null, "status":[null,"active",false]
			}`,
			check: func(t *testing.T, parsed RDAPInfo) {
				data, ok := parsed.Data.(IPInfo)
				if !ok {
					t.Fatalf("data type = %T, want IPInfo", parsed.Data)
				}
				if data.Range != "192.0.2.0" || data.CIDR != "192.0.2.0/24" || data.Networktype != "Unknown" {
					t.Fatalf("unexpected IP data: %+v", data)
				}
				if len(data.IPStatus) != 1 || data.IPStatus[0] != "active" {
					t.Fatalf("valid IP status was lost: %+v", data)
				}
			},
		},
		{
			name: "autnum",
			raw:  `{"objectClassName":"autnum","handle":null,"name":42,"status":[null,"active",{}]}`,
			check: func(t *testing.T, parsed RDAPInfo) {
				data, ok := parsed.Data.(ASNInfo)
				if !ok {
					t.Fatalf("data type = %T, want ASNInfo", parsed.Data)
				}
				if len(data.ASStatus) != 1 || data.ASStatus[0] != "active" {
					t.Fatalf("valid ASN status was lost: %+v", data)
				}
			},
		},
		{
			name: "unsupported object class",
			raw:  `{"objectClassName":"entity","handle":null}`,
			check: func(t *testing.T, parsed RDAPInfo) {
				if parsed.Data != nil {
					t.Fatalf("unsupported class data = %T, want nil", parsed.Data)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(tt.raw), &raw); err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRDAPResponse(raw)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, parsed)
		})
	}
}

func TestParseRDAPResponseValidFields(t *testing.T) {
	t.Run("domain", func(t *testing.T) {
		var raw map[string]interface{}
		const response = `{
			"objectClassName":"domain", "handle":"D-123", "ldhName":"example.com",
			"status":["active"],
			"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Example Registrar"]]],"publicIds":[{"identifier":"1234"}]}],
			"nameservers":[{"ldhName":"ns.example.com"}],
			"secureDNS":{"dsData":[{"keytag":123,"algorithm":8,"digestType":2,"digest":"ABCD"}]}
		}`
		if err := json.Unmarshal([]byte(response), &raw); err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRDAPResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		data, ok := parsed.Data.(DomainInfo)
		if !ok {
			t.Fatalf("data type = %T, want DomainInfo", parsed.Data)
		}
		if data.ID != "D-123" || data.Domain != "example.com" || data.Registrar != "Example Registrar" || data.RegistrarIANAID != "1234" || data.DNSSec != "signedDelegation" || data.DNSSecDSData != "123 8 2 ABCD" {
			t.Fatalf("unexpected domain data: %+v", data)
		}
		if len(data.Status) != 1 || data.Status[0] != "active" || len(data.NameServers) != 1 || data.NameServers[0] != "ns.example.com" {
			t.Fatalf("unexpected domain lists: %+v", data)
		}
	})

	t.Run("ip network", func(t *testing.T) {
		var raw map[string]interface{}
		const response = `{
			"objectClassName":"ip network", "handle":"NET-192-0-2-0", "startAddress":"192.0.2.0", "endAddress":"192.0.2.255",
			"name":"EXAMPLE-NET", "cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}],
			"type":"DIRECT ALLOCATION", "country":"US", "status":["active"]
		}`
		if err := json.Unmarshal([]byte(response), &raw); err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRDAPResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		data, ok := parsed.Data.(IPInfo)
		if !ok {
			t.Fatalf("data type = %T, want IPInfo", parsed.Data)
		}
		if data.IP != "NET-192-0-2-0" || data.Range != "192.0.2.0 - 192.0.2.255" || data.NetName != "EXAMPLE-NET" || data.CIDR != "192.0.2.0/24" || data.Networktype != "DIRECT ALLOCATION" || data.Country != "US" {
			t.Fatalf("unexpected IP data: %+v", data)
		}
		if len(data.IPStatus) != 1 || data.IPStatus[0] != "active" {
			t.Fatalf("unexpected IP status: %+v", data)
		}
	})
}
