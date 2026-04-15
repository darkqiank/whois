package server

import (
	"encoding/json"
	"testing"

	parser "github.com/darkqiank/whois/parsers"
)

func TestConvertRDAPToIPTipResponse(t *testing.T) {
	rawJSON := `{
		"objectClassName": "ip network",
		"startAddress": "216.250.248.0",
		"endAddress": "216.250.255.255",
		"cidr0_cidrs": [{"v4prefix": "216.250.248.0", "length": 21}],
		"ipVersion": "v4",
		"name": "MHSL-5-216-250-248-0-21",
		"handle": "NET-216-250-248-0-1",
		"parentHandle": "NET-216-0-0-0-0",
		"type": "DIRECT ALLOCATION",
		"status": ["active"],
		"links": [
			{"rel": "self", "href": "https://rdap.arin.net/registry/ip/216.250.248.0"}
		],
		"events": [
			{"eventAction": "last changed", "eventDate": "2020-07-30T18:02:08-04:00"},
			{"eventAction": "registration", "eventDate": "2020-07-30T16:23:06-04:00"}
		],
		"entities": [
			{
				"handle": "MHSL-5",
				"roles": ["registrant"],
				"vcardArray": ["vcard", [
					["fn", {}, "text", "Majestic Hosting Solutions, LLC"],
					["adr", {"label": "1900 Surveyor Blvd Suite 100\nCarrollton\nTX\n75006\nUnited States"}, "text", ["", "", "", "", "", "", ""]]
				]],
				"events": [
					{"eventAction": "last changed", "eventDate": "2024-11-25T11:09:46-05:00"},
					{"eventAction": "registration", "eventDate": "2018-08-01T11:40:32-04:00"}
				],
				"entities": [
					{
						"handle": "ABUSE7610-ARIN",
						"roles": ["abuse"],
						"vcardArray": ["vcard", [
							["fn", {}, "text", "Abuse"],
							["email", {}, "text", "abuse@spinservers.com"],
							["tel", {}, "text", "+1-833-774-6778"]
						]]
					},
					{
						"handle": "TECHN1659-ARIN",
						"roles": ["technical"],
						"vcardArray": ["vcard", [
							["fn", {}, "text", "Technical"],
							["email", {}, "text", "technical@spinservers.com"],
							["tel", {}, "text", "+1-833-774-6778"]
						]]
					}
				]
			}
		]
	}`

	raw := map[string]interface{}{}
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		t.Fatalf("unmarshal raw rdap json: %v", err)
	}

	rdap := parser.RDAPInfo{
		Type: "ip network",
		Raw:  raw,
	}

	result, err := convertRDAPToIPTipResponse(rdap)
	if err != nil {
		t.Fatalf("convert rdap to ip tip response: %v", err)
	}

	if result.BasicInfo.IPRange != "216.250.248.0 - 216.250.255.255" {
		t.Fatalf("unexpected ip range: %s", result.BasicInfo.IPRange)
	}
	if result.BasicInfo.CIDR != "216.250.248.0/21" {
		t.Fatalf("unexpected cidr: %s", result.BasicInfo.CIDR)
	}
	if result.BasicInfo.LinkDetail != "https://rdap.arin.net/registry/ip/216.250.248.0" {
		t.Fatalf("unexpected link detail: %s", result.BasicInfo.LinkDetail)
	}
	if result.EventDateInfo.SegmentLastChanged != "2020-07-30T18:02:08-04:00" {
		t.Fatalf("unexpected segment last changed: %s", result.EventDateInfo.SegmentLastChanged)
	}
	if result.EventDateInfo.SegmentRegistration != "2020-07-30T16:23:06-04:00" {
		t.Fatalf("unexpected segment registration: %s", result.EventDateInfo.SegmentRegistration)
	}
	if result.EventDateInfo.InstitutionLastChanged != "2024-11-25T11:09:46-05:00" {
		t.Fatalf("unexpected institution last changed: %s", result.EventDateInfo.InstitutionLastChanged)
	}
	if result.EventDateInfo.InstitutionRegistration != "2018-08-01T11:40:32-04:00" {
		t.Fatalf("unexpected institution registration: %s", result.EventDateInfo.InstitutionRegistration)
	}
	if result.InstitutionInfo.Name != "Majestic Hosting Solutions, LLC" {
		t.Fatalf("unexpected institution name: %s", result.InstitutionInfo.Name)
	}
	if result.AbuseInfo.Email != "abuse@spinservers.com" {
		t.Fatalf("unexpected abuse email: %s", result.AbuseInfo.Email)
	}
	if result.TechnicalInfo.Email != "technical@spinservers.com" {
		t.Fatalf("unexpected technical email: %s", result.TechnicalInfo.Email)
	}
}
