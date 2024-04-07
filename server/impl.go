package server

import (
	"github.com/darkqiank/whois"
	parser "github.com/darkqiank/whois/parsers"
	"golang.org/x/net/proxy"
)

// GetWhois does a WHOIS lookup for a supplied domain
func GetWhois(domain string, disableReferral bool) (parser.WhoisInfo, error) {
	c := whois.NewClient().SetDialer(proxy.FromEnvironment())
	c.SetDisableReferral(disableReferral)
	raw, err := c.Whois(domain)

	result, err1 := parser.Parse(raw)
	if err1 != nil {
		return parser.WhoisInfo{}, err1
	}

	return result, err
}

// GetRDAP does a RDAP lookup for a supplied domain
func GetRDAP(domain string, disableReferral bool) (parser.RDAPInfo, error) {
	c := whois.NewRDAPClient()
	c.SetDisableReferral(disableReferral)
	raw, err := c.RDAP(domain)

	result, err1 := parser.ParseRDAPResponse(raw)
	if err1 != nil {
		return parser.RDAPInfo{}, err1
	}

	return result, err
}
