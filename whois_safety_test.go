package whois

import "testing"

func TestWhoisWithoutInitializedServerMap(t *testing.T) {
	original := serverMapInstance
	serverMapInstance = nil
	defer func() { serverMapInstance = original }()

	client := NewClient()
	if _, err := client.Whois("example.com"); err == nil {
		t.Fatal("query without a server map should return an error")
	}

	client.SetDialer(fakeWhoisDialer{
		responses: map[string]string{
			"primary.test:43": "Domain Name: EXAMPLE.COM\n",
		},
	})
	client.SetDisableReferral(true)
	client.SetDisableStats(true)
	response, err := client.Whois("example.com", "primary.test")
	if err != nil || response != "Domain Name: EXAMPLE.COM" {
		t.Fatalf("query with explicit server = (%q, %v)", response, err)
	}
}
