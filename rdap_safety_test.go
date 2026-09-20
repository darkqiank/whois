package whois

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMergeServicesSkipsIncompleteEntries(t *testing.T) {
	servers := make(map[string]string)
	mergeServices([][][]string{
		nil,
		{{"192.0.2.0/24"}},
		{{"198.51.100.0/24"}, {}},
		{{"203.0.113.0/24"}, {"https://rdap.example/"}},
	}, servers)

	if len(servers) != 1 || servers["203.0.113.0/24"] != "https://rdap.example/" {
		t.Fatalf("unexpected RDAP services: %#v", servers)
	}
}

func TestRDAPRawQueryRejectsNullResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte("null"))
	}))
	defer server.Close()

	result, err := NewRDAPClient().rdapRawQuery(server.URL)
	if err == nil || result != nil {
		t.Fatalf("rdapRawQuery(null) = (%v, %v), want (nil, error)", result, err)
	}
}

func TestRDAPWithoutInitializedServerMap(t *testing.T) {
	original := rdapMapInstance
	rdapMapInstance = nil
	defer func() { rdapMapInstance = original }()

	result, err := NewRDAPClient().RDAP("example.com")
	if err == nil || result != nil {
		t.Fatalf("RDAP without a server map = (%v, %v), want (nil, error)", result, err)
	}
}
