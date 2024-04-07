package parsers

import "time"

// WhoisInfo storing domain whois info
type WhoisInfo struct {
	Domain         *Domain  `json:"domain,omitempty"`
	Registrar      *Contact `json:"registrar,omitempty"`
	Registrant     *Contact `json:"registrant,omitempty"`
	Administrative *Contact `json:"administrative,omitempty"`
	Technical      *Contact `json:"technical,omitempty"`
	Billing        *Contact `json:"billing,omitempty"`
}

// Domain storing domain name info
type Domain struct {
	ID                   string     `json:"id,omitempty"`
	Domain               string     `json:"domain,omitempty"`
	Punycode             string     `json:"punycode,omitempty"`
	Name                 string     `json:"name,omitempty"`
	Extension            string     `json:"extension,omitempty"`
	WhoisServer          string     `json:"whois_server,omitempty"`
	Status               []string   `json:"status,omitempty"`
	NameServers          []string   `json:"name_servers,omitempty"`
	DNSSec               bool       `json:"dnssec,omitempty"`
	CreatedDate          string     `json:"created_date,omitempty"`
	CreatedDateInTime    *time.Time `json:"created_date_in_time,omitempty"`
	UpdatedDate          string     `json:"updated_date,omitempty"`
	UpdatedDateInTime    *time.Time `json:"updated_date_in_time,omitempty"`
	ExpirationDate       string     `json:"expiration_date,omitempty"`
	ExpirationDateInTime *time.Time `json:"expiration_date_in_time,omitempty"`
}

// Contact storing domain contact info
type Contact struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Street       string `json:"street,omitempty"`
	City         string `json:"city,omitempty"`
	Province     string `json:"province,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Country      string `json:"country,omitempty"`
	Phone        string `json:"phone,omitempty"`
	PhoneExt     string `json:"phone_ext,omitempty"`
	Fax          string `json:"fax,omitempty"`
	FaxExt       string `json:"fax_ext,omitempty"`
	Email        string `json:"email,omitempty"`
	ReferralURL  string `json:"referral_url,omitempty"`
}

// RDAPInfo 下面全是rdap的返回结构
type RDAPInfo struct {
	Type string `json:"type,omitempty"`
	Data any    `json:"info,omitempty"`
}

// DomainInfo represents the information about a domain.
type DomainInfo struct {
	ID                   string     `json:"id,omitempty"`
	Domain               string     `json:"domain"`         // DomainName is the name of the domain.
	Status               []string   `json:"status"`         // DomainStatus is the status of the domain.
	NameServers          []string   `json:"name_servers"`   // NameServer is the name server of the domain.
	DNSSec               string     `json:"dnssec"`         // DNSSec is the DNSSEC of the domain.
	DNSSecDSData         string     `json:"dnssec_ds_data"` // DNSSecDSData is the DNSSEC DS Data of the domain.
	CreatedDate          string     `json:"created_date"`   // CreationDate is the creation date of the domain.
	CreatedDateInTime    *time.Time `json:"created_date_in_time,omitempty"`
	UpdatedDate          string     `json:"updated_date"` // UpdatedDate is the updated date of the domain.
	UpdatedDateInTime    *time.Time `json:"updated_date_in_time,omitempty"`
	ExpirationDate       string     `json:"expiration_date"` // RegistryExpiryDate is the expiry date of the domain.
	ExpirationDateInTime *time.Time `json:"expiration_date_in_time,omitempty"`
	Registrar            string     `json:"registrar"`              // Registrar is the registrar of the domain.
	RegistrarIANAID      string     `json:"registrar_iana_id"`      // RegistrarIANAID is the IANA ID of the registrar.
	LastUpdateOfRDAPDB   string     `json:"last_updated_of_rdapdb"` // LastUpdateOfRDAPDB is the last update of the database.
}

// ASNInfo represents the information about an Autonomous System Number (ASN).
type ASNInfo struct {
	ASN          string   `json:"AS Number"`     // ASN is the Autonomous System Number.
	ASName       string   `json:"Network Name"`  // ASName is the name of the network.
	ASStatus     []string `json:"Status"`        // ASStatus is the status of the ASN.
	CreationDate string   `json:"Creation Date"` // CreationDate is the creation date of the ASN.
	UpdatedDate  string   `json:"Updated Date"`  // UpdatedDate is the updated date of the ASN.
}

// IPInfo represents the information about an IP network.
type IPInfo struct {
	IP           string   `json:"IP Network"`    // IP is the IP network.
	Range        string   `json:"Address Range"` // Range is the address range of the IP network.
	NetName      string   `json:"Network Name"`  // NetName is the name of the network.
	CIDR         string   `json:"CIDR"`          // CIDR is the CIDR of the IP network.
	Networktype  string   `json:"Network Type"`  // Networktype is the type of the network.
	Country      string   `json:"Country"`       // Country is the country of the IP network.
	IPStatus     []string `json:"Status"`        // IPStatus is the status of the IP network.
	CreationDate string   `json:"Creation Date"` // CreationDate is the creation date of the IP network.
	UpdatedDate  string   `json:"Updated Date"`  // UpdatedDate is the updated date of the IP network.
}
