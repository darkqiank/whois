package server

// SingleBody defines the JSON body for
// getting Whois data of a single domain
type SingleBody struct {
	Domain string
}

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// TipResponse 用于 tip=1 参数时返回的扁平化格式
type TipResponse struct {
	ContactEmail         string   `json:"contactEmail"`
	ContactPhone         string   `json:"contactPhone"`
	DNSNameServer        []string `json:"dnsNameServer"`
	DomainName           string   `json:"domainName"`
	DomainStatus         []string `json:"domainStatus"`
	ExpirationTime       string   `json:"expirationTime"`
	Registrant           string   `json:"registrant"`
	Registrar            string   `json:"registrar"`
	RegistrarWHOISServer string   `json:"registrarWHOISServer"`
	RegistrationTime     string   `json:"registrationTime"`
	UpdatedDate          string   `json:"updatedDate"`
}
