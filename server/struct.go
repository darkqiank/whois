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
