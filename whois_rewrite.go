package whois

var whoisRewriteMap = map[string]string{
	"whois.godaddy":       "whois.godaddy.com",
	"porkbun.com":         "whois.porkbun.com",
	"www.cronon.net":      "whois.cronon.net",
	"squarespace.domains": "whois.squarespace.domains",
	"rdap.namecheap.com":  "whois.namecheap.com",
	"corenic.org":         "whois.corenic.org",
	"website.ws":          "whois.website.ws",
	"register4less.com":   "whois.register4less.com",
	// 添加更多TLD到Whois server的映射
}
