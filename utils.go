package whois

import (
	"net"
	"regexp"
	"strings"
)

// asnPrefix is asn prefix string
const asnPrefix = "AS"

// 预编译正则表达式并重用，以提高性能。
var asnRegex = regexp.MustCompile(`^(as|asn)?\d+$`)

// IsASN function is used to check if the given resource is an Autonomous System Number (ASN).
func IsASN(resource string) bool {
	s := strings.ToLower(resource)
	return asnRegex.MatchString(s)
}

// getExtension returns extension of domain
func getExtension(domain string) string {
	ext := domain

	if net.ParseIP(domain) == nil {
		domains := strings.Split(domain, ".")
		ext = domains[len(domains)-1]
	}

	if strings.Contains(ext, "/") {
		ext = strings.Split(ext, "/")[0]
	}

	return ext
}

// extractHostname 从可能的URL中提取主机名
func extractHostname(url string) string {
	// 转小写
	url = strings.ToLower(url)
	// 移除协议头
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "whois://")
	url = strings.TrimPrefix(url, "rwhois://")

	// 截取到第一个斜杠（如果有）之前的部分
	if slashIndex := strings.Index(url, "/"); slashIndex != -1 {
		url = url[:slashIndex]
	}

	// 检查是否以www或www.whois开头，如果是，则替换成whois
	if strings.HasPrefix(url, "www.whois.") {
		url = "whois." + url[10:] // 移除www.并保留whois.以及之后的部分
	} else if strings.HasPrefix(url, "www.") {
		url = "whois." + url[4:] // 移除www.并加上whois.
	}

	return url
}
