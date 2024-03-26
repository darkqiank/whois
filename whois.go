/*
 * Copyright 2014-2023 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for domain and ip whois information query
 * https://www.likexian.com/
 */

package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultWhoisServer is iana whois server
	defaultWhoisServer = "whois.iana.org"
	// defaultWhoisPort is default whois port
	defaultWhoisPort = "43"
	// defaultElapsedTimeout
	defaultElapsedTimeout = 15 * time.Second
	// defaultTimeout is query default timeout
	defaultTimeout = 5 * time.Second
	// asnPrefix is asn prefix string
	asnPrefix = "AS"
)

// DefaultClient is default whois client
var DefaultClient = NewClient()

// Client is whois client
type Client struct {
	dialer          net.Dialer
	timeout         time.Duration
	elapsed         time.Duration
	disableStats    bool
	disableReferral bool
}

// Version returns package version
func Version() string {
	return "1.15.0"
}

// Author returns package author
func Author() string {
	return "[Li Kexian](https://www.likexian.com/)"
}

// License returns package license
func License() string {
	return "Licensed under the Apache License 2.0"
}

// Whois do the whois query and returns whois information
func Whois(domain string, servers ...string) (result string, err error) {
	return DefaultClient.Whois(domain, servers...)
}

// NewClient returns new whois client
func NewClient() *Client {
	return &Client{
		dialer: net.Dialer{
			Timeout: defaultTimeout,
		},
		timeout: defaultElapsedTimeout,
	}
}

// SetDialer set query net dialer
func (c *Client) SetDialer(dialer net.Dialer) *Client {
	c.dialer = dialer
	return c
}

// SetTimeout set query timeout
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.timeout = timeout
	return c
}

// SetDisableStats set disable stats
func (c *Client) SetDisableStats(disabled bool) *Client {
	c.disableStats = disabled
	return c
}

// SetDisableReferral if set to true, will not query the referral server.
func (c *Client) SetDisableReferral(disabled bool) *Client {
	c.disableReferral = disabled
	return c
}

// Whois do the whois query and returns whois information
func (c *Client) Whois(domain string, servers ...string) (result string, err error) {
	start := time.Now()
	defer func() {
		result = strings.TrimSpace(result)
		if result != "" && !c.disableStats {
			result = fmt.Sprintf("%s\n\n%% Query time: %d msec\n%% WHEN: %s\n",
				result, time.Since(start).Milliseconds(), start.Format("Mon Jan 02 15:04:05 MST 2006"),
			)
		}
	}()

	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		return "", ErrDomainEmpty
	}

	isASN := IsASN(domain)
	if isASN {
		if !strings.HasPrefix(strings.ToUpper(domain), asnPrefix) {
			domain = asnPrefix + domain
		}
	}

	if !strings.Contains(domain, ".") && !strings.Contains(domain, ":") && !isASN {
		return c.rawQuery(domain, defaultWhoisServer, defaultWhoisPort)
	}

	var server, port string
	if len(servers) > 0 && servers[0] != "" {
		server = strings.ToLower(servers[0])
		port = defaultWhoisPort
	} else {
		ext := getExtension(domain)
		if v, ok := tldToWhoisServer[ext]; ok {
			// 如果tld存在于map中，更新server变量为map中对应的值
			server = v
			port = defaultWhoisPort
		} else {
			result, err := c.rawQuery(ext, defaultWhoisServer, defaultWhoisPort)
			if err != nil {
				return "", fmt.Errorf("whois: query for whois server failed: %w", err)
			}
			server, port = getServer(result)
			if server == "" {
				return "", fmt.Errorf("%w: %s", ErrWhoisServerNotFound, domain)
			}
		}
	}

	result, err = c.rawQuery(domain, server, port)
	if err != nil {
		return
	}

	if c.disableReferral {
		return
	}

	refServer, refPort := getServer(result)
	if refServer == "" || refServer == server {
		return
	}

	data, err := c.rawQuery(domain, refServer, refPort)
	if err == nil {
		result += data
	}

	return
}

// rawQuery do raw query to the server
func (c *Client) rawQuery(domain, server, port string) (string, error) {
	c.elapsed = 0
	// start := time.Now()
	if server == "whois.arin.net" {
		if IsASN(domain) {
			domain = "a + " + domain
		} else {
			domain = "n + " + domain
		}
	}

	if value, ok := whoisRewriteMap[server]; ok {
		// 如果键存在于map中，更新server变量为map中对应的值
		server = value
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	conn, err := c.dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, port))

	if err != nil {
		return "", fmt.Errorf("whois: connect to whois server (%s) failed: %w", server, err)
	}

	defer conn.Close()
	// c.elapsed = time.Since(start)

	// _ = conn.SetWriteDeadline(time.Now().Add(c.timeout - c.elapsed))
	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", fmt.Errorf("whois: send to whois server (%s) failed: %w", server, err)
	}

	// c.elapsed = time.Since(start)

	// _ = conn.SetReadDeadline(time.Now().Add(c.timeout - c.elapsed))
	buffer, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("whois: read from whois server (%s) failed: %w", server, err)
	}

	// c.elapsed = time.Since(start)

	return string(buffer), nil
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

// getServer returns server from whois data
func getServer(data string) (string, string) {
	tokens := []string{
		"Registrar WHOIS Server: ",
		"whois: ",
		"ReferralServer: ",
		"refer: ",
	}

	for _, token := range tokens {
		start := strings.Index(data, token)
		if start != -1 {
			start += len(token)
			end := strings.Index(data[start:], "\n")
			if end == -1 { // 如果没有找到换行符，使用整个字符串
				end = len(data[start:])
			}
			server := strings.TrimSpace(data[start : start+end])

			// 新增代码：从URL提取主机名
			server = extractHostname(server)

			port := defaultWhoisPort
			if strings.Contains(server, ":") {
				v := strings.Split(server, ":")
				server, port = v[0], v[1]
			}
			return server, port
		}
	}

	return "", ""
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

// IsASN returns if s is ASN
func IsASN(s string) bool {
	s = strings.ToUpper(s)

	s = strings.TrimPrefix(s, asnPrefix)
	_, err := strconv.Atoi(s)

	return err == nil
}
