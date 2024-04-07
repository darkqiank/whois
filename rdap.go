package whois

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var (
	rdapMapInstance *RdapMap
	onceRDAP        sync.Once
)

const (
	defaultRDAPTimeout = 10 * time.Second
)

// RDAPClient is RDAP client
type RDAPClient struct {
	httpClient      *http.Client
	timeout         time.Duration
	disableReferral bool
	rdapMap         *RdapMap
}

// DefaultRDAPClient is default RDAP client
var DefaultRDAPClient = NewRDAPClient()

// RDAP do the RDAP query and returns RDAP information
func RDAP(domain string) (result map[string]interface{}, err error) {
	return DefaultRDAPClient.RDAP(domain)
}

// NewRDAPClient returns new RDAP client
func NewRDAPClient() *RDAPClient {
	return &RDAPClient{
		httpClient: &http.Client{
			Timeout: defaultRDAPTimeout,
		},
		timeout:         defaultRDAPTimeout,
		rdapMap:         rdapMapInstance,
		disableReferral: true,
	}
}

// SetDisableReferral if set to true, will not query the referral server.
func (c *RDAPClient) SetDisableReferral(disabled bool) *RDAPClient {
	c.disableReferral = disabled
	return c
}

func (c *RDAPClient) RDAP(q string) (map[string]interface{}, error) {
	if q == "" {
		return nil, ErrDomainEmpty
	}
	rtype, url, exists := rdapMapInstance.GetRdapServer(q)
	fmt.Println(url)
	if exists {
		res, err := c.rdapRawQuery(url)
		if res != nil && err == nil {
			if !c.disableReferral && rtype == "domain" {
				// 配置了不跳过refer
				url, exists = GetRelURL(res)
				if exists {
					res, err = c.rdapRawQuery(url)
				}
			}
			return res, err
		} else {
			return nil, fmt.Errorf("rdap: query rdap server (%s) failed: (%s)", url, err)
		}
	}
	return nil, fmt.Errorf("rdap: query rdap server (%s) failed", url)
}

// 查询rdap
func (c *RDAPClient) rdapRawQuery(url string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("resource not found")
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, err
	}
	// fmt.Println(buf.String())
	//尝试解析json
	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	if err != nil {
		return nil, fmt.Errorf("rdap: return data (%s) not json: (%s)", url, err)
	}
	return result, nil
}

func GetRelURL(res map[string]interface{}) (string, bool) {
	if links, ok := res["links"]; ok {
		for _, link := range links.([]interface{}) {
			linkData := link.(map[string]interface{})
			rel, ok1 := linkData["rel"].(string)
			value, ok2 := linkData["value"].(string)
			if ok1 && ok2 {
				if rel == "related" {
					return value, true
				}
			}
		}
	}
	return "", false
}

// InitRDAP sync.Once的作用是确保在多线程环境下一个操作只被执行一次
func InitRDAP(configFile string) {
	onceRDAP.Do(func() {
		var err error
		rdapMapInstance = NewRdapMap()
		if configFile == "online" {
			err = rdapMapInstance.LoadFromIANA()
			if err != nil {
				err = rdapMapInstance.LoadFromFile(configFile)
			}
		} else {
			err = rdapMapInstance.LoadFromFile(configFile)
		}
		if err != nil {
			// 统一的错误处理
			// 可以选择记录日志、发送报警、panic等
			panic(err)
		}
	})
}
