package whois

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
)

//go:embed config/rdap.json
var embeddedRADPFiles embed.FS

// RDAPBootstrap 定义一个结构体来映射原始JSON数据的最外层
type RDAPBootstrap struct {
	IPv4 RDAPData `json:"ipv4"`
	IPv6 RDAPData `json:"ipv6"`
	ASN  RDAPData `json:"asn"`
	DNS  RDAPData `json:"dns"`
}

// RDAPData 结构体用于映射IPv4、IPv6、dns、asn的数据
type RDAPData struct {
	Description string       `json:"description"`
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
	Version     string       `json:"version"`
}

type RdapConfig struct {
	IP        map[string]string `json:"ip"`
	ASN       map[string]string `json:"asn"`
	TLD       map[string]string `json:"tld"`
	asnRanges []ASNRange
	ipRanger  cidranger.Ranger
}

// ASNRange 表示ASN范围和对应的URL
type ASNRange struct {
	Start int
	End   int
	URL   string
}

type RdapMap struct {
	sync.RWMutex
	config *RdapConfig
}

// NewRdapMap creates a new rdapMap instance
func NewRdapMap() *RdapMap {
	return &RdapMap{
		config: &RdapConfig{
			IP:        make(map[string]string),
			ASN:       make(map[string]string),
			TLD:       make(map[string]string),
			asnRanges: make([]ASNRange, 0),
			ipRanger:  cidranger.NewPCTrieRanger(), // 假设使用PCTrie实现
		},
	}
}

func (rm *RdapMap) GetRdapServer(query string) (string, string, bool) {
	rm.RLock()
	defer rm.RUnlock()

	ip := net.ParseIP(query)
	if ip != nil {
		url, exists := rm.findIPServer(ip)
		println("ip")
		return "ip", url, exists
	} else if IsASN(query) {
		println("asn")
		url, exists := rm.findASNServer(query)
		return "asn", url, exists
	} else {
		println("domain")
		url, exists := rm.findTLDServer(query)
		return "domain", url, exists
	}
}

func (rm *RdapMap) findIPServer(ip net.IP) (string, bool) {
	entries, err := rm.config.ipRanger.ContainingNetworks(ip)
	if err == nil && len(entries) > 0 {
		entry := entries[0].Network()
		cidr := entry.String()
		server, exists := rm.config.IP[cidr]
		if exists {
			url := fmt.Sprintf("%s%s/%s", server, "ip", ip.String())
			return url, exists
		}
	}
	return "", false
}

func (rm *RdapMap) findASNServer(query string) (string, bool) {
	query = strings.ToLower(query)
	asnStr := strings.TrimPrefix(query, "asn")
	if asnStr == query {
		asnStr = strings.TrimPrefix(query, "as")
	}
	asnInt, err := strconv.Atoi(asnStr)
	if err != nil {
		return "", false
	}
	asnRange, exists := rm.findASNRange(asnInt)
	if exists {
		url := fmt.Sprintf("%s%s/%s", asnRange.URL, "autnum", asnStr)
		return url, exists
	}
	return "", false
}

func (rm *RdapMap) findASNRange(asn int) (ASNRange, bool) {
	index := sort.Search(len(rm.config.asnRanges), func(i int) bool {
		return rm.config.asnRanges[i].End >= asn
	})
	if index < len(rm.config.asnRanges) && rm.config.asnRanges[index].Start <= asn {
		return rm.config.asnRanges[index], true
	}
	return ASNRange{}, false
}

// 通过ASN范围字符串创建ASNRange实例
func NewASNRange(rangeStr, url string) (ASNRange, error) {
	parts := strings.Split(rangeStr, "-")
	var start, end int
	var err error

	start, err = strconv.Atoi(parts[0])
	if err != nil {
		return ASNRange{}, err
	}
	if len(parts) == 2 {
		end, err = strconv.Atoi(parts[1])
		if err != nil {
			return ASNRange{}, err
		}
	} else {
		end = start
	}
	return ASNRange{Start: start, End: end, URL: url}, nil
}

func (rm *RdapMap) findTLDServer(query string) (string, bool) {
	ext := getExtension(query)
	rm.RLock()
	defer rm.RUnlock()
	server, exists := rm.config.TLD[ext]
	if exists {
		url := fmt.Sprintf("%s%s/%s", server, "domain", query)
		return url, exists
	}
	return "", false
}

// LoadFromFile loads the server map from a JSON file
func (rm *RdapMap) LoadFromFile(filename string) error {
	var data []byte
	var err error

	if filename != "" {
		// 使用os.ReadFile读取文件
		data, err = os.ReadFile(filename)
		fmt.Printf("从指定路径 %s 读取配置", filename)
		if err != nil {
			return err
		}
	} else {
		// 从嵌入的文件系统读取
		data, err = fs.ReadFile(embeddedRADPFiles, "config/rdap.json")
		fmt.Println("从默认路径读取rdap.json")
		if err != nil {
			return err
		}
	}
	var bootstrap RDAPBootstrap
	err = json.Unmarshal(data, &bootstrap)
	if err != nil {
		return err
	}

	return rm.LoadBootstrap(bootstrap)
}

func (rm *RdapMap) LoadFromIANA() error {
	var bootstrap RDAPBootstrap
	// 创建一个http.Client实例并设置超时
	client := &http.Client{
		Timeout: 20 * time.Second, // 例如，10秒超时
	}
	baseIANAURL := "https://data.iana.org/rdap/"
	rdapTypes := []string{"dns", "ipv4", "ipv6", "asn"}
	fmt.Printf("从IANA官方 %s 读取配置\n", baseIANAURL)
	for _, rdapType := range rdapTypes {
		url := fmt.Sprintf("%s%s%s", baseIANAURL, rdapType, ".json")
		fmt.Printf("请求 %s \n", url)
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("请求 %s 时出错: %v\n", url, err)
			return err
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {

			}
		}(resp.Body)
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("请求 %s 返回非200状态码: %d\n", url, resp.StatusCode)
			return fmt.Errorf("status code error: %d %s", resp.StatusCode, resp.Status)
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("读取 %s 响应时出错: %v\n", url, err)
			return err
		}
		if err != nil {
			fmt.Printf("读取 %s 响应时出错: %v\n", url, err)
			return err
		}

		// 根据URL决定如何更新RDAPBootstrap实例
		switch rdapType {
		case "dns":
			err = json.Unmarshal(data, &bootstrap.DNS)
		case "ipv4":
			err = json.Unmarshal(data, &bootstrap.IPv4)
		case "ipv6":
			err = json.Unmarshal(data, &bootstrap.IPv6)
		case "asn":
			err = json.Unmarshal(data, &bootstrap.ASN)
		}
		if err != nil {
			fmt.Printf("解析 %s 数据时出错: %v\n", url, err)
			return err
		}
	}
	return rm.LoadBootstrap(bootstrap)
}

// LoadBootstrap loads the server map from Bootstrap
func (rm *RdapMap) LoadBootstrap(bootstrap RDAPBootstrap) error {
	rm.Lock()
	defer rm.Unlock()

	// 合并IPv4和IPv6到IP map中
	mergeServices(bootstrap.IPv4.Services, rm.config.IP)
	mergeServices(bootstrap.IPv6.Services, rm.config.IP)

	// ASN 和 DNS 转换
	mergeServices(bootstrap.ASN.Services, rm.config.ASN)
	mergeServices(bootstrap.DNS.Services, rm.config.TLD)

	// 添加ip Ranger
	for cidr := range rm.config.IP {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Printf("解析CIDR '%s' 出错: %v\n", cidr, err)
			continue // 发生错误时跳过当前项
		}
		if err := rm.config.ipRanger.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			fmt.Printf("添加CIDR到ranger时出错: %v\n", err)
			continue // 发生错误时跳过当前项
		}
	}

	// 添加ASN Ranger
	var asnRanges []ASNRange
	for rangeStr, url := range rm.config.ASN {
		asnRange, err := NewASNRange(rangeStr, url)
		if err != nil {
			fmt.Println("Error parsing range:", rangeStr, url, err)
			continue
		}
		asnRanges = append(asnRanges, asnRange)
	}
	// 按Start排序，以便进行二分查找
	sort.Slice(asnRanges, func(i, j int) bool {
		return asnRanges[i].Start < asnRanges[j].Start
	})
	rm.config.asnRanges = asnRanges

	// 添加asn Ranger

	return nil
}

// mergeServices 将services中的数据按照特定的规则合并到给定的map中
func mergeServices(services [][][]string, targetMap map[string]string) {
	for _, service := range services {
		if len(service[1]) > 0 {
			value := service[1][0] // 使用第二个子数组的第一个元素作为值
			for _, key := range service[0] {
				targetMap[key] = value
			}
		}
	}
}
