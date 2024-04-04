package whois

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sync"
)

//go:embed config/servers.json
var embeddedServerFiles embed.FS

type ServerConfig struct {
	Rewrite map[string]string `json:"rewrite"`
	Servers map[string]string `json:"servers"`
}

type serverMap struct {
	sync.RWMutex
	config *ServerConfig
}

// NewServerMap creates a new serverMap instance
func NewServerMap() *serverMap {
	return &serverMap{
		// 初始化ServerConfig结构体，其中包括Servers和Rewrite的map
		config: &ServerConfig{
			Rewrite: make(map[string]string),
			Servers: make(map[string]string),
		},
	}
}

// GetWhoisServer returns the WHOIS server for the given TLD
// 获取whois服务器
func (sm *serverMap) GetWhoisServer(tld string) (string, bool) {
	sm.RLock()
	defer sm.RUnlock()
	server, exists := sm.config.Servers[tld]
	return server, exists
}

// 设置whois服务器
func (sm *serverMap) SetWhoisServer(tld string, server string) (string, bool) {
	// 写入map中，需要先获取写锁
	sm.Lock()
	defer sm.Unlock()
	// 再次检查是否存在，以避免多线程查询后重复写入
	if _, exists := sm.config.Servers[tld]; !exists {
		sm.config.Servers[tld] = server
	}
	return server, true
}

// 获取重写服务
func (sm *serverMap) GetRewriteServer(server string) (string, bool) {
	sm.RLock()
	defer sm.RUnlock()
	server, exists := sm.config.Rewrite[server]
	return server, exists
}

// LoadFromFile loads the server map from a JSON file
func (sm *serverMap) LoadFromFile(filename string) error {
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
		data, err = fs.ReadFile(embeddedServerFiles, "config/servers.json")
		fmt.Println("从默认路径读取servers.json")
		if err != nil {
			return err
		}
	}

	sm.Lock()
	defer sm.Unlock()

	// 使用新的ServerConfig结构体来解析数据
	sm.config = &ServerConfig{}
	return json.Unmarshal(data, sm.config)
}
