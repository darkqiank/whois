package server

import (
	"fmt"
	"strings"

	parser "github.com/darkqiank/whois/parsers"
	"github.com/gofiber/fiber/v2"
)

// WhoisHandler 用于处理单个域名的Whois信息查询
func WhoisHandler(c *fiber.Ctx) error {
	// 确保是GET请求
	if c.Method() != fiber.MethodGet {
		return sendJSONResponse(c, fiber.StatusMethodNotAllowed, nil, fmt.Errorf("please use a GET request"))
	}

	// 从URL路径中提取域名
	domain := c.Params("*")

	// 检查路径是否为空
	if domain == "" {
		return sendJSONResponse(c, fiber.StatusBadRequest, nil, fmt.Errorf("domain not specified"))
	}

	// 初始化disableReferral为true
	disableReferral := true

	// 检查是否有ref查询参数传入
	ref := c.Query("ref")
	if ref != "" {
		disableReferral = false
	}

	// 检查是否有tip查询参数传入
	tip := c.Query("tip")

	// 获取Whois数据
	whois, err := GetWhois(domain, disableReferral)
	if err != nil {
		if tip == "1" {
			return c.Status(fiber.StatusInternalServerError).JSON(nil)
		}
		return sendJSONResponse(c, fiber.StatusInternalServerError, whois, err)
	}

	// 检查是否获得了空数据
	if whois.Domain == nil { // 假设WhoisInfo有一个Domain字段
		if tip == "1" {
			return c.Status(fiber.StatusInternalServerError).JSON(nil)
		}
		return sendJSONResponse(c, fiber.StatusNotFound, nil, fmt.Errorf("WHOIS DATA EMPTY"))
	}

	// 如果tip=1，返回TipResponse格式
	if tip == "1" {
		tipResponse, err := convertToTipResponse(whois)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(nil)
		}
		return c.Status(fiber.StatusOK).JSON(tipResponse)
	}

	// 成功响应
	return sendJSONResponse(c, fiber.StatusOK, whois, nil)
}

// convertToTipResponse 将WhoisInfo转换为TipResponse格式
func convertToTipResponse(whois parser.WhoisInfo) (*TipResponse, error) {
	if whois.Domain == nil {
		return nil, fmt.Errorf("domain info is nil")
	}

	tipResponse := &TipResponse{
		DomainName:   strings.ToUpper(whois.Domain.Domain),
		DomainStatus: whois.Domain.Status,
		DNSNameServer: func() []string {
			if whois.Domain.NameServers == nil {
				return []string{}
			}
			// 将 name servers 转换为大写
			servers := make([]string, len(whois.Domain.NameServers))
			for i, ns := range whois.Domain.NameServers {
				servers[i] = strings.ToUpper(ns)
			}
			return servers
		}(),
		RegistrarWHOISServer: whois.Domain.WhoisServer,
	}

	// 处理日期
	if whois.Domain.CreatedDateInTime != nil {
		tipResponse.RegistrationTime = whois.Domain.CreatedDateInTime.Format("2006-01-02T15:04:05Z")
	} else if whois.Domain.CreatedDate != "" {
		tipResponse.RegistrationTime = whois.Domain.CreatedDate
	}

	if whois.Domain.UpdatedDateInTime != nil {
		tipResponse.UpdatedDate = whois.Domain.UpdatedDateInTime.Format("2006-01-02T15:04:05Z")
	} else if whois.Domain.UpdatedDate != "" {
		tipResponse.UpdatedDate = whois.Domain.UpdatedDate
	}

	if whois.Domain.ExpirationDateInTime != nil {
		tipResponse.ExpirationTime = whois.Domain.ExpirationDateInTime.Format("2006-01-02T15:04:05Z")
	} else if whois.Domain.ExpirationDate != "" {
		tipResponse.ExpirationTime = whois.Domain.ExpirationDate
	}

	// 处理 Registrar 信息
	if whois.Registrar != nil {
		tipResponse.Registrar = whois.Registrar.Name
		tipResponse.ContactEmail = whois.Registrar.Email
		tipResponse.ContactPhone = whois.Registrar.Phone
	}

	// 处理 Registrant 信息
	if whois.Registrant != nil {
		tipResponse.Registrant = whois.Registrant.Organization
		if tipResponse.Registrant == "" {
			tipResponse.Registrant = whois.Registrant.Name
		}
	}

	return tipResponse, nil
}

func RdapHandler(c *fiber.Ctx) error {
	// 确保是GET请求
	if c.Method() != fiber.MethodGet {
		return sendJSONResponse(c, fiber.StatusMethodNotAllowed, nil, fmt.Errorf("please use a GET request"))
	}
	// 从URL路径中提取域名
	domain := c.Params("*")
	// 检查路径是否为空
	if domain == "" {
		return sendJSONResponse(c, fiber.StatusBadRequest, nil, fmt.Errorf("domain not specified"))
	}

	// 初始化disableReferral为true
	disableReferral := true

	// 检查是否有ref查询参数传入
	ref := c.Query("ref")
	if ref != "" {
		disableReferral = false
	}
	// 获取rdap数据
	rdap, err := GetRDAP(domain, disableReferral)
	if err != nil {
		return sendJSONResponse(c, fiber.StatusInternalServerError, rdap, err)
	}

	// 检查是否获得了空数据
	if rdap.Data == nil {
		return sendJSONResponse(c, fiber.StatusNotFound, nil, fmt.Errorf("RDAP DATA EMPTY"))
	}

	// 成功响应
	return sendJSONResponse(c, fiber.StatusOK, rdap, nil)

}

// sendJSONResponse 使用Fiber发送JSON响应
func sendJSONResponse(c *fiber.Ctx, statusCode int, data interface{}, err error) error {
	response := Response{
		Success: err == nil,
	}

	if err != nil {
		response.Error = err.Error()
	}
	response.Data = data

	// Fiber自带的JSON方法可以直接返回JSON响应
	return c.Status(statusCode).JSON(response)
}
