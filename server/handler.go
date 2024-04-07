package server

import (
	"fmt"
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

	// 获取Whois数据
	whois, err := GetWhois(domain, disableReferral)
	if err != nil {
		return sendJSONResponse(c, fiber.StatusInternalServerError, whois, err)
	}

	// 检查是否获得了空数据
	if whois.Domain == nil { // 假设WhoisInfo有一个Domain字段
		return sendJSONResponse(c, fiber.StatusNotFound, nil, fmt.Errorf("WHOIS DATA EMPTY"))
	}

	// 成功响应
	return sendJSONResponse(c, fiber.StatusOK, whois, nil)
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
