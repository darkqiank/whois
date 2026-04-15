package server

import (
	"fmt"
	"strings"

	parser "github.com/darkqiank/whois/parsers"
)

// RDAPIPTipResponse defines the RDAP tip=1 response for IP queries.
type RDAPIPTipResponse struct {
	BasicInfo       RDAPIPTipBasicInfo       `json:"basicInfo"`
	EventDateInfo   RDAPIPTipEventDateInfo   `json:"eventDateInfo"`
	InstitutionInfo RDAPIPTipInstitutionInfo `json:"institutionInfo"`
	AbuseInfo       RDAPIPTipContactInfo     `json:"abuseInfo"`
	TechnicalInfo   RDAPIPTipContactInfo     `json:"technicalInfo"`
}

type RDAPIPTipBasicInfo struct {
	IPRange      string `json:"ipRange"`
	CIDR         string `json:"cidr"`
	IPVersion    string `json:"ipVersion"`
	Name         string `json:"name"`
	Handle       string `json:"handle"`
	ParentHandle string `json:"parentHandle"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	LinkDetail   string `json:"linkDetail"`
}

type RDAPIPTipEventDateInfo struct {
	SegmentLastChanged      string `json:"segmentLastChanged"`
	SegmentRegistration     string `json:"segmentRegistration"`
	InstitutionLastChanged  string `json:"institutionLastChanged"`
	InstitutionRegistration string `json:"institutionRegistration"`
}

type RDAPIPTipInstitutionInfo struct {
	Handle  string `json:"handle"`
	Role    string `json:"role"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

type RDAPIPTipContactInfo struct {
	Handle string `json:"handle"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Phone  string `json:"phone"`
}

func convertRDAPToIPTipResponse(rdap parser.RDAPInfo) (*RDAPIPTipResponse, error) {
	raw, ok := rdap.Raw.(map[string]interface{})
	if !ok || raw == nil {
		return nil, fmt.Errorf("rdap raw data is invalid")
	}

	tipResponse := &RDAPIPTipResponse{
		BasicInfo:     buildRDAPIPTipBasicInfo(raw),
		EventDateInfo: buildRDAPIPTipEventDateInfo(raw),
	}

	if registrant := findRDAPEntityByRole(raw, "registrant"); registrant != nil {
		tipResponse.InstitutionInfo = RDAPIPTipInstitutionInfo{
			Handle:  getMapString(registrant, "handle"),
			Role:    "registrant",
			Name:    getEntityDisplayName(registrant),
			Address: getEntityAddress(registrant),
		}
		tipResponse.EventDateInfo.InstitutionLastChanged = extractEventDate(registrant, "last changed")
		tipResponse.EventDateInfo.InstitutionRegistration = extractEventDate(registrant, "registration")
	}

	if abuse := findRDAPEntityByRole(raw, "abuse"); abuse != nil {
		tipResponse.AbuseInfo = RDAPIPTipContactInfo{
			Handle: getMapString(abuse, "handle"),
			Name:   getEntityDisplayName(abuse),
			Email:  getEntityEmail(abuse),
			Phone:  getEntityPhone(abuse),
		}
	}

	if technical := findRDAPEntityByRole(raw, "technical"); technical != nil {
		tipResponse.TechnicalInfo = RDAPIPTipContactInfo{
			Handle: getMapString(technical, "handle"),
			Name:   getEntityDisplayName(technical),
			Email:  getEntityEmail(technical),
			Phone:  getEntityPhone(technical),
		}
	}

	return tipResponse, nil
}

func buildRDAPIPTipBasicInfo(raw map[string]interface{}) RDAPIPTipBasicInfo {
	return RDAPIPTipBasicInfo{
		IPRange:      buildIPRange(raw),
		CIDR:         strings.Join(extractCIDRs(raw), ", "),
		IPVersion:    strings.ToLower(getMapString(raw, "ipVersion")),
		Name:         getMapString(raw, "name"),
		Handle:       getMapString(raw, "handle"),
		ParentHandle: getMapString(raw, "parentHandle"),
		Type:         getMapString(raw, "type"),
		Status:       strings.Join(getStringSlice(raw["status"]), ", "),
		LinkDetail:   extractPreferredLink(raw),
	}
}

func buildRDAPIPTipEventDateInfo(raw map[string]interface{}) RDAPIPTipEventDateInfo {
	return RDAPIPTipEventDateInfo{
		SegmentLastChanged:  extractEventDate(raw, "last changed"),
		SegmentRegistration: extractEventDate(raw, "registration"),
	}
}

func buildIPRange(raw map[string]interface{}) string {
	startAddress := getMapString(raw, "startAddress")
	endAddress := getMapString(raw, "endAddress")

	switch {
	case startAddress != "" && endAddress != "":
		return startAddress + " - " + endAddress
	case startAddress != "":
		return startAddress
	default:
		return endAddress
	}
}

func extractCIDRs(raw map[string]interface{}) []string {
	cidrs, ok := raw["cidr0_cidrs"].([]interface{})
	if !ok {
		return nil
	}

	results := make([]string, 0, len(cidrs))
	for _, item := range cidrs {
		cidrMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		length := ""
		if value, ok := cidrMap["length"].(float64); ok {
			length = fmt.Sprintf("%d", int(value))
		}

		if prefix, ok := cidrMap["v4prefix"].(string); ok && prefix != "" {
			if length != "" {
				results = append(results, prefix+"/"+length)
			} else {
				results = append(results, prefix)
			}
			continue
		}

		if prefix, ok := cidrMap["v6prefix"].(string); ok && prefix != "" {
			if length != "" {
				results = append(results, prefix+"/"+length)
			} else {
				results = append(results, prefix)
			}
		}
	}

	return results
}

func extractPreferredLink(raw map[string]interface{}) string {
	links, ok := raw["links"].([]interface{})
	if !ok {
		return ""
	}

	var fallback string
	for _, item := range links {
		linkMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		href := getMapString(linkMap, "href")
		if href == "" {
			href = getMapString(linkMap, "value")
		}
		if href == "" {
			continue
		}

		rel := strings.ToLower(getMapString(linkMap, "rel"))
		if rel == "self" {
			return href
		}
		if fallback == "" {
			fallback = href
		}
	}

	return fallback
}

func extractEventDate(data map[string]interface{}, action string) string {
	events, ok := data["events"].([]interface{})
	if !ok {
		return ""
	}

	for _, event := range events {
		eventInfo, ok := event.(map[string]interface{})
		if !ok {
			continue
		}
		if strings.EqualFold(getMapString(eventInfo, "eventAction"), action) {
			return getMapString(eventInfo, "eventDate")
		}
	}

	return ""
}

func findRDAPEntityByRole(data map[string]interface{}, role string) map[string]interface{} {
	entities, ok := data["entities"].([]interface{})
	if !ok {
		return nil
	}

	for _, item := range entities {
		entity, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if entityHasRole(entity, role) {
			return entity
		}
		if nested := findRDAPEntityByRole(entity, role); nested != nil {
			return nested
		}
	}

	return nil
}

func entityHasRole(entity map[string]interface{}, role string) bool {
	roles, ok := entity["roles"].([]interface{})
	if !ok {
		return false
	}

	for _, item := range roles {
		if value, ok := item.(string); ok && strings.EqualFold(value, role) {
			return true
		}
	}

	return false
}

func getEntityDisplayName(entity map[string]interface{}) string {
	vcardItems := getEntityVCardItems(entity)
	for _, item := range vcardItems {
		if len(item) > 3 && item[0] == "fn" {
			if value, ok := item[3].(string); ok && value != "" {
				return value
			}
		}
	}
	for _, item := range vcardItems {
		if len(item) > 3 && item[0] == "org" {
			if value, ok := item[3].(string); ok && value != "" {
				return value
			}
		}
	}
	return ""
}

func getEntityEmail(entity map[string]interface{}) string {
	for _, item := range getEntityVCardItems(entity) {
		if len(item) > 3 && item[0] == "email" {
			if value, ok := item[3].(string); ok {
				return value
			}
		}
	}
	return ""
}

func getEntityPhone(entity map[string]interface{}) string {
	for _, item := range getEntityVCardItems(entity) {
		if len(item) > 3 && item[0] == "tel" {
			if value, ok := item[3].(string); ok {
				return value
			}
		}
	}
	return ""
}

func getEntityAddress(entity map[string]interface{}) string {
	for _, item := range getEntityVCardItems(entity) {
		if len(item) < 4 || item[0] != "adr" {
			continue
		}

		if params, ok := item[1].(map[string]interface{}); ok {
			if label, ok := params["label"].(string); ok && label != "" {
				return cleanAddress(label)
			}
		}

		if values, ok := item[3].([]interface{}); ok {
			parts := make([]string, 0, len(values))
			for _, value := range values {
				if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, strings.TrimSpace(text))
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, ", ")
			}
		}
	}
	return ""
}

func cleanAddress(label string) string {
	fields := strings.FieldsFunc(label, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	for i, field := range fields {
		fields[i] = strings.TrimSpace(field)
	}
	return strings.Join(fields, ", ")
}

func getEntityVCardItems(entity map[string]interface{}) [][]interface{} {
	vcardArray, ok := entity["vcardArray"].([]interface{})
	if !ok || len(vcardArray) < 2 {
		return nil
	}

	items, ok := vcardArray[1].([]interface{})
	if !ok {
		return nil
	}

	results := make([][]interface{}, 0, len(items))
	for _, item := range items {
		if fields, ok := item.([]interface{}); ok {
			results = append(results, fields)
		}
	}
	return results
}

func getMapString(data map[string]interface{}, key string) string {
	value, ok := data[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func getStringSlice(value interface{}) []string {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}

	results := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok && text != "" {
			results = append(results, text)
		}
	}
	return results
}
