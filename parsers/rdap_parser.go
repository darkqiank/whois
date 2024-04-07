package parsers

import (
	"fmt"
)

func ParseRDAPResponse(result map[string]interface{}) (RDAPInfo, error) {

	rdap := RDAPInfo{}
	if objectClassName, ok := result["objectClassName"]; ok {
		rdap.Type = objectClassName.(string)
		if rdap.Type == "domain" {
			data, err := ParseRDAPResponseForDomain(result)
			if err == nil {
				rdap.Data = data
			}
		} else if rdap.Type == "autnum" {
			data, err := ParseRDAPResponseforASN(result)
			if err == nil {
				rdap.Data = data
			}
		} else {
			data, err := ParseRDAPResponseforIP(result)
			if err == nil {
				rdap.Data = data
			}
		}
	}

	return rdap, nil
}

// ParseRDAPResponseForDomain function is used to parse the RDAP response for a given domain.
func ParseRDAPResponseForDomain(result map[string]interface{}) (DomainInfo, error) {
	domainInfo := DomainInfo{}

	if handle, ok := result["handle"]; ok {
		domainInfo.ID = handle.(string)
	}

	if ldhName, ok := result["ldhName"]; ok {
		domainInfo.Domain = ldhName.(string)
	}

	if status, ok := result["status"]; ok {
		domainInfo.Status = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			domainInfo.Status[i] = s.(string)
		}
	}

	if entities, ok := result["entities"]; ok {
		for _, entity := range entities.([]interface{}) {
			if roles, ok := entity.(map[string]interface{})["roles"]; ok {
				for _, role := range roles.([]interface{}) {
					if role.(string) == "registrar" {
						registrarEntity := entity.(map[string]interface{})
						if vcardArray, ok := registrarEntity["vcardArray"]; ok {
							vcardArraySlice, ok := vcardArray.([]interface{})
							if ok && len(vcardArraySlice) > 1 {
								innerSlice, ok := vcardArraySlice[1].([]interface{})
								if ok {
									for _, item := range innerSlice {
										itemSlice, ok := item.([]interface{})
										if ok && len(itemSlice) > 0 {
											if itemSlice[0] == "fn" && len(itemSlice) > 3 {
												domainInfo.Registrar = itemSlice[3].(string)
												break
											}
										}
									}
								}
							}
						}
						if publicIds, ok := registrarEntity["publicIds"]; ok {
							domainInfo.RegistrarIANAID = publicIds.([]interface{})[0].(map[string]interface{})["identifier"].(string)
						}
						break
					}
				}
			}
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				value := eventInfo["eventDate"].(string)
				domainInfo.CreatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domainInfo.CreatedDateInTime = &parsed
				}
			case "expiration":
				value := eventInfo["eventDate"].(string)
				domainInfo.ExpirationDate = value
				if parsed, err := parseDateString(value); err == nil {
					domainInfo.ExpirationDateInTime = &parsed
				}
			case "last changed":
				value := eventInfo["eventDate"].(string)
				domainInfo.UpdatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domainInfo.UpdatedDateInTime = &parsed
				}
			case "last update of RDAP database":
				value := eventInfo["eventDate"].(string)
				domainInfo.LastUpdateOfRDAPDB = value
			}
		}
	}

	if nameservers, ok := result["nameservers"]; ok {
		domainInfo.NameServers = make([]string, len(nameservers.([]interface{})))
		for i, ns := range nameservers.([]interface{}) {
			domainInfo.NameServers[i] = ns.(map[string]interface{})["ldhName"].(string)
		}
	}

	domainInfo.DNSSec = "unsigned"
	if secureDNS, ok := result["secureDNS"]; ok {
		if dsData, ok := secureDNS.(map[string]interface{})["dsData"].([]interface{}); ok && len(dsData) > 0 {
			dsDataInfo := dsData[0].(map[string]interface{})
			if dsDataInfo["keytag"] != nil && dsDataInfo["algorithm"] != nil && dsDataInfo["digestType"] != nil && dsDataInfo["digest"] != nil {
				domainInfo.DNSSec = "signedDelegation"
				domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
					int(dsDataInfo["keytag"].(float64)),
					int(dsDataInfo["algorithm"].(float64)),
					int(dsDataInfo["digestType"].(float64)),
					dsDataInfo["digest"].(string),
				)
			}
		} else if keyData, ok := secureDNS.(map[string]interface{})["keyData"].([]interface{}); ok && len(keyData) > 0 {
			keyDataInfo := keyData[0].(map[string]interface{})
			if keyDataInfo["algorithm"] != nil && keyDataInfo["flags"] != nil && keyDataInfo["protocol"] != nil && keyDataInfo["publicKey"] != nil {
				domainInfo.DNSSec = "signedDelegation"
				domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
					int(keyDataInfo["algorithm"].(float64)),
					int(keyDataInfo["flags"].(float64)),
					int(keyDataInfo["protocol"].(float64)),
					keyDataInfo["publicKey"].(string),
				)
			}
		}
	}

	return domainInfo, nil
}

// ParseRDAPResponseforIP function is used to parse the WHOIS response for an IP address.
func ParseRDAPResponseforIP(result map[string]interface{}) (IPInfo, error) {
	ipinfo := IPInfo{}

	if handle, ok := result["handle"]; ok {
		ipinfo.IP = handle.(string)
	}

	if startAddress, ok := result["startAddress"]; ok {
		ipinfo.Range = startAddress.(string)
	}

	if endAddress, ok := result["endAddress"]; ok {
		ipinfo.Range += " - " + endAddress.(string)
	}

	if name, ok := result["name"]; ok {
		ipinfo.NetName = name.(string)
	}

	if cidrs, ok := result["cidr0_cidrs"]; ok {
		for _, cidr := range cidrs.([]interface{}) {
			cidrMap := cidr.(map[string]interface{})
			if v4prefix, ok := cidrMap["v4prefix"]; ok {
				length := cidrMap["length"].(float64)
				ipinfo.CIDR = fmt.Sprintf("%s/%d", v4prefix.(string), int(length))
			} else if v6prefix, ok := cidrMap["v6prefix"]; ok {
				length := cidrMap["length"].(float64)
				ipinfo.CIDR = fmt.Sprintf("%s/%d", v6prefix.(string), int(length))
			}
		}
	}

	if type_, ok := result["type"]; ok && type_ != nil {
		ipinfo.Networktype = type_.(string)
	} else {
		ipinfo.Networktype = "Unknown"
	}

	if country, ok := result["country"]; ok {
		ipinfo.Country = country.(string)
	}

	if status, ok := result["status"]; ok {
		ipinfo.IPStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			ipinfo.IPStatus[i] = s.(string)
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				ipinfo.CreationDate = eventInfo["eventDate"].(string)
			case "last changed":
				ipinfo.UpdatedDate = eventInfo["eventDate"].(string)
			}
		}
	}
	return ipinfo, nil
}

// ParseRDAPResponseforASN function is used to parse the RDAP response for an ASN.
func ParseRDAPResponseforASN(result map[string]interface{}) (ASNInfo, error) {
	asninfo := ASNInfo{}

	if handle, ok := result["handle"]; ok {
		asninfo.ASN = handle.(string)
	}

	if name, ok := result["name"]; ok {
		asninfo.ASName = name.(string)
	}

	if status, ok := result["status"]; ok {
		asninfo.ASStatus = make([]string, len(status.([]interface{})))
		for i, s := range status.([]interface{}) {
			asninfo.ASStatus[i] = s.(string)
		}
	}

	if events, ok := result["events"]; ok {
		for _, event := range events.([]interface{}) {
			eventInfo := event.(map[string]interface{})
			switch eventInfo["eventAction"].(string) {
			case "registration":
				asninfo.CreationDate = eventInfo["eventDate"].(string)
			case "last changed":
				asninfo.UpdatedDate = eventInfo["eventDate"].(string)
			}
		}
	}
	return asninfo, nil
}
