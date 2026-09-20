package parsers

import (
	"fmt"
)

func ParseRDAPResponse(result map[string]interface{}) (RDAPInfo, error) {

	rdap := RDAPInfo{Raw: result}
	if objectClassName, ok := result["objectClassName"].(string); ok {
		rdap.Type = objectClassName
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
		} else if rdap.Type == "ip network" {
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

	if handle, ok := result["handle"].(string); ok {
		domainInfo.ID = handle
	}

	if ldhName, ok := result["ldhName"].(string); ok {
		domainInfo.Domain = ldhName
	}

	domainInfo.Status = rdapStringSlice(result["status"])

	if entities, ok := result["entities"].([]interface{}); ok {
		for _, item := range entities {
			entity, ok := item.(map[string]interface{})
			if !ok || !rdapContainsString(entity["roles"], "registrar") {
				continue
			}
			if vcard, ok := entity["vcardArray"].([]interface{}); ok && len(vcard) > 1 {
				if fields, ok := vcard[1].([]interface{}); ok {
					for _, field := range fields {
						parts, ok := field.([]interface{})
						if !ok || len(parts) < 4 || parts[0] != "fn" {
							continue
						}
						if name, ok := parts[3].(string); ok {
							domainInfo.Registrar = name
							break
						}
					}
				}
			}
			if ids, ok := entity["publicIds"].([]interface{}); ok {
				for _, id := range ids {
					if publicID, ok := id.(map[string]interface{}); ok {
						if identifier, ok := publicID["identifier"].(string); ok {
							domainInfo.RegistrarIANAID = identifier
							break
						}
					}
				}
			}
			break
		}
	}

	if events, ok := result["events"].([]interface{}); ok {
		for _, event := range events {
			eventInfo, ok := event.(map[string]interface{})
			if !ok {
				continue
			}
			action, ok := eventInfo["eventAction"].(string)
			if !ok {
				continue
			}
			value, ok := eventInfo["eventDate"].(string)
			if !ok {
				continue
			}
			switch action {
			case "registration":
				domainInfo.CreatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domainInfo.CreatedDateInTime = &parsed
				}
			case "expiration":
				domainInfo.ExpirationDate = value
				if parsed, err := parseDateString(value); err == nil {
					domainInfo.ExpirationDateInTime = &parsed
				}
			case "last changed":
				domainInfo.UpdatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domainInfo.UpdatedDateInTime = &parsed
				}
			case "last update of RDAP database":
				domainInfo.LastUpdateOfRDAPDB = value
			}
		}
	}

	if nameservers, ok := result["nameservers"].([]interface{}); ok {
		domainInfo.NameServers = make([]string, 0, len(nameservers))
		for _, ns := range nameservers {
			if nameserver, ok := ns.(map[string]interface{}); ok {
				if name, ok := nameserver["ldhName"].(string); ok {
					domainInfo.NameServers = append(domainInfo.NameServers, name)
				}
			}
		}
	}

	domainInfo.DNSSec = "unsigned"
	if secureDNS, ok := result["secureDNS"].(map[string]interface{}); ok {
		if dsData, ok := secureDNS["dsData"].([]interface{}); ok && len(dsData) > 0 {
			if dsDataInfo, ok := dsData[0].(map[string]interface{}); ok {
				keytag, keytagOK := dsDataInfo["keytag"].(float64)
				algorithm, algorithmOK := dsDataInfo["algorithm"].(float64)
				digestType, digestTypeOK := dsDataInfo["digestType"].(float64)
				digest, digestOK := dsDataInfo["digest"].(string)
				if keytagOK && algorithmOK && digestTypeOK && digestOK {
					domainInfo.DNSSec = "signedDelegation"
					domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
						int(keytag), int(algorithm), int(digestType), digest)
				}
			}
		} else if keyData, ok := secureDNS["keyData"].([]interface{}); ok && len(keyData) > 0 {
			if keyDataInfo, ok := keyData[0].(map[string]interface{}); ok {
				algorithm, algorithmOK := keyDataInfo["algorithm"].(float64)
				flags, flagsOK := keyDataInfo["flags"].(float64)
				protocol, protocolOK := keyDataInfo["protocol"].(float64)
				publicKey, publicKeyOK := keyDataInfo["publicKey"].(string)
				if algorithmOK && flagsOK && protocolOK && publicKeyOK {
					domainInfo.DNSSec = "signedDelegation"
					domainInfo.DNSSecDSData = fmt.Sprintf("%d %d %d %s",
						int(algorithm), int(flags), int(protocol), publicKey)
				}
			}
		}
	}

	return domainInfo, nil
}

// ParseRDAPResponseforIP function is used to parse the WHOIS response for an IP address.
func ParseRDAPResponseforIP(result map[string]interface{}) (IPInfo, error) {
	ipinfo := IPInfo{}

	if handle, ok := result["handle"].(string); ok {
		ipinfo.IP = handle
	}

	if startAddress, ok := result["startAddress"].(string); ok {
		ipinfo.Range = startAddress
	}

	if endAddress, ok := result["endAddress"].(string); ok {
		ipinfo.Range += " - " + endAddress
	}

	if name, ok := result["name"].(string); ok {
		ipinfo.NetName = name
	}

	if cidrs, ok := result["cidr0_cidrs"].([]interface{}); ok {
		for _, cidr := range cidrs {
			cidrMap, ok := cidr.(map[string]interface{})
			if !ok {
				continue
			}
			length, ok := cidrMap["length"].(float64)
			if !ok {
				continue
			}
			if prefix, ok := cidrMap["v4prefix"].(string); ok {
				ipinfo.CIDR = fmt.Sprintf("%s/%d", prefix, int(length))
			} else if prefix, ok := cidrMap["v6prefix"].(string); ok {
				ipinfo.CIDR = fmt.Sprintf("%s/%d", prefix, int(length))
			}
		}
	}

	if networkType, ok := result["type"].(string); ok {
		ipinfo.Networktype = networkType
	} else {
		ipinfo.Networktype = "Unknown"
	}

	if country, ok := result["country"].(string); ok {
		ipinfo.Country = country
	}

	ipinfo.IPStatus = rdapStringSlice(result["status"])

	if events, ok := result["events"].([]interface{}); ok {
		for _, event := range events {
			eventInfo, ok := event.(map[string]interface{})
			if !ok {
				continue
			}
			action, ok := eventInfo["eventAction"].(string)
			if !ok {
				continue
			}
			date, ok := eventInfo["eventDate"].(string)
			if !ok {
				continue
			}
			switch action {
			case "registration":
				ipinfo.CreationDate = date
			case "last changed":
				ipinfo.UpdatedDate = date
			}
		}
	}
	return ipinfo, nil
}

// ParseRDAPResponseforASN function is used to parse the RDAP response for an ASN.
func ParseRDAPResponseforASN(result map[string]interface{}) (ASNInfo, error) {
	asninfo := ASNInfo{}

	if handle, ok := result["handle"].(string); ok {
		asninfo.ASN = handle
	}

	if name, ok := result["name"].(string); ok {
		asninfo.ASName = name
	}

	asninfo.ASStatus = rdapStringSlice(result["status"])

	if events, ok := result["events"].([]interface{}); ok {
		for _, event := range events {
			eventInfo, ok := event.(map[string]interface{})
			if !ok {
				continue
			}
			action, ok := eventInfo["eventAction"].(string)
			if !ok {
				continue
			}
			date, ok := eventInfo["eventDate"].(string)
			if !ok {
				continue
			}
			switch action {
			case "registration":
				asninfo.CreationDate = date
			case "last changed":
				asninfo.UpdatedDate = date
			}
		}
	}
	return asninfo, nil
}

func rdapStringSlice(value interface{}) []string {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	strings := make([]string, 0, len(items))
	for _, item := range items {
		if value, ok := item.(string); ok {
			strings = append(strings, value)
		}
	}
	return strings
}

func rdapContainsString(value interface{}, target string) bool {
	for _, item := range rdapStringSlice(value) {
		if item == target {
			return true
		}
	}
	return false
}
