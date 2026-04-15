# Tip 格式接口说明

本文档说明当前支持 `tip=1` 返回格式的接口，包括：

- 域名 WHOIS 接口：`GET /{domain}?tip=1`
- IP RDAP 接口：`GET /rdap/{ip}?tip=1`

## 通用说明

- 请求方法：`GET`
- 当 `tip=1` 且查询成功时，接口直接返回 tip 对象，不再使用 `{ success, data, error }` 包装结构。
- 域名 tip 仅适用于域名 WHOIS 查询。
- IP tip 仅适用于 IP RDAP 查询。
- 如果需要完整原始数据，请不要传 `tip=1`，直接使用默认接口返回。

## 1. 域名 WHOIS Tip 接口

接口地址：

```http
GET /{domain}?tip=1
```

请求示例：

```http
GET /google.com?tip=1
```

可选参数：

- `tip=1`：启用 tip 返回格式
- `ref=1`：启用 referral 查询

成功响应示例：

```json
{
  "contactEmail": "abusecomplaints@markmonitor.com",
  "contactPhone": "+1.2086851750",
  "dnsNameServer": [
    "NS1.GOOGLE.COM",
    "NS2.GOOGLE.COM",
    "NS3.GOOGLE.COM",
    "NS4.GOOGLE.COM"
  ],
  "domainName": "GOOGLE.COM",
  "domainStatus": [
    "clientdeleteprohibited",
    "clienttransferprohibited",
    "clientupdateprohibited"
  ],
  "expirationTime": "2028-09-14T04:00:00Z",
  "registrant": "Google LLC",
  "registrar": "MarkMonitor Inc.",
  "registrarWHOISServer": "whois.markmonitor.com",
  "registrationTime": "1997-09-15T04:00:00Z",
  "updatedDate": "2019-09-09T15:39:04Z"
}
```

返回字段说明：

| 字段名 | 类型 | 说明 |
| --- | --- | --- |
| `domainName` | string | 域名，统一转为大写 |
| `domainStatus` | string[] | 域名状态列表 |
| `dnsNameServer` | string[] | DNS 服务器列表，统一转为大写 |
| `registrar` | string | 注册商名称 |
| `registrant` | string | 注册人或注册组织名称 |
| `contactEmail` | string | 联系邮箱 |
| `contactPhone` | string | 联系电话 |
| `registrarWHOISServer` | string | 注册商 WHOIS 服务器 |
| `registrationTime` | string | 注册时间 |
| `updatedDate` | string | 更新时间 |
| `expirationTime` | string | 过期时间 |

失败说明：

- 查询失败或数据为空时，当前接口返回 `HTTP 500`，响应体可能为：

```json
null
```

## 2. IP RDAP Tip 接口

接口地址：

```http
GET /rdap/{ip}?tip=1
```

请求示例：

```http
GET /rdap/216.250.248.0?tip=1
```

可选参数：

- `tip=1`：启用 tip 返回格式
- `ref=1`：启用 RDAP referral 跳转

限制说明：

- 该接口仅支持 IP 查询。
- 如果传入域名或 ASN，则返回参数错误，不支持 tip 格式。

成功响应示例：

```json
{
  "basicInfo": {
    "ipRange": "216.250.248.0 - 216.250.255.255",
    "cidr": "216.250.248.0/21",
    "ipVersion": "v4",
    "name": "MHSL-5-216-250-248-0-21",
    "handle": "NET-216-250-248-0-1",
    "parentHandle": "NET-216-0-0-0-0",
    "type": "DIRECT ALLOCATION",
    "status": "active",
    "linkDetail": "https://rdap.arin.net/registry/ip/216.250.248.0"
  },
  "eventDateInfo": {
    "segmentLastChanged": "2020-07-30T18:02:08-04:00",
    "segmentRegistration": "2020-07-30T16:23:06-04:00",
    "institutionLastChanged": "2024-11-25T11:09:46-05:00",
    "institutionRegistration": "2018-08-01T11:40:32-04:00"
  },
  "institutionInfo": {
    "handle": "MHSL-5",
    "role": "registrant",
    "name": "Majestic Hosting Solutions, LLC",
    "address": "1900 Surveyor Blvd Suite 100, Carrollton, TX, 75006, United States"
  },
  "abuseInfo": {
    "handle": "ABUSE7610-ARIN",
    "name": "Abuse",
    "email": "abuse@spinservers.com",
    "phone": "+1-833-774-6778"
  },
  "technicalInfo": {
    "handle": "TECHN1659-ARIN",
    "name": "Technical",
    "email": "technical@spinservers.com",
    "phone": "+1-833-774-6778"
  }
}
```

返回字段说明：

### `basicInfo`

| 字段名 | 类型 | 说明 |
| --- | --- | --- |
| `ipRange` | string | IP 地址范围 |
| `cidr` | string | CIDR 表示 |
| `ipVersion` | string | IP 版本，如 `v4`、`v6` |
| `name` | string | 网络名称 |
| `handle` | string | 当前网段句柄 |
| `parentHandle` | string | 上级网段句柄 |
| `type` | string | 分配类型 |
| `status` | string | 网段状态，多个状态时以逗号拼接 |
| `linkDetail` | string | 详情链接，优先返回 RDAP `self` 链接 |

### `eventDateInfo`

| 字段名 | 类型 | 说明 |
| --- | --- | --- |
| `segmentLastChanged` | string | 当前网段最后变更时间 |
| `segmentRegistration` | string | 当前网段注册时间 |
| `institutionLastChanged` | string | 机构最后变更时间 |
| `institutionRegistration` | string | 机构注册时间 |

### `institutionInfo`

| 字段名 | 类型 | 说明 |
| --- | --- | --- |
| `handle` | string | 机构句柄 |
| `role` | string | 机构角色，当前固定为 `registrant` |
| `name` | string | 机构名称 |
| `address` | string | 机构地址 |

### `abuseInfo` / `technicalInfo`

| 字段名 | 类型 | 说明 |
| --- | --- | --- |
| `handle` | string | 联系人句柄 |
| `name` | string | 联系人名称 |
| `email` | string | 联系邮箱 |
| `phone` | string | 联系电话 |

失败响应示例：

```json
{
  "success": false,
  "error": "tip=1 only supports ip rdap queries"
}
```

常见失败场景：

- 传入的不是 IP 地址
- RDAP 查询失败
- RDAP 返回空数据

## 3. 调用建议

- 域名 tip 适合快速展示域名注册信息。
- IP tip 适合快速展示网段、机构和联系人信息。
- 如果需要完整 RDAP 或 WHOIS 内容，建议不要传 `tip=1`。
