package certutil

import (
	"golang.org/x/net/publicsuffix"
	"net"
	"strings"
)

const (
	DomainPrefix = "_acme-challenge"
	wildcard     = "*."
)

// CheckTXTRecord 检测dns-01 challenge 的 TXT 记录, 是否和 compareRecord 一致
func CheckTXTRecord(domain, compareRecord string) bool {
	ss, err := net.LookupTXT(DomainPrefix + "." + domain)
	if err != nil {
		return false
	}

	if len(ss) < 1 {
		return false
	}

	return ss[0] == compareRecord
}

// GetRecordName 根据domain, 获取需要设置TXT记录的字段
func GetRecordName(domain string) string {
	index := strings.Index(domain, wildcard)
	switch index {
	case 0:
		return DomainPrefix + "." + domain[len(wildcard):]
	default:
		return DomainPrefix + "." + domain
	}
}

// GetSubDomain 获取二级域名
func GetSubDomain(domain string) string {
	ef, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return ef
}
