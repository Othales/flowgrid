package enrichment

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"flowgrid/pkg/types"
)

type ThreatIntelService struct {
	cache         sync.Map
	blocklistIPs  map[string]struct{}
	blocklistCIDR []*net.IPNet
}

func NewThreatIntelService() *ThreatIntelService {
	return &ThreatIntelService{
		blocklistIPs: make(map[string]struct{}),
	}
}

var blocklistSources = []string{
	"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
	"https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
	"https://www.spamhaus.org/drop/drop.txt",
	"https://www.spamhaus.org/drop/edrop.txt",
}

func (s *ThreatIntelService) UpdateBlocklist() {
	newIPs := make(map[string]struct{})
	var newCIDRs []*net.IPNet
	client := &http.Client{Timeout: 30 * time.Second}

	for _, url := range blocklistSources {
		resp, err := client.Get(url)
		if err != nil {
			log.Printf("Erro ao baixar blocklist de %s: %v", url, err)
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			entry := parts[0]
			if strings.Contains(entry, "/") {
				if _, network, err := net.ParseCIDR(entry); err == nil {
					newCIDRs = append(newCIDRs, network)
				}
			} else if net.ParseIP(entry) != nil {
				newIPs[entry] = struct{}{}
			}
		}
		resp.Body.Close()
	}

	s.blocklistIPs = newIPs
	s.blocklistCIDR = newCIDRs
	log.Printf("Blocklist atualizada: %d IPs, %d ranges", len(s.blocklistIPs), len(s.blocklistCIDR))
}

func (s *ThreatIntelService) Check(ip string) types.ThreatIntel {
	if cached, ok := s.cache.Load(ip); ok {
		return cached.(types.ThreatIntel)
	}

	malicious := false
	if _, ok := s.blocklistIPs[ip]; ok {
		malicious = true
	} else if parsed := net.ParseIP(ip); parsed != nil {
		for _, network := range s.blocklistCIDR {
			if network.Contains(parsed) {
				malicious = true
				break
			}
		}
	}

	result := types.ThreatIntel{
		IsMalicious: malicious,
		Confidence:  0.9,
		LastUpdated: time.Now().Unix(),
	}
	s.cache.Store(ip, result)
	return result
}

func (s *ThreatIntelService) ClearCache() {
	s.cache.Range(func(key, _ interface{}) bool {
		s.cache.Delete(key)
		return true
	})
}
