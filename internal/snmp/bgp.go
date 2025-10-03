package snmp

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"flowgrid/pkg/types"
)

const (
	bgpPeerStateOID       = "1.3.6.1.2.1.15.3.1.2"
	bgpPeerAdminStatusOID = "1.3.6.1.2.1.15.3.1.3"
	bgpPeerRemoteAddrOID  = "1.3.6.1.2.1.15.3.1.7"
	bgpPeerRemoteAsOID    = "1.3.6.1.2.1.15.3.1.9"
	bgpPeerInUpdatesOID   = "1.3.6.1.2.1.15.3.1.10"
	bgpPeerOutUpdatesOID  = "1.3.6.1.2.1.15.3.1.11"
	bgpPeerEstablishedOID = "1.3.6.1.2.1.15.3.1.19"
)

var (
	bgpStateMap = map[int]string{
		1: "idle",
		2: "connect",
		3: "active",
		4: "opensent",
		5: "openconfirm",
		6: "established",
	}
	bgpAdminMap = map[int]string{
		1: "parado",
		2: "iniciado",
	}
)

// FetchBGPPeers consulta os roteadores configurados via SNMP e retorna os peers BGP detectados.
func FetchBGPPeers(sources []types.Source) ([]types.BGPNeighbor, error) {
	neighbors := make([]types.BGPNeighbor, 0)
	failures := make([]string, 0)

	for _, source := range sources {
		if strings.TrimSpace(source.SNMP.IP) == "" {
			continue
		}
		if source.SNMP.Port == 0 {
			source.SNMP.Port = 161
		}

		entries, err := fetchPeersForSource(source)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source.Name, err))
			continue
		}
		neighbors = append(neighbors, entries...)
	}

	if len(failures) > 0 {
		log.Printf("AVISO: falhas ao consultar peers BGP: %s", strings.Join(failures, "; "))
	}

	sort.Slice(neighbors, func(i, j int) bool {
		if neighbors[i].SourceName == neighbors[j].SourceName {
			return neighbors[i].PeerIP < neighbors[j].PeerIP
		}
		return neighbors[i].SourceName < neighbors[j].SourceName
	})

	if len(neighbors) == 0 && len(failures) > 0 {
		return nil, fmt.Errorf(strings.Join(failures, "; "))
	}

	return neighbors, nil
}

func fetchPeersForSource(source types.Source) ([]types.BGPNeighbor, error) {
	session, err := buildSNMPSession(source.SNMP, 10*time.Second, 2)
	if err != nil {
		return nil, err
	}
	if err := session.Connect(); err != nil {
		return nil, err
	}
	defer session.Conn.Close()
	session.Conn.SetDeadline(time.Now().Add(20 * time.Second))

	entries := make(map[string]*types.BGPNeighbor)
	ensureEntry := func(idx string) *types.BGPNeighbor {
		if entries[idx] == nil {
			entries[idx] = &types.BGPNeighbor{
				SourceName: source.Name,
				Vendor:     source.Vendor,
			}
		}
		return entries[idx]
	}

	walkers := []struct {
		oid string
		fn  func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU)
	}{
		{
			oid: bgpPeerRemoteAddrOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				entry.PeerIP = decodeIPAddress(pdu.Value)
			},
		},
		{
			oid: bgpPeerRemoteAsOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				if value, ok := toUint64(pdu.Value); ok {
					entry.RemoteAS = uint32(value)
				}
			},
		},
		{
			oid: bgpPeerStateOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				if value, ok := toInt(pdu.Value); ok {
					entry.State = bgpStateMap[value]
					if entry.State == "" {
						entry.State = fmt.Sprintf("estado-%d", value)
					}
				}
			},
		},
		{
			oid: bgpPeerAdminStatusOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				if value, ok := toInt(pdu.Value); ok {
					entry.AdminStatus = bgpAdminMap[value]
					if entry.AdminStatus == "" {
						entry.AdminStatus = fmt.Sprintf("status-%d", value)
					}
				}
			},
		},
		{
			oid: bgpPeerInUpdatesOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				if value, ok := toUint64(pdu.Value); ok {
					entry.InputMessages = value
				}
			},
		},
		{
			oid: bgpPeerOutUpdatesOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				if value, ok := toUint64(pdu.Value); ok {
					entry.OutputMessages = value
				}
			},
		},
		{
			oid: bgpPeerEstablishedOID,
			fn: func(entry *types.BGPNeighbor, pdu gosnmp.SnmpPDU) {
				if value, ok := toUint64(pdu.Value); ok && value > 0 {
					entry.EstablishedFor = formatDuration(time.Duration(value) * time.Second)
				}
			},
		},
	}

	for _, walker := range walkers {
		pdus, err := session.WalkAll(walker.oid)
		if err != nil {
			if isTableMissing(err) {
				if walker.oid == bgpPeerRemoteAddrOID {
					return []types.BGPNeighbor{}, nil
				}
				continue
			}
			return nil, err
		}
		for _, pdu := range pdus {
			idx := oidSuffix(pdu.Name, walker.oid)
			if idx == "" {
				continue
			}
			entry := ensureEntry(idx)
			walker.fn(entry, pdu)
		}
	}

	result := make([]types.BGPNeighbor, 0, len(entries))
	for _, entry := range entries {
		if entry.PeerIP == "" {
			continue
		}
		if entry.State == "" {
			entry.State = "desconhecido"
		}
		if entry.AdminStatus == "" {
			entry.AdminStatus = "indisponível"
		}
		result = append(result, *entry)
	}

	return result, nil
}

func decodeIPAddress(value interface{}) string {
	switch v := value.(type) {
	case string:
		if strings.Contains(v, ":") {
			ip := net.ParseIP(v)
			if ip != nil {
				return ip.String()
			}
		}
		return strings.TrimSpace(v)
	case []byte:
		if len(v) == 0 {
			return ""
		}
		ip := net.IP(v)
		return ip.String()
	default:
		return fmt.Sprint(v)
	}
}

func toUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int16:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int32:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	default:
		return 0, false
	}
}

func toInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	default:
		return 0, false
	}
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	hours := int(d.Hours())
	days := hours / 24
	hours = hours % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func oidSuffix(oid, base string) string {
	cleanOID := strings.TrimPrefix(oid, ".")
	cleanBase := strings.TrimPrefix(base, ".")
	if !strings.HasPrefix(cleanOID, cleanBase) {
		return ""
	}
	suffix := strings.TrimPrefix(cleanOID[len(cleanBase):], ".")
	return suffix
}

func isTableMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "nosuch") || strings.Contains(lower, "no such object")
}
