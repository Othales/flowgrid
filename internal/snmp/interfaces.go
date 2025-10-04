package snmp

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"flowgrid/internal/metrics"
	"flowgrid/pkg/types"
)

type InterfaceInfo struct {
	Name     string `json:"name"`
	Desc     string `json:"desc"`
	SNMPName string `json:"snmp_name,omitempty"`
	SNMPDesc string `json:"snmp_desc,omitempty"`
}

type SourceInfo struct {
	Vendor     string                   `json:"vendor"`
	SourceIP   string                   `json:"source_ip"`
	Interfaces map[uint32]InterfaceInfo `json:"interfaces"`
}

type InterfaceMap struct {
	mu   sync.RWMutex
	data map[string]*SourceInfo
}

func NewInterfaceMap() *InterfaceMap {
	return &InterfaceMap{data: make(map[string]*SourceInfo)}
}

func (im *InterfaceMap) GetInterface(sourceName string, ifIndex uint32) (InterfaceInfo, bool) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	if sourceInfo, exists := im.data[sourceName]; exists {
		if ifInfo, ok := sourceInfo.Interfaces[ifIndex]; ok {
			return ifInfo, true
		}
	}
	return InterfaceInfo{}, false
}

func (im *InterfaceMap) GetSource(sourceName string) (*SourceInfo, bool) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	info, ok := im.data[sourceName]
	return info, ok
}

func (im *InterfaceMap) SnapshotSource(sourceName string) (*SourceInfo, bool) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	src, ok := im.data[sourceName]
	if !ok || src == nil {
		return nil, false
	}
	copied := &SourceInfo{
		Vendor:     src.Vendor,
		SourceIP:   src.SourceIP,
		Interfaces: make(map[uint32]InterfaceInfo, len(src.Interfaces)),
	}
	for idx, iface := range src.Interfaces {
		copied.Interfaces[idx] = iface
	}
	return copied, true
}

func (im *InterfaceMap) Len() int {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return len(im.data)
}

func (im *InterfaceMap) SetSource(sourceName, vendor, sourceIP string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.data[sourceName] == nil {
		im.data[sourceName] = &SourceInfo{
			Interfaces: make(map[uint32]InterfaceInfo),
		}
	}
	im.data[sourceName].Vendor = vendor
	im.data[sourceName].SourceIP = sourceIP
}

func (im *InterfaceMap) SetInterface(sourceName string, ifIndex uint32, info InterfaceInfo) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.data[sourceName] == nil {
		im.data[sourceName] = &SourceInfo{Interfaces: make(map[uint32]InterfaceInfo)}
	}
	im.data[sourceName].Interfaces[ifIndex] = info
}

func (im *InterfaceMap) ReplaceData(newData map[string]*SourceInfo) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.data = newData
}

func (im *InterfaceMap) UpdateSource(sourceName string, info *SourceInfo) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.data == nil {
		im.data = make(map[string]*SourceInfo)
	}
	if info == nil {
		delete(im.data, sourceName)
		return
	}
	copied := &SourceInfo{
		Vendor:     info.Vendor,
		SourceIP:   info.SourceIP,
		Interfaces: make(map[uint32]InterfaceInfo, len(info.Interfaces)),
	}
	for idx, iface := range info.Interfaces {
		copied.Interfaces[idx] = iface
	}
	im.data[sourceName] = copied
}

func (im *InterfaceMap) RenameSource(oldName, newName string) {
	if oldName == "" || newName == "" || oldName == newName {
		return
	}
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.data == nil {
		return
	}
	src, ok := im.data[oldName]
	if !ok {
		return
	}
	if im.data[newName] == nil {
		im.data[newName] = src
	} else {
		if im.data[newName].Interfaces == nil {
			im.data[newName].Interfaces = make(map[uint32]InterfaceInfo)
		}
		if im.data[newName].Vendor == "" {
			im.data[newName].Vendor = src.Vendor
		}
		if im.data[newName].SourceIP == "" {
			im.data[newName].SourceIP = src.SourceIP
		}
		for idx, iface := range src.Interfaces {
			im.data[newName].Interfaces[idx] = iface
		}
	}
	delete(im.data, oldName)
}

func (im *InterfaceMap) Snapshot() map[string]*SourceInfo {
	im.mu.RLock()
	defer im.mu.RUnlock()
	snapshot := make(map[string]*SourceInfo, len(im.data))
	for name, src := range im.data {
		if src == nil {
			continue
		}
		copied := &SourceInfo{
			Vendor:     src.Vendor,
			SourceIP:   src.SourceIP,
			Interfaces: make(map[uint32]InterfaceInfo, len(src.Interfaces)),
		}
		for idx, iface := range src.Interfaces {
			copied.Interfaces[idx] = iface
		}
		snapshot[name] = copied
	}
	return snapshot
}

func (im *InterfaceMap) SaveToFile(path string) error {
	im.mu.RLock()
	defer im.mu.RUnlock()

	data, err := json.MarshalIndent(im.data, "", "  ")
	if err != nil {
		return fmt.Errorf("erro ao serializar mapa de interfaces: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("erro ao escrever arquivo temporário de interfaces: %w", err)
	}
	return os.Rename(tmp, path)
}

func (im *InterfaceMap) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Arquivo de cache de interfaces '%s' não encontrado.", path)
			return nil
		}
		return fmt.Errorf("erro ao ler arquivo de interfaces: %w", err)
	}

	var fileData map[string]*SourceInfo
	if err := json.Unmarshal(data, &fileData); err != nil {
		return fmt.Errorf("erro ao deserializar JSON de interfaces: %w", err)
	}

	im.mu.Lock()
	im.data = fileData
	im.mu.Unlock()

	log.Printf("Carregado %d sources do cache '%s'", len(im.data), path)
	return nil
}

var VendorOIDs = map[string]struct {
	IfName       string
	IfAlias      string
	IfDesc       string
	SamplingRate string
}{
	"Cisco": {
		IfName:       "1.3.6.1.2.1.2.2.1.2",
		IfAlias:      "1.3.6.1.2.1.31.1.1.1.18",
		IfDesc:       "1.3.6.1.2.1.2.2.1.2",
		SamplingRate: "1.3.6.1.4.1.9.9.10.1.3.1.1.2",
	},
	"Juniper": {
		IfName:       "1.3.6.1.2.1.2.2.1.2",
		IfAlias:      "1.3.6.1.2.1.31.1.1.1.18",
		IfDesc:       "1.3.6.1.2.1.2.2.1.2",
		SamplingRate: "1.3.6.1.4.1.2636.3.2.1.1.1",
	},
	"Huawei": {
		IfName:       "1.3.6.1.2.1.2.2.1.2",
		IfAlias:      "1.3.6.1.2.1.31.1.1.1.18",
		IfDesc:       "1.3.6.1.2.1.2.2.1.2",
		SamplingRate: "1.3.6.1.4.1.2011.5.25.1.1.2",
	},
	"Default": {
		IfName:       "1.3.6.1.2.1.2.2.1.2",
		IfAlias:      "1.3.6.1.2.1.31.1.1.1.18",
		IfDesc:       "1.3.6.1.2.1.2.2.1.2",
		SamplingRate: "1.3.6.1.2.1.2.2.1.2",
	},
}

const sysDescrOID = "1.3.6.1.2.1.1.1.0"

func buildSNMPSession(cfg types.SNMPConfig, timeout time.Duration, retries int) (*gosnmp.GoSNMP, error) {
	target := strings.TrimSpace(cfg.IP)
	if target == "" {
		return nil, fmt.Errorf("IP SNMP não informado")
	}

	session := &gosnmp.GoSNMP{
		Target:    target,
		Port:      cfg.Port,
		Timeout:   timeout,
		Retries:   retries,
		Transport: "udp",
	}
	if session.Port == 0 {
		session.Port = 161
	}

	version := strings.TrimSpace(strings.ToLower(cfg.Version))
	switch version {
	case "3", "v3", "snmpv3":
		session.Version = gosnmp.Version3
		authProto := toAuthProtocol(cfg.Auth)
		privProto := toPrivProtocol(cfg.Priv)
		security := &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: cfg.AuthPass,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        cfg.PrivPass,
		}
		switch {
		case authProto == gosnmp.NoAuth && privProto == gosnmp.NoPriv:
			session.MsgFlags = gosnmp.NoAuthNoPriv
		case authProto != gosnmp.NoAuth && privProto == gosnmp.NoPriv:
			session.MsgFlags = gosnmp.AuthNoPriv
		case authProto != gosnmp.NoAuth && privProto != gosnmp.NoPriv:
			session.MsgFlags = gosnmp.AuthPriv
		default:
			session.MsgFlags = gosnmp.NoAuthNoPriv
		}
		session.SecurityParameters = security
	case "1", "v1", "snmpv1":
		session.Version = gosnmp.Version1
		if cfg.Community == "" {
			return nil, fmt.Errorf("community SNMP não informado")
		}
		session.Community = cfg.Community
	default:
		session.Version = gosnmp.Version2c
		if cfg.Community == "" {
			return nil, fmt.Errorf("community SNMP não informado")
		}
		session.Community = cfg.Community
	}

	return session, nil
}

func getVendorOIDs(vendor string) (string, string, string, string) {
	vendor = strings.Title(strings.ToLower(vendor))
	if oids, ok := VendorOIDs[vendor]; ok {
		return oids.IfName, oids.IfAlias, oids.IfDesc, oids.SamplingRate
	}
	defaultOIDs := VendorOIDs["Default"]
	return defaultOIDs.IfName, defaultOIDs.IfAlias, defaultOIDs.IfDesc, defaultOIDs.SamplingRate
}

func toAuthProtocol(name string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(name) {
	case "MD5":
		return gosnmp.MD5
	case "SHA", "SHA1":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func toPrivProtocol(name string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(name) {
	case "DES":
		return gosnmp.DES
	case "AES", "AES128":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.NoPriv
	}
}

func TestConnection(cfg types.SNMPConfig) (string, error) {
	session, err := buildSNMPSession(cfg, 5*time.Second, 1)
	if err != nil {
		return "", err
	}

	if err := session.Connect(); err != nil {
		return "", fmt.Errorf("falha ao conectar SNMP: %w", err)
	}
	defer session.Conn.Close()

	packet, err := session.Get([]string{sysDescrOID})
	if err != nil {
		return "", fmt.Errorf("falha ao executar GET SNMP: %w", err)
	}
	if packet == nil || len(packet.Variables) == 0 {
		if packet != nil && packet.Error != gosnmp.NoError {
			return "", fmt.Errorf("dispositivo respondeu com erro SNMP: %s", packet.Error.String())
		}
		return "", fmt.Errorf("nenhuma resposta SNMP recebida")
	}
	for _, variable := range packet.Variables {
		if strings.TrimPrefix(variable.Name, ".") == sysDescrOID {
			switch v := variable.Value.(type) {
			case string:
				return v, nil
			case []byte:
				return string(v), nil
			default:
				return fmt.Sprintf("resposta SNMP: %v", v), nil
			}
		}
	}
	return "", fmt.Errorf("nenhuma resposta SNMP recebida")
}

func UpdateInterfaceMap(im *InterfaceMap, cfg *types.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuração SNMP ausente")
	}
	if !cfg.SNMPEnabled {
		log.Println("SNMP desabilitado na configuração. Ignorando atualização do mapa de interfaces.")
		return nil
	}
	if len(cfg.Sources) == 0 {
		log.Println("Nenhum roteador com SNMP configurado. Mapa de interfaces não foi atualizado.")
		return nil
	}

	log.Println("Iniciando atualização do mapa de interfaces SNMP...")
	previous := im.Snapshot()
	newData := make(map[string]*SourceInfo)

	for _, source := range cfg.Sources {
		if strings.TrimSpace(source.SNMP.IP) == "" {
			continue
		}
		if source.SNMP.Port == 0 {
			source.SNMP.Port = 161
		}
		base := &SourceInfo{
			Vendor:     source.Vendor,
			SourceIP:   source.SNMP.IP,
			Interfaces: make(map[uint32]InterfaceInfo),
		}
		if prev, ok := previous[source.Name]; ok {
			if base.Vendor == "" && prev.Vendor != "" {
				base.Vendor = prev.Vendor
			}
			if source.SNMP.IP == "" && prev.SourceIP != "" {
				base.SourceIP = prev.SourceIP
			}
			for idx, iface := range prev.Interfaces {
				base.Interfaces[idx] = iface
			}
		}
		newData[source.Name] = base

		ifNameOid, ifAliasOid, ifDescOid, _ := getVendorOIDs(source.Vendor)
		log.Printf("Atualizando interfaces para %s (%s)", source.Name, source.Vendor)

		session, err := buildSNMPSession(source.SNMP, 10*time.Second, 2)
		if err != nil {
			log.Printf("AVISO: Configuração SNMP inválida para %s: %v", source.Name, err)
			metrics.Global().IncSnmpErrors()
			continue
		}

		if err := session.Connect(); err != nil {
			log.Printf("AVISO: Falha ao conectar via SNMP a %s: %v", source.SNMP.IP, err)
			metrics.Global().IncSnmpErrors()
			continue
		}
		session.Conn.SetDeadline(time.Now().Add(20 * time.Second))

		ifNames, err := session.WalkAll(ifNameOid)
		if err != nil {
			log.Printf("AVISO: Falha ao fazer walk em ifName para %s: %v", source.Name, err)
			metrics.Global().IncSnmpErrors()
			session.Conn.Close()
			continue
		}

		ifAliases, _ := session.WalkAll(ifAliasOid)
		ifDescs, _ := session.WalkAll(ifDescOid)
		session.Conn.Close()

		aliasMap := make(map[uint32]string)
		for _, pdu := range ifAliases {
			oidParts := strings.Split(pdu.Name, ".")
			ifIndex, err := strconv.ParseUint(oidParts[len(oidParts)-1], 10, 32)
			if err != nil {
				continue
			}
			if value, ok := pdu.Value.([]byte); ok {
				aliasMap[uint32(ifIndex)] = string(value)
			}
		}

		descMap := make(map[uint32]string)
		for _, pdu := range ifDescs {
			oidParts := strings.Split(pdu.Name, ".")
			ifIndex, err := strconv.ParseUint(oidParts[len(oidParts)-1], 10, 32)
			if err != nil {
				continue
			}
			if value, ok := pdu.Value.([]byte); ok {
				descMap[uint32(ifIndex)] = string(value)
			}
		}

		for _, pdu := range ifNames {
			oidParts := strings.Split(pdu.Name, ".")
			ifIndex, err := strconv.ParseUint(oidParts[len(oidParts)-1], 10, 32)
			if err != nil {
				continue
			}

			if value, ok := pdu.Value.([]byte); ok {
				snmpName := string(value)
				snmpDesc := aliasMap[uint32(ifIndex)]
				if desc := descMap[uint32(ifIndex)]; desc != "" {
					snmpDesc = desc
				}

				existing := newData[source.Name].Interfaces[uint32(ifIndex)]
				finalName := strings.TrimSpace(existing.Name)
				if finalName == "" {
					finalName = snmpName
				}
				finalDesc := strings.TrimSpace(existing.Desc)
				if finalDesc == "" {
					finalDesc = snmpDesc
				}

				newData[source.Name].Interfaces[uint32(ifIndex)] = InterfaceInfo{
					Name:     finalName,
					Desc:     finalDesc,
					SNMPName: snmpName,
					SNMPDesc: snmpDesc,
				}
			}
		}

		log.Printf("Source %s: %d interfaces atualizadas", source.Name, len(ifNames))
	}

	im.ReplaceData(newData)
	log.Printf("Mapa de interfaces atualizado. Total: %d sources", im.Len())

	if err := im.SaveToFile("interfaces.json"); err != nil {
		log.Printf("AVISO: Falha ao salvar o cache de interfaces: %v", err)
	}

	return nil
}

func UpdateWithRetry(im *InterfaceMap, cfg *types.Config, maxRetries int) {
	for i := 0; i < maxRetries; i++ {
		if err := UpdateInterfaceMap(im, cfg); err == nil {
			return
		}
		backoff := time.Duration(i) * time.Second
		log.Printf("Tentativa %d/%d falhou, aguardando %v...", i+1, maxRetries, backoff)
		time.Sleep(backoff)
	}
	log.Printf("ERRO: Falha após %d tentativas de atualizar mapa SNMP", maxRetries)
}

func FindSourceNameByIP(cfg *types.Config, ip string) string {
	for _, source := range cfg.Sources {
		if source.SNMP.IP == ip {
			return source.Name
		}
	}
	return "Unknown"
}

func CheckBlocklist(ip net.IP, cidrs []*net.IPNet) bool {
	for _, network := range cidrs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func SamplingRateOID(vendor string) string {
	_, _, _, sampling := getVendorOIDs(vendor)
	return sampling
}
