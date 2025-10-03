package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"flowgrid/pkg/types"
)

func Load(path string) (*types.Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(file, &raw); err != nil {
		return nil, fmt.Errorf("falha ao decodificar %s: %w", path, err)
	}

	var cfg types.Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("falha ao decodificar %s: %w", path, err)
	}

	applyDefaults(&cfg, raw)
	return &cfg, nil
}

func LoadAlertRules(path string) ([]types.AlertRule, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler %s: %w", path, err)
	}

	var rules []types.AlertRule
	if err := json.Unmarshal(file, &rules); err != nil {
		return nil, fmt.Errorf("falha ao decodificar %s: %w", path, err)
	}

	log.Printf("%d regras de alerta carregadas de %s", len(rules), path)
	return rules, nil
}

func LoadWhitelist(path string) (*types.Whitelist, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler %s: %w", path, err)
	}

	var wl types.Whitelist
	if err := json.Unmarshal(file, &wl); err != nil {
		return nil, fmt.Errorf("falha ao decodificar %s: %w", path, err)
	}

	log.Printf("Whitelist carregada com %d IPs e %d CIDRs.", len(wl.IPs), len(wl.CIDRs))
	return &wl, nil
}

func applyDefaults(cfg *types.Config, raw map[string]json.RawMessage) {
	if cfg.UpdateInterval == 0 {
		cfg.UpdateInterval = 15
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 10000
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 5
	}
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.NetFlowPort == 0 {
		cfg.NetFlowPort = 2055
	}
	if cfg.ClickHouseAddr == "" {
		cfg.ClickHouseAddr = "127.0.0.1:9000"
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.CircuitBreaker.MaxFailures == 0 {
		cfg.CircuitBreaker.MaxFailures = 5
	}
	if cfg.CircuitBreaker.ResetTimeout == 0 {
		cfg.CircuitBreaker.ResetTimeout = 60
	}
	if cfg.AdaptiveSampling.CooldownSeconds == 0 {
		cfg.AdaptiveSampling.CooldownSeconds = 300
	}
	if cfg.AdaptiveSampling.IncrementStep == 0 {
		cfg.AdaptiveSampling.IncrementStep = 100
	}
	if cfg.AdaptiveSampling.MinRate == 0 {
		cfg.AdaptiveSampling.MinRate = 100
	}
	if cfg.AdaptiveSampling.MaxRate == 0 {
		cfg.AdaptiveSampling.MaxRate = 2000
	}

	if cfg.Performance.MaxGoroutines == 0 {
		cfg.Performance.MaxGoroutines = 1000
	}
	if cfg.Performance.FlowQueueSize == 0 {
		cfg.Performance.FlowQueueSize = 50000
	}
	if cfg.Performance.AlertQueueSize == 0 {
		cfg.Performance.AlertQueueSize = 10000
	}
	if cfg.Performance.MaxOpenConnections == 0 {
		cfg.Performance.MaxOpenConnections = 50
	}
	if cfg.Performance.MaxIdleConnections == 0 {
		cfg.Performance.MaxIdleConnections = 25
	}
	if cfg.Performance.ConnectionMaxLifetime == 0 {
		cfg.Performance.ConnectionMaxLifetime = 60
	}

	if len(cfg.InternalIPBlocks) == 0 && len(cfg.LocalNetworks) > 0 {
		cfg.InternalIPBlocks = append([]string{}, cfg.LocalNetworks...)
	}
	if len(cfg.LocalNetworks) == 0 && len(cfg.InternalIPBlocks) > 0 {
		cfg.LocalNetworks = append([]string{}, cfg.InternalIPBlocks...)
	}

	// garante slices inicializados para evitar null em JSON
	if cfg.FavoriteIPs == nil {
		cfg.FavoriteIPs = []string{}
	}
	if cfg.FavoriteASNs == nil {
		cfg.FavoriteASNs = []uint32{}
	}
	if cfg.InternalASNs == nil {
		cfg.InternalASNs = []uint32{}
	}
	if cfg.IgnoredIPs == nil {
		cfg.IgnoredIPs = []string{}
	}
	if cfg.IgnoredASNs == nil {
		cfg.IgnoredASNs = []uint32{}
	}
	if cfg.FavoriteServices == nil {
		cfg.FavoriteServices = []string{}
	}
	if cfg.APINetwork == nil {
		cfg.APINetwork = []string{}
	}
	if cfg.Firewall.NetFlowAllowed == nil {
		cfg.Firewall.NetFlowAllowed = []string{}
	}
	if cfg.Firewall.SflowAllowed == nil {
		cfg.Firewall.SflowAllowed = []string{}
	}
	if cfg.Firewall.APIAllowed == nil {
		cfg.Firewall.APIAllowed = []string{}
	}
	if cfg.Firewall.InterfaceExport == nil {
		cfg.Firewall.InterfaceExport = []string{}
	}
	if cfg.Notification.Telegram.ChatIDs == nil {
		cfg.Notification.Telegram.ChatIDs = []string{}
	}
	if cfg.Notification.Telegram.ReplyIDs == nil {
		cfg.Notification.Telegram.ReplyIDs = []string{}
	}
	if cfg.Notification.Email.To == nil {
		cfg.Notification.Email.To = []string{}
	}
	if cfg.Notification.Email.ReplyTo == nil {
		cfg.Notification.Email.ReplyTo = []string{}
	}

	if raw != nil {
		if _, ok := raw["snmp_enabled"]; !ok && len(cfg.Sources) > 0 {
			cfg.SNMPEnabled = true
		}
	} else if len(cfg.Sources) > 0 {
		cfg.SNMPEnabled = true
	}
}

func SaveAlertRules(path string, rules []types.AlertRule) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return fmt.Errorf("falha ao serializar regras: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func SaveWhitelist(path string, wl *types.Whitelist) error {
	if wl == nil {
		wl = &types.Whitelist{}
	}
	data, err := json.MarshalIndent(wl, "", "  ")
	if err != nil {
		return fmt.Errorf("falha ao serializar whitelist: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
