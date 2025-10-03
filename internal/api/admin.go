package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"flowgrid/internal/config"
	"flowgrid/internal/snmp"
	"flowgrid/pkg/types"
)

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	cfg := a.sanitizedConfig()
	user := "admin"
	if ctxUser, ok := r.Context().Value(ctxUserKey).(string); ok && ctxUser != "" {
		user = ctxUser
	}
	resp := map[string]interface{}{
		"user":           user,
		"started_at":     a.startTime.Format(time.RFC3339),
		"uptime_seconds": time.Since(a.startTime).Seconds(),
		"config":         cfg,
	}
	if claims, ok := r.Context().Value(ctxClaimsKey).(*Claims); ok && claims != nil && claims.ExpiresAt != nil {
		resp["expires_at"] = claims.ExpiresAt.Time.Format(time.RFC3339)
	}
	a.writeJSON(w, resp)
}

func (a *App) handleVendors(w http.ResponseWriter, r *http.Request) {
	vendors := make([]string, 0, len(snmp.VendorOIDs))
	for name := range snmp.VendorOIDs {
		if name == "Default" {
			continue
		}
		vendors = append(vendors, name)
	}
	sort.Strings(vendors)
	a.writeJSON(w, vendors)
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := a.sanitizedConfig()
		a.writeJSON(w, cfg)
	case http.MethodPut:
		var req configUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		if err := a.applyConfigUpdate(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg := a.sanitizedConfig()
		a.writeJSON(w, cfg)
	default:
		http.Error(w, "método não suportado", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.configMux.RLock()
		rules := append([]types.AlertRule(nil), a.alertRules...)
		a.configMux.RUnlock()
		a.writeJSON(w, rules)
	case http.MethodPost:
		var rule types.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		rule.Name = strings.TrimSpace(rule.Name)
		if rule.Name == "" {
			http.Error(w, "nome obrigatório", http.StatusBadRequest)
			return
		}
		if err := a.addAlertRule(rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.writeJSON(w, map[string]string{"message": "regra criada"})
	default:
		http.Error(w, "método não suportado", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleAlertDetail(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	name, _ = url.PathUnescape(name)
	if name == "" {
		http.Error(w, "nome inválido", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var rule types.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		rule.Name = strings.TrimSpace(rule.Name)
		if rule.Name == "" {
			rule.Name = name
		}
		if err := a.updateAlertRule(name, rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.writeJSON(w, map[string]string{"message": "regra atualizada"})
	case http.MethodDelete:
		if err := a.deleteAlertRule(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "método não suportado", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if a.whitelist == nil {
			a.whitelist = &types.Whitelist{}
		}
		a.writeJSON(w, a.whitelist)
	case http.MethodPut:
		var wl types.Whitelist
		if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		if err := config.SaveWhitelist(a.whitelistPath, &wl); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.configMux.Lock()
		a.whitelist = &wl
		a.configMux.Unlock()
		a.writeJSON(w, map[string]string{"message": "whitelist atualizada"})
	default:
		http.Error(w, "método não suportado", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleSnmpTest(w http.ResponseWriter, r *http.Request) {
	var cfg types.SNMPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "json inválido", http.StatusBadRequest)
		return
	}
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	descr, err := snmp.TestConnection(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.writeJSON(w, map[string]string{"message": "SNMP ok", "description": descr})
}

func (a *App) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	data := a.interfaceMap.Snapshot()
	a.writeJSON(w, data)
}

func (a *App) handleRestart(w http.ResponseWriter, r *http.Request) {
	go func() {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()
	a.writeJSON(w, map[string]string{"message": "reinicialização agendada"})
}

func (a *App) handleSnmpRefresh(w http.ResponseWriter, r *http.Request) {
	go snmp.UpdateWithRetry(a.interfaceMap, a.cfg, a.cfg.MaxRetries)
	a.writeJSON(w, map[string]string{"message": "atualização SNMP iniciada"})
}

func (a *App) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if a.resolver != nil {
		a.resolver.Clear()
	}
	if a.threats != nil {
		a.threats.ClearCache()
	}
	a.writeJSON(w, map[string]string{"message": "caches limpos"})
}

func (a *App) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	backend, available, detail := detectFirewallBackend()
	a.writeJSON(w, map[string]interface{}{
		"backend":            backend,
		"available_backends": available,
		"detail":             detail,
	})
}

func detectFirewallBackend() (string, []string, string) {
	type backendCheck struct {
		label   string
		binary  string
		args    []string
		success string
	}

	checks := []backendCheck{
		{label: "nftables", binary: "nft", args: []string{"list", "tables"}, success: "Integração nativa com nftables disponível."},
		{label: "iptables", binary: "iptables", args: []string{"-S"}, success: "iptables legado disponível."},
		{label: "firewalld", binary: "firewall-cmd", args: []string{"--state"}, success: "firewalld ativo no sistema."},
	}

	available := []string{}
	detected := ""
	detail := ""

	for _, check := range checks {
		if _, err := exec.LookPath(check.binary); err != nil {
			continue
		}
		available = append(available, check.label)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, check.binary, check.args...)
		if err := cmd.Run(); err == nil {
			if detected == "" {
				detected = check.label
				detail = check.success
			}
		} else if detected == "" && detail == "" {
			detail = fmt.Sprintf("%s encontrado, mas comando retornou: %v", check.label, err)
		}
		cancel()
	}

	if detected == "" {
		detected = "não detectado"
		if detail == "" && len(available) == 0 {
			detail = "Nenhum backend de firewall conhecido foi localizado no PATH."
		}
	}

	return detected, available, detail
}

func (a *App) handleGrafanaDashboards(w http.ResponseWriter, r *http.Request) {
	baseDir := filepath.Join("configs", "grafana")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			a.writeJSON(w, []map[string]interface{}{})
			return
		}
		http.Error(w, "Falha ao listar dashboards: "+err.Error(), http.StatusInternalServerError)
		return
	}

	dashboards := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		dashboards = append(dashboards, map[string]interface{}{
			"name":     entry.Name(),
			"size":     info.Size(),
			"modified": info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(dashboards, func(i, j int) bool {
		return dashboards[i]["name"].(string) < dashboards[j]["name"].(string)
	})
	a.writeJSON(w, dashboards)
}

type configUpdateRequest struct {
	NetFlowPort      *int                      `json:"netflow_port"`
	SflowPort        *int                      `json:"sflow_port"`
	HTTPPort         *int                      `json:"http_port"`
	DataPath         *string                   `json:"data_path"`
	ClickhouseClean  *int                      `json:"clickhouse_clean_time"`
	MaximumDiskGB    *int                      `json:"maximum_disk_gb"`
	APINetwork       *[]string                 `json:"api_network"`
	InternalIPBlocks *[]string                 `json:"internal_ip_blocks"`
	InternalASNs     *[]uint32                 `json:"internal_asns"`
	FavoriteIPs      *[]string                 `json:"favorite_ips"`
	FavoriteASNs     *[]uint32                 `json:"favorite_asns"`
	IgnoredIPs       *[]string                 `json:"ignored_ips"`
	IgnoredASNs      *[]uint32                 `json:"ignored_asns"`
	FavoriteServices *[]string                 `json:"favorite_services"`
	Notification     *types.NotificationConfig `json:"notification"`
	Firewall         *types.FirewallConfig     `json:"firewall"`
	UpdateInterval   *int                      `json:"update_interval_minutes"`
	Password         *string                   `json:"password"`
}

func (a *App) applyConfigUpdate(req configUpdateRequest) error {
	a.configMux.Lock()
	defer a.configMux.Unlock()

	if req.NetFlowPort != nil {
		a.cfg.NetFlowPort = *req.NetFlowPort
	}
	if req.SflowPort != nil {
		a.cfg.SflowPort = *req.SflowPort
	}
	if req.HTTPPort != nil {
		a.cfg.HTTPPort = *req.HTTPPort
	}
	if req.DataPath != nil {
		a.cfg.DataPath = *req.DataPath
	}
	if req.ClickhouseClean != nil {
		a.cfg.ClickhouseCleanTime = *req.ClickhouseClean
	}
	if req.MaximumDiskGB != nil {
		a.cfg.MaximumDiskGB = *req.MaximumDiskGB
	}
	if req.APINetwork != nil {
		a.cfg.APINetwork = append([]string{}, (*req.APINetwork)...)
	}
	if req.InternalIPBlocks != nil {
		blocks := append([]string{}, (*req.InternalIPBlocks)...)
		a.cfg.InternalIPBlocks = blocks
		a.cfg.LocalNetworks = append([]string{}, blocks...)
		a.detector.UpdateLocalNetworks(blocks)
	}
	if req.InternalASNs != nil {
		a.cfg.InternalASNs = append([]uint32{}, (*req.InternalASNs)...)
	}
	if req.FavoriteIPs != nil {
		a.cfg.FavoriteIPs = append([]string{}, (*req.FavoriteIPs)...)
	}
	if req.FavoriteASNs != nil {
		a.cfg.FavoriteASNs = append([]uint32{}, (*req.FavoriteASNs)...)
	}
	if req.IgnoredIPs != nil {
		a.cfg.IgnoredIPs = append([]string{}, (*req.IgnoredIPs)...)
	}
	if req.IgnoredASNs != nil {
		a.cfg.IgnoredASNs = append([]uint32{}, (*req.IgnoredASNs)...)
	}
	if req.FavoriteServices != nil {
		a.cfg.FavoriteServices = append([]string{}, (*req.FavoriteServices)...)
	}
	if req.Notification != nil {
		a.cfg.Notification = *req.Notification
	}
	if req.Firewall != nil {
		a.cfg.Firewall = *req.Firewall
	}
	if req.UpdateInterval != nil {
		a.cfg.UpdateInterval = *req.UpdateInterval
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		a.cfg.Password = *req.Password
	}

	if err := a.saveConfig(); err != nil {
		return err
	}
	return nil
}

func (a *App) sanitizedConfig() types.Config {
	a.configMux.RLock()
	defer a.configMux.RUnlock()
	cfg := *a.cfg
	cfg.Password = ""
	cfg.ClickHouseDSN = ""
	cfg.Notification.Telegram.BotToken = ""
	cfg.Notification.Email.Password = ""
	if cfg.Notification.Telegram.ChatIDs == nil {
		cfg.Notification.Telegram.ChatIDs = []string{}
	}
	if cfg.Notification.Telegram.ReplyIDs == nil {
		cfg.Notification.Telegram.ReplyIDs = []string{}
	}
	cfg.APINetwork = append([]string(nil), cfg.APINetwork...)
	cfg.InternalIPBlocks = append([]string(nil), cfg.InternalIPBlocks...)
	cfg.InternalASNs = append([]uint32(nil), cfg.InternalASNs...)
	cfg.FavoriteIPs = append([]string(nil), cfg.FavoriteIPs...)
	cfg.FavoriteASNs = append([]uint32(nil), cfg.FavoriteASNs...)
	cfg.IgnoredIPs = append([]string(nil), cfg.IgnoredIPs...)
	cfg.IgnoredASNs = append([]uint32(nil), cfg.IgnoredASNs...)
	cfg.FavoriteServices = append([]string(nil), cfg.FavoriteServices...)
	if cfg.Notification.Email.To == nil {
		cfg.Notification.Email.To = []string{}
	}
	if cfg.Notification.Email.ReplyTo == nil {
		cfg.Notification.Email.ReplyTo = []string{}
	}
	return cfg
}

func (a *App) writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func (a *App) addAlertRule(rule types.AlertRule) error {
	a.configMux.Lock()
	defer a.configMux.Unlock()
	for _, existing := range a.alertRules {
		if strings.EqualFold(existing.Name, rule.Name) {
			return fmt.Errorf("regra já existe")
		}
	}
	a.alertRules = append(a.alertRules, rule)
	if err := config.SaveAlertRules(a.alertPath, a.alertRules); err != nil {
		return err
	}
	a.detector.UpdateRules(a.alertRules)
	return nil
}

func (a *App) updateAlertRule(name string, rule types.AlertRule) error {
	a.configMux.Lock()
	defer a.configMux.Unlock()
	found := false
	for i, existing := range a.alertRules {
		if strings.EqualFold(existing.Name, name) {
			if rule.Name == "" {
				rule.Name = existing.Name
			}
			a.alertRules[i] = rule
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("regra não encontrada")
	}
	if err := config.SaveAlertRules(a.alertPath, a.alertRules); err != nil {
		return err
	}
	a.detector.UpdateRules(a.alertRules)
	return nil
}

func (a *App) deleteAlertRule(name string) error {
	a.configMux.Lock()
	defer a.configMux.Unlock()
	idx := -1
	for i, existing := range a.alertRules {
		if strings.EqualFold(existing.Name, name) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("regra não encontrada")
	}
	a.alertRules = append(a.alertRules[:idx], a.alertRules[idx+1:]...)
	if err := config.SaveAlertRules(a.alertPath, a.alertRules); err != nil {
		return err
	}
	a.detector.UpdateRules(a.alertRules)
	return nil
}
