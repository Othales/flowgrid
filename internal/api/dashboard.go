package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"flowgrid/internal/snmp"

	"flowgrid/pkg/types"
)

// GET /api/routers
func (a *App) handleRouters(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.configMux.RLock()
		list := append([]types.Source(nil), a.cfg.Sources...)
		a.configMux.RUnlock()
		a.writeJSON(w, list)

	case http.MethodPost:
		var src types.Source
		if err := json.NewDecoder(r.Body).Decode(&src); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if src.SNMP.Port == 0 {
			src.SNMP.Port = 161
		}
		allowed := make(map[string]struct{})
		for vendor := range snmp.VendorOIDs {
			allowed[strings.ToLower(vendor)] = struct{}{}
		}
		if _, ok := allowed[strings.ToLower(src.Vendor)]; !ok {
			http.Error(w, "vendor não suportado", http.StatusBadRequest)
			return
		}

		a.configMux.RLock()
		for _, s := range a.cfg.Sources {
			if strings.EqualFold(s.Name, src.Name) {
				a.configMux.RUnlock()
				http.Error(w, "nome já existe", http.StatusConflict)
				return
			}
			if s.SNMP.IP == src.SNMP.IP {
				a.configMux.RUnlock()
				http.Error(w, "ip já existe", http.StatusConflict)
				return
			}
		}
		a.configMux.RUnlock()

		a.configMux.Lock()
		a.cfg.Sources = append(a.cfg.Sources, src)
		err := a.saveConfig()
		a.configMux.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.writeJSON(w, src)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleRouterDetail(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/api/routers/")
	if raw == "" {
		http.Error(w, "rota inválida", http.StatusBadRequest)
		return
	}
	namePart := raw
	subresource := ""
	if idx := strings.Index(raw, "/"); idx != -1 {
		namePart = raw[:idx]
		subresource = raw[idx+1:]
	}
	name, err := url.PathUnescape(namePart)
	if err != nil {
		name = namePart
	}

	if subresource != "" {
		switch {
		case subresource == "interfaces":
			a.handleRouterInterfacesDetail(name, w, r)
			return
		case subresource == "peers":
			a.handleRouterPeersDetail(name, w, r)
			return
		case subresource == "peers/refresh":
			a.handleRouterPeersRefresh(name, w, r)
			return
		default:
			http.Error(w, "recurso não encontrado", http.StatusNotFound)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		a.configMux.RLock()
		defer a.configMux.RUnlock()
		for _, src := range a.cfg.Sources {
			if src.Name == name {
				a.writeJSON(w, src)
				return
			}
		}
		http.Error(w, "roteador não encontrado", http.StatusNotFound)
	case http.MethodPut:
		var updated types.Source
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		if updated.SNMP.Port == 0 {
			updated.SNMP.Port = 161
		}
		replaced := false
		a.configMux.Lock()
		originalName := name
		for i, src := range a.cfg.Sources {
			if src.Name == name {
				if updated.Name == "" {
					updated.Name = src.Name
				}
				a.cfg.Sources[i] = updated
				replaced = true
				break
			}
		}
		if !replaced {
			a.configMux.Unlock()
			http.Error(w, "roteador não encontrado", http.StatusNotFound)
			return
		}
		err := a.saveConfig()
		a.configMux.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.syncSourceRename(originalName, updated.Name)
		a.writeJSON(w, updated)
	case http.MethodDelete:
		a.configMux.Lock()
		filtered := make([]types.Source, 0, len(a.cfg.Sources))
		for _, src := range a.cfg.Sources {
			if src.Name != name {
				filtered = append(filtered, src)
			}
		}
		a.cfg.Sources = filtered
		err := a.saveConfig()
		a.configMux.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	hours := r.URL.Query().Get("hours")
	if hours == "" {
		hours = "24"
	}
	hoursInt, _ := strconv.Atoi(hours)
	startTime := time.Now().Add(-time.Duration(hoursInt) * time.Hour)

	var stats types.DashboardStats
	err := a.conn.QueryRow(ctx, `
            SELECT
                    count(*) as total_flows,
                    sum(Bytes) as total_bytes,
                    sum(Packets) as total_packets,
                    avg(Bps) as current_bps
            FROM flows
            WHERE TimeReceived >= ?
    `, startTime).Scan(
		&stats.TotalFlows,
		&stats.TotalBytes,
		&stats.TotalPackets,
		&stats.CurrentBPS,
	)
	if err != nil {
		http.Error(w, "Erro ao buscar estatísticas gerais: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := a.conn.Query(ctx, `
            SELECT
                    SourceName,
                    any(Vendor) AS vendor,
                    count() AS flow_count,
                    sum(Bytes) AS total_bytes,
                    sum(Packets) AS total_packets,
                    avg(Bps) AS avg_bps,
                    max(Bps) AS peak_bps,
                    max(TimeReceived) AS last_active
            FROM flows
            WHERE TimeReceived >= ?
            GROUP BY SourceName
            ORDER BY total_bytes DESC
            LIMIT 10
    `, startTime)
	if err != nil {
		http.Error(w, "Erro ao buscar top sources: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var source types.SourceStats
		var lastActive time.Time
		var avgBps float64
		var peakBps uint64
		if err := rows.Scan(&source.SourceName, &source.Vendor, &source.FlowCount, &source.TotalBytes, &source.TotalPackets, &avgBps, &peakBps, &lastActive); err == nil {
			source.AvgBps = avgBps
			source.PeakBps = float64(peakBps)
			source.LastActive = lastActive.Format(time.RFC3339)
			if stats.TotalBytes > 0 {
				source.Percentage = float64(source.TotalBytes) / float64(stats.TotalBytes) * 100
			}
			stats.TopSources = append(stats.TopSources, source)
		}
	}

	rows, err = a.conn.Query(ctx, `
            SELECT
                    Proto,
                    DstPort,
                    count(*) as flow_count,
                    sum(Bytes) as total_bytes
            FROM flows
            WHERE TimeReceived >= ?
            GROUP BY Proto, DstPort
            ORDER BY total_bytes DESC
            LIMIT 10
    `, startTime)
	if err != nil {
		http.Error(w, "Erro ao buscar top applications: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var app types.AppStats
		if err := rows.Scan(&app.Protocol, &app.Port, &app.FlowCount, &app.TotalBytes); err == nil {
			stats.TopApplications = append(stats.TopApplications, app)
		}
	}

	if err := a.conn.QueryRow(ctx, `
            SELECT count(*)
            FROM flows
            WHERE TimeReceived >= ?
            AND JSONExtractBool(ThreatInfo, 'is_malicious') = true
    `, startTime).Scan(&stats.ThreatsBlocked); err != nil {
		a.conn.QueryRow(ctx, `
                SELECT count(*)
                FROM flows
                WHERE TimeReceived >= ?
                AND ThreatInfo LIKE '%"is_malicious":true%'
        `, startTime).Scan(&stats.ThreatsBlocked)
	}

	if err := a.conn.QueryRow(ctx, `
            SELECT count(*)
            FROM alerts
            WHERE Timestamp >= ?
    `, startTime).Scan(&stats.AlertsLast24h); err != nil {
		stats.AlertsLast24h = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (a *App) handleBGPPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		peers := a.flattenPeers()
		if len(peers) == 0 {
			a.configMux.RLock()
			snmpEnabled := a.cfg.SNMPEnabled
			sources := make([]types.Source, len(a.cfg.Sources))
			copy(sources, a.cfg.Sources)
			a.configMux.RUnlock()

			if snmpEnabled && len(sources) > 0 {
				refreshed, err := a.refreshAllPeers(sources)
				if err != nil {
					http.Error(w, "Erro ao consultar peers BGP via SNMP: "+err.Error(), http.StatusBadGateway)
					return
				}
				peers = refreshed
			}
		}
		a.writeJSON(w, peers)
	case http.MethodPost:
		a.configMux.RLock()
		snmpEnabled := a.cfg.SNMPEnabled
		sources := make([]types.Source, len(a.cfg.Sources))
		copy(sources, a.cfg.Sources)
		a.configMux.RUnlock()

		if !snmpEnabled {
			http.Error(w, "SNMP desabilitado", http.StatusBadRequest)
			return
		}

		peers, err := a.refreshAllPeers(sources)
		if err != nil {
			http.Error(w, "Erro ao consultar peers BGP via SNMP: "+err.Error(), http.StatusBadGateway)
			return
		}

		a.writeJSON(w, peers)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleRouterInterfacesDetail(name string, w http.ResponseWriter, r *http.Request) {
	if a.interfaceMap == nil {
		http.Error(w, "SNMP não configurado", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		info, ok := a.interfaceMap.SnapshotSource(name)
		if !ok {
			http.Error(w, "roteador sem interfaces conhecidas", http.StatusNotFound)
			return
		}
		a.writeJSON(w, info)
	case http.MethodPut:
		var payload snmp.SourceInfo
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		a.interfaceMap.UpdateSource(name, &payload)
		if err := a.saveInterfaces(); err != nil {
			http.Error(w, "falha ao salvar interfaces: "+err.Error(), http.StatusInternalServerError)
			return
		}
		a.writeJSON(w, payload)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleRouterPeersDetail(name string, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, a.getPeersForRouter(name))
	case http.MethodPut:
		var payload []types.BGPNeighbor
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		for i := range payload {
			payload[i].SourceName = name
		}
		if err := a.updatePeersForRouter(name, payload); err != nil {
			http.Error(w, "falha ao salvar peers: "+err.Error(), http.StatusInternalServerError)
			return
		}
		a.writeJSON(w, payload)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleRouterPeersRefresh(name string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.configMux.RLock()
	snmpEnabled := a.cfg.SNMPEnabled
	var source *types.Source
	for i := range a.cfg.Sources {
		if a.cfg.Sources[i].Name == name {
			src := a.cfg.Sources[i]
			source = &src
			break
		}
	}
	a.configMux.RUnlock()

	if !snmpEnabled {
		http.Error(w, "SNMP desabilitado", http.StatusBadRequest)
		return
	}
	if source == nil {
		http.Error(w, "roteador não encontrado", http.StatusNotFound)
		return
	}

	peers, err := snmp.FetchBGPPeers([]types.Source{*source})
	if err != nil {
		http.Error(w, "Erro ao atualizar peers: "+err.Error(), http.StatusBadGateway)
		return
	}

	filtered := make([]types.BGPNeighbor, 0, len(peers))
	for _, peer := range peers {
		if peer.SourceName == name || peer.SourceName == source.Name {
			peer.SourceName = name
			filtered = append(filtered, peer)
		}
	}

	if err := a.updatePeersForRouter(name, filtered); err != nil {
		http.Error(w, "falha ao salvar peers: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a.writeJSON(w, filtered)
}

func (a *App) refreshAllPeers(sources []types.Source) ([]types.BGPNeighbor, error) {
	peers, err := snmp.FetchBGPPeers(sources)
	if err != nil {
		return nil, err
	}

	grouped := make(map[string][]types.BGPNeighbor)
	for _, peer := range peers {
		key := peer.SourceName
		grouped[key] = append(grouped[key], peer)
	}

	a.peersMux.Lock()
	if a.peersCache == nil {
		a.peersCache = make(map[string][]types.BGPNeighbor)
	}
	for name, list := range grouped {
		for i := range list {
			list[i].SourceName = name
		}
		a.peersCache[name] = list
	}
	flattened := a.flattenPeersLocked()
	if err := a.savePeersLocked(); err != nil {
		a.peersMux.Unlock()
		return nil, err
	}
	a.peersMux.Unlock()
	return flattened, nil
}

func (a *App) updatePeersForRouter(name string, peers []types.BGPNeighbor) error {
	a.peersMux.Lock()
	defer a.peersMux.Unlock()
	if a.peersCache == nil {
		a.peersCache = make(map[string][]types.BGPNeighbor)
	}
	normalized := make([]types.BGPNeighbor, len(peers))
	copy(normalized, peers)
	for i := range normalized {
		normalized[i].SourceName = name
	}
	a.peersCache[name] = normalized
	return a.savePeersLocked()
}

func (a *App) getPeersForRouter(name string) []types.BGPNeighbor {
	a.peersMux.RLock()
	defer a.peersMux.RUnlock()
	list := a.peersCache[name]
	result := make([]types.BGPNeighbor, len(list))
	copy(result, list)
	sort.Slice(result, func(i, j int) bool {
		if result[i].PeerIP == result[j].PeerIP {
			return result[i].RemoteAS < result[j].RemoteAS
		}
		return result[i].PeerIP < result[j].PeerIP
	})
	return result
}

func (a *App) flattenPeers() []types.BGPNeighbor {
	a.peersMux.RLock()
	defer a.peersMux.RUnlock()
	return a.flattenPeersLocked()
}

func (a *App) flattenPeersLocked() []types.BGPNeighbor {
	total := 0
	for _, list := range a.peersCache {
		total += len(list)
	}
	result := make([]types.BGPNeighbor, 0, total)
	for name, list := range a.peersCache {
		for _, peer := range list {
			peer.SourceName = name
			result = append(result, peer)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SourceName == result[j].SourceName {
			return result[i].PeerIP < result[j].PeerIP
		}
		return result[i].SourceName < result[j].SourceName
	})
	return result
}

func (a *App) interfacesFile() string {
	if a.interfacesPath != "" {
		return a.interfacesPath
	}
	return "interfaces.json"
}

func (a *App) saveInterfaces() error {
	if a.interfaceMap == nil {
		return nil
	}
	return a.interfaceMap.SaveToFile(a.interfacesFile())
}

func (a *App) peersFile() string {
	if a.peersPath != "" {
		return a.peersPath
	}
	return "peers.json"
}

func (a *App) savePeersLocked() error {
	path := a.peersFile()
	if path == "" {
		path = "peers.json"
	}
	data, err := json.MarshalIndent(a.peersCache, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *App) syncSourceRename(oldName, newName string) {
	if oldName == "" || newName == "" || oldName == newName {
		return
	}
	if a.conn == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := a.conn.Exec(ctx, `ALTER TABLE flows UPDATE SourceName = ? WHERE SourceName = ?`, newName, oldName); err != nil {
			log.Printf("falha ao atualizar flows para %s -> %s: %v", oldName, newName, err)
		}
		if err := a.conn.Exec(ctx, `ALTER TABLE alerts UPDATE SourceName = ? WHERE SourceName = ?`, newName, oldName); err != nil {
			log.Printf("falha ao atualizar alerts para %s -> %s: %v", oldName, newName, err)
		}
		if a.interfaceMap != nil {
			a.interfaceMap.RenameSource(oldName, newName)
			if err := a.saveInterfaces(); err != nil {
				log.Printf("falha ao salvar interfaces ao renomear %s -> %s: %v", oldName, newName, err)
			}
		}
		a.peersMux.Lock()
		if a.peersCache != nil {
			if list, ok := a.peersCache[oldName]; ok {
				delete(a.peersCache, oldName)
				for i := range list {
					list[i].SourceName = newName
				}
				a.peersCache[newName] = list
				if err := a.savePeersLocked(); err != nil {
					log.Printf("falha ao salvar peers ao renomear %s -> %s: %v", oldName, newName, err)
				}
			}
		}
		a.peersMux.Unlock()
	}()
}

func (a *App) handleTimeSeries(w http.ResponseWriter, r *http.Request) {
	sourceName := r.URL.Query().Get("source")
	metric := r.URL.Query().Get("metric")
	hours := r.URL.Query().Get("hours")
	if hours == "" {
		hours = "24"
	}

	if sourceName == "" || metric == "" {
		http.Error(w, "Parâmetros source e metric são obrigatórios", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var query string
	switch metric {
	case "bps":
		query = `SELECT toStartOfMinute(TimeReceived) as time, avg(Bps) as value`
	case "pps":
		query = `SELECT toStartOfMinute(TimeReceived) as time, avg(Packets) as value`
	case "flows":
		query = `SELECT toStartOfMinute(TimeReceived) as time, count(*) as value`
	default:
		http.Error(w, "Métrica inválida", http.StatusBadRequest)
		return
	}

	query += `
            FROM flows
            WHERE TimeReceived >= now() - INTERVAL ? HOUR
            AND SourceName = ?
            GROUP BY time
            ORDER BY time
    `

	rows, err := a.conn.Query(ctx, query, hours, sourceName)
	if err != nil {
		http.Error(w, "Erro ao buscar time series: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var series []types.TimeSeriesPoint
	for rows.Next() {
		var point types.TimeSeriesPoint
		var t time.Time
		if err := rows.Scan(&t, &point.Value); err == nil {
			point.Time = t.Format("15:04")
			series = append(series, point)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(series)
}
