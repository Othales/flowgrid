package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
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
	name, err := url.PathUnescape(raw)
	if err != nil {
		name = raw
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
	a.configMux.RLock()
	snmpEnabled := a.cfg.SNMPEnabled
	sources := make([]types.Source, len(a.cfg.Sources))
	copy(sources, a.cfg.Sources)
	a.configMux.RUnlock()

	if !snmpEnabled {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]types.BGPNeighbor{})
		return
	}

	peers, err := snmp.FetchBGPPeers(sources)
	if err != nil {
		http.Error(w, "Erro ao consultar peers BGP via SNMP: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
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
		}
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
