package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"strings"
	"time"

	"flowgrid/internal/snmp"
	"flowgrid/pkg/types"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

var jwtKey = []byte("super-secret-key") // ideal: ler do env

type contextKey string

const (
	ctxUserKey   contextKey = "flowgrid_user"
	ctxClaimsKey contextKey = "flowgrid_claims"
)

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func (a *App) startHTTPServer() *http.Server {
	mux := http.NewServeMux()

	// login sem auth
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.handleLogout)

	// protegido
	mux.HandleFunc("/api/session", a.authMiddleware(a.handleSession))
	mux.HandleFunc("/api/system", a.authMiddleware(a.handleSystem))
	mux.HandleFunc("/api/vendors", a.authMiddleware(a.handleVendors))
	mux.HandleFunc("/api/routers", a.authMiddleware(a.handleRouters))
	mux.HandleFunc("/api/routers/", a.authMiddleware(a.handleRouterDetail))
	mux.HandleFunc("/api/config", a.authMiddleware(a.handleConfig))
	mux.HandleFunc("/api/alerts", a.authMiddleware(a.handleAlerts))
	mux.HandleFunc("/api/alerts/", a.authMiddleware(a.handleAlertDetail))
	mux.HandleFunc("/api/whitelist", a.authMiddleware(a.handleWhitelist))
	mux.HandleFunc("/api/snmp/test", a.authMiddleware(a.handleSnmpTest))
	mux.HandleFunc("/api/interfaces", a.authMiddleware(a.handleInterfaces))
	mux.HandleFunc("/api/management/restart", a.authMiddleware(a.handleRestart))
	mux.HandleFunc("/api/management/snmp-refresh", a.authMiddleware(a.handleSnmpRefresh))
	mux.HandleFunc("/api/management/cache-clear", a.authMiddleware(a.handleCacheClear))
	mux.HandleFunc("/api/firewall/status", a.authMiddleware(a.handleFirewallStatus))
	mux.HandleFunc("/api/grafana/dashboards", a.authMiddleware(a.handleGrafanaDashboards))
	mux.HandleFunc("/api/bgp/peers", a.authMiddleware(a.handleBGPPeers))

	// frontend
	mux.Handle("/", http.FileServer(http.Dir("./frontend")))

	mux.HandleFunc("/flows", a.handleFlows)
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/api/v1/", a.handleManagement)
	mux.HandleFunc("/api/dashboard/stats", a.handleDashboardStats)
	mux.HandleFunc("/api/dashboard/timeseries", a.handleTimeSeries)
	mux.HandleFunc("/api/backup/restore", a.backup.HandleRestore)

	mux.HandleFunc("/debug/pprof/", pprof.Index)

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(a.cfg.HTTPPort),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Servidor HTTP na porta %d", a.cfg.HTTPPort)
		log.Printf("Dashboard disponível em: http://45.6.180.13:%d/dashboard/", a.cfg.HTTPPort)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Erro no servidor HTTP: %v", err)
		}
	}()

	return server
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
		return
	}

	if req.User != "admin" || req.Pass != a.cfg.Password {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	// gera token válido por 2h
	exp := time.Now().Add(2 * time.Hour)
	claims := &Claims{
		Username: req.User,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(jwtKey)

	// grava como cookie HttpOnly
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    tokenStr,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true em produção com HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})

	response := map[string]interface{}{
		"message":    "ok",
		"expires_at": exp.Format(time.RFC3339),
		"token":      tokenStr,
	}
	if a != nil {
		cfg := a.sanitizedConfig()
		response["config"] = cfg
	}
	json.NewEncoder(w).Encode(response)
}

// ===== MIDDLEWARE =====
func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractTokenFromRequest(r)
		if tokenStr == "" {
			http.Error(w, "missing auth token", http.StatusUnauthorized)
			return
		}
		claims, err := parseJWTClaims(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey, claims.Username)
		ctx = context.WithValue(ctx, ctxClaimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

func extractTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie("auth"); err == nil && c != nil && c.Value != "" {
		return c.Value
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}
	parts := strings.Fields(authHeader)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func parseJWTClaims(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "logout"})
}

func (a *App) handleSystem(w http.ResponseWriter, r *http.Request) {
	// CPU
	percentages, _ := cpu.Percent(time.Second, true) // true = por core
	totalPercent, _ := cpu.Percent(time.Second, false)

	// Memória
	vm, _ := mem.VirtualMemory()

	// Disco (só partição root)
	du, _ := disk.Usage("/")

	// Host info
	hi, _ := host.Info()

	info := map[string]interface{}{
		"cpu":   totalPercent[0], // uso total %
		"cores": percentages,     // uso por core
		"mem": map[string]float64{
			"used_gb":  float64(vm.Used) / 1024 / 1024 / 1024,
			"total_gb": float64(vm.Total) / 1024 / 1024 / 1024,
		},
		"disk": map[string]float64{
			"used_gb":  float64(du.Used) / 1024 / 1024 / 1024,
			"total_gb": float64(du.Total) / 1024 / 1024 / 1024,
		},
		"host": map[string]string{
			"uptime": formatUptime(hi.Uptime),
			"hwid":   hi.HostID,
			"os":     hi.OS,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}
func formatUptime(seconds uint64) string {
	d := time.Duration(seconds) * time.Second
	days := d / (24 * time.Hour)
	hours := (d % (24 * time.Hour)) / time.Hour
	minutes := (d % time.Hour) / time.Minute
	return fmt.Sprintf("%d dias, %02d:%02d", days, hours, minutes)
}
func (a *App) handleFlows(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		limitStr = "100"
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 10000 {
		http.Error(w, "invalid limit", http.StatusBadRequest)
		return
	}

	var results []types.Flow
	if err := a.conn.Select(ctx, &results, `SELECT * FROM flows ORDER BY TimeReceived DESC LIMIT ?`, limit); err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := types.HealthStatus{}
	if err := a.conn.Ping(r.Context()); err != nil {
		health.ClickHouse = "unhealthy"
		health.Status = "unhealthy"
	} else {
		health.ClickHouse = "healthy"
		health.Status = "healthy"
	}

	health.GoFlow2 = "healthy"
	health.FlowQueueLength = len(a.pipeline.FlowChannel())
	health.AlertQueueLength = a.detector.AlertsQueueLength()
	health.Uptime = time.Since(a.startTime).String()
	health.Goroutines = runtime.NumGoroutine()

	w.Header().Set("Content-Type", "application/json")
	if health.Status == "unhealthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(health)
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	snapshot := a.metricsSnapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"flows_processed": snapshot.FlowsProcessed,
		"flow_errors":     snapshot.FlowErrors,
		"snmp_errors":     snapshot.SnmpErrors,
		"active_flows":    snapshot.ActiveFlows,
		"queue_length":    snapshot.QueueLength,
		"interface_count": a.interfaceMap.Len(),
		"goroutines":      runtime.NumGoroutine(),
	})
}

func (a *App) handleManagement(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	w.Header().Set("Content-Type", "application/json")
	switch action {
	case "snmp-refresh":
		go snmp.UpdateWithRetry(a.interfaceMap, a.cfg, a.cfg.MaxRetries)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"message": "Atualização SNMP iniciada."})
	case "blocklist-refresh":
		go a.threats.UpdateBlocklist()
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"message": "Atualização da blocklist iniciada."})
	case "cache-clear":
		if a.resolver != nil {
			a.resolver.Clear()
		}
		if a.threats != nil {
			a.threats.ClearCache()
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Caches limpos."})
	default:
		http.Error(w, "ação desconhecida", http.StatusNotFound)
	}
}
