package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"flowgrid/pkg/types"
)

type ruleTracker struct {
	Bytes        uint64
	Packets      uint64
	FlowCount    int64
	FirstSeen    time.Time
	LastSeen     time.Time
	AlertedAt    time.Time
	UniqueSrcIPs map[string]struct{}
}

type FilterCache struct {
	mu    sync.RWMutex
	cache map[string]*vm.Program
}

func NewFilterCache() *FilterCache {
	return &FilterCache{cache: make(map[string]*vm.Program)}
}

func (fc *FilterCache) Get(filter string) (*vm.Program, error) {
	fc.mu.RLock()
	program, exists := fc.cache[filter]
	fc.mu.RUnlock()
	if exists {
		return program, nil
	}

	compiled, err := expr.Compile(filter)
	if err != nil {
		return nil, fmt.Errorf("erro ao compilar filtro '%s': %w", filter, err)
	}

	fc.mu.Lock()
	fc.cache[filter] = compiled
	fc.mu.Unlock()
	return compiled, nil
}

type Detector struct {
	mu             sync.Mutex
	rules          []types.AlertRule
	trackers       map[string]map[string]*ruleTracker
	dbConn         clickhouse.Conn
	localNetworks  []*net.IPNet
	filterCache    *FilterCache
	conditionCache *FilterCache
	alerts         chan types.Alert
}

func NewDetector(rules []types.AlertRule, conn clickhouse.Conn, localNetworks []string, queueSize int) *Detector {
	var nets []*net.IPNet
	for _, cidr := range localNetworks {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, network)
		}
	}

	if queueSize <= 0 {
		queueSize = 1000
	}

	return &Detector{
		rules:          rules,
		trackers:       make(map[string]map[string]*ruleTracker),
		dbConn:         conn,
		localNetworks:  nets,
		filterCache:    NewFilterCache(),
		conditionCache: NewFilterCache(),
		alerts:         make(chan types.Alert, queueSize),
	}
}

func (d *Detector) AlertsQueueLength() int {
	return len(d.alerts)
}

func (d *Detector) UpdateRules(rules []types.AlertRule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rules = rules
	d.filterCache = NewFilterCache()
	d.conditionCache = NewFilterCache()
	d.trackers = make(map[string]map[string]*ruleTracker)
}

func (d *Detector) UpdateLocalNetworks(networks []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var nets []*net.IPNet
	for _, cidr := range networks {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, network)
		}
	}
	d.localNetworks = nets
}

func (d *Detector) CheckFlow(flow types.Flow, samplerAddress string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, rule := range d.rules {
		if !rule.Enabled {
			continue
		}

		program, err := d.filterCache.Get(rule.Filter)
		if err != nil {
			log.Printf("Erro ao compilar filtro da regra '%s': %v", rule.Name, err)
			continue
		}

		env := d.createFlowEnv(flow, samplerAddress)
		result, err := expr.Run(program, env)
		if err != nil {
			log.Printf("Erro ao executar filtro da regra '%s': %v", rule.Name, err)
			continue
		}

		match, ok := result.(bool)
		if !ok || !match {
			continue
		}

		trackerKey := flow.DstAddr
		if rule.TimeWindowSeconds == 0 {
			rule.TimeWindowSeconds = 60
		}

		if d.trackers[rule.Name] == nil {
			d.trackers[rule.Name] = make(map[string]*ruleTracker)
		}

		tracker, exists := d.trackers[rule.Name][trackerKey]
		if !exists {
			tracker = &ruleTracker{
				UniqueSrcIPs: make(map[string]struct{}),
				FirstSeen:    time.Now(),
			}
			d.trackers[rule.Name][trackerKey] = tracker
		}

		tracker.Bytes += flow.Bytes
		tracker.Packets += flow.Packets
		tracker.FlowCount++
		tracker.LastSeen = time.Now()
		tracker.UniqueSrcIPs[flow.SrcAddr] = struct{}{}

		if time.Since(tracker.FirstSeen) > time.Duration(rule.TimeWindowSeconds)*time.Second {
			d.evaluateRule(rule, flow, tracker)
		}
	}
}

func (d *Detector) createFlowEnv(flow types.Flow, samplerAddress string) map[string]interface{} {
	srcIP := net.ParseIP(flow.SrcAddr)
	dstIP := net.ParseIP(flow.DstAddr)

	flowDirection := ""
	isSrcLocal, isDstLocal := false, false
	for _, network := range d.localNetworks {
		if srcIP != nil && network.Contains(srcIP) {
			isSrcLocal = true
		}
		if dstIP != nil && network.Contains(dstIP) {
			isDstLocal = true
		}
	}

	if isDstLocal && !isSrcLocal {
		flowDirection = "inbound"
	}
	if isSrcLocal && !isDstLocal {
		flowDirection = "outbound"
	}

	return map[string]interface{}{
		"Bytes":          flow.Bytes,
		"Packets":        flow.Packets,
		"Bps":            flow.Bps,
		"Bpp":            flow.Bpp,
		"SrcAddr":        flow.SrcAddr,
		"DstAddr":        flow.DstAddr,
		"Proto":          flow.Proto,
		"SrcPort":        flow.SrcPort,
		"DstPort":        flow.DstPort,
		"TCPFlags":       flow.TCPFlags,
		"SrcAS":          flow.SrcAS,
		"DstAS":          flow.DstAS,
		"SrcCountry":     flow.SrcCountry,
		"DstCountry":     flow.DstCountry,
		"SamplerAddress": samplerAddress,
		"Direction":      flowDirection,
		"Vendor":         flow.Vendor,
	}
}

func (d *Detector) evaluateRule(rule types.AlertRule, flow types.Flow, tracker *ruleTracker) {
	now := time.Now()
	if now.Sub(tracker.AlertedAt) < 5*time.Minute {
		return
	}

	conditionProgram, err := d.conditionCache.Get(rule.Condition)
	if err != nil {
		log.Printf("AVISO: Pulando condição da regra '%s' devido a erro: %v", rule.Name, err)
		return
	}

	env := d.createTrackerEnv(tracker)
	conditionResult, err := expr.Run(conditionProgram, env)
	if err != nil {
		log.Printf("AVISO: Erro ao executar condição para a regra '%s': %v", rule.Name, err)
		return
	}

	if match, ok := conditionResult.(bool); ok && match {
		tracker.AlertedAt = now
		d.triggerAlert(rule, flow, env)
	}
}

func (d *Detector) createTrackerEnv(tracker *ruleTracker) map[string]interface{} {
	duration := tracker.LastSeen.Sub(tracker.FirstSeen).Seconds()
	if duration < 1 {
		duration = 1
	}
	bpp := uint64(0)
	if tracker.Packets > 0 {
		bpp = uint64(float64(tracker.Bytes) / float64(tracker.Packets))
	}
	return map[string]interface{}{
		"Bps":          uint64((float64(tracker.Bytes) * 8) / duration),
		"Pps":          uint64(float64(tracker.Packets) / duration),
		"Bpp":          bpp,
		"Bytes":        tracker.Bytes,
		"Packets":      tracker.Packets,
		"FlowCount":    tracker.FlowCount,
		"UniqueSrcIPs": len(tracker.UniqueSrcIPs),
	}
}

func (d *Detector) triggerAlert(rule types.AlertRule, flow types.Flow, trackerEnv map[string]interface{}) {
	metadataBytes, _ := json.Marshal(trackerEnv)

	alert := types.Alert{
		Timestamp:     time.Now(),
		RuleName:      rule.Name,
		Condition:     rule.Condition,
		SourceIP:      flow.SrcAddr,
		DestinationIP: flow.DstAddr,
		Vendor:        flow.Vendor,
		SourceName:    flow.SourceName,
		Metadata:      string(metadataBytes),
	}

	for _, action := range rule.Actions {
		switch action {
		case "log":
			log.Printf("[ALERTA] Regra '%s' disparada para o destino %s (Source: %s, Vendor: %s). Condição: '%s'. Dados: %s",
				alert.RuleName, alert.DestinationIP, alert.SourceName, alert.Vendor, alert.Condition, alert.Metadata)
		case "database":
			d.SaveAlert(context.Background(), alert)
		case "webhook":
			go sendWebhook(alert)
		case "block":
			go executeBlockScript(alert.SourceIP, alert.Vendor, alert.SourceName)
		}
	}
}

func (d *Detector) CleanupTask(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for ruleName, dstTrackers := range d.trackers {
				for dstAddr, tracker := range dstTrackers {
					if now.Sub(tracker.LastSeen) > 10*time.Minute {
						delete(dstTrackers, dstAddr)
					}
				}
				if len(dstTrackers) == 0 {
					delete(d.trackers, ruleName)
				}
			}
			d.mu.Unlock()
		}
	}
}

func (d *Detector) StartAlertWriter(ctx context.Context) {
	go d.alertWriter(ctx)
}

func (d *Detector) alertWriter(ctx context.Context) {
	batchSize := 100
	batch := make([]types.Alert, 0, batchSize)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				d.insertAlertBatch(ctx, batch)
			}
			return
		case alert, ok := <-d.alerts:
			if !ok {
				if len(batch) > 0 {
					d.insertAlertBatch(ctx, batch)
				}
				return
			}
			batch = append(batch, alert)
			if len(batch) >= batchSize {
				d.insertAlertBatch(ctx, batch)
				batch = make([]types.Alert, 0, batchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				d.insertAlertBatch(ctx, batch)
				batch = make([]types.Alert, 0, batchSize)
			}
		}
	}
}

func (d *Detector) insertAlertBatch(ctx context.Context, alerts []types.Alert) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	batch, err := d.dbConn.PrepareBatch(ctx, "INSERT INTO alerts")
	if err != nil {
		log.Printf("ERRO ao preparar lote de alertas: %v", err)
		return
	}

	for _, alert := range alerts {
		if err := batch.AppendStruct(&alert); err != nil {
			log.Printf("ERRO ao adicionar alerta ao lote: %v", err)
		}
	}

	if err := batch.Send(); err != nil {
		log.Printf("ERRO ao enviar lote de %d alertas: %v", len(alerts), err)
	}
}

func (d *Detector) SaveAlert(ctx context.Context, alert types.Alert) {
	select {
	case d.alerts <- alert:
	case <-ctx.Done():
		log.Println("Context cancelado, não foi possível enfileirar o alerta.")
	default:
		log.Printf("AVISO: O canal de alertas está cheio. Descartando o alerta para o IP %s", alert.SourceIP)
	}
}

func sendWebhook(alert types.Alert) {
	webhookURL := os.Getenv("WEBHOOK_URL")
	if webhookURL == "" {
		return
	}

	payloadMap := map[string]interface{}{
		"rule":         alert.RuleName,
		"source_ip":    alert.SourceIP,
		"destination":  alert.DestinationIP,
		"vendor":       alert.Vendor,
		"source_name":  alert.SourceName,
		"metadata":     alert.Metadata,
		"trigger_time": alert.Timestamp.Format(time.RFC3339),
	}

	payloadBytes, _ := json.Marshal(payloadMap)
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("Erro ao criar requisição de webhook: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Erro ao enviar webhook: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		log.Printf("Webhook retornou status %d", resp.StatusCode)
	}
}

func executeBlockScript(ip, vendor, sourceName string) {
	scriptPath := os.Getenv("BLOCK_SCRIPT_PATH")
	if scriptPath == "" {
		log.Printf("AVISO: BLOCK_SCRIPT_PATH não configurado. Bloqueio ignorado para %s", ip)
		return
	}

	vendorScript := fmt.Sprintf("%s_%s", scriptPath, strings.ToLower(vendor))
	if _, err := os.Stat(vendorScript); err == nil {
		scriptPath = vendorScript
	}

	log.Printf("EXECUTANDO SCRIPT DE BLOQUEIO '%s' PARA O IP: %s (Source: %s, Vendor: %s)",
		scriptPath, ip, sourceName, vendor)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, scriptPath, ip, vendor, sourceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ERRO ao executar script de bloqueio para %s (Source: %s, Vendor: %s): %v. Saída: %s",
			ip, sourceName, vendor, err, string(output))
	} else {
		log.Printf("Script de bloqueio para %s (Source: %s, Vendor: %s) executado com sucesso.",
			ip, sourceName, vendor)
	}
}
