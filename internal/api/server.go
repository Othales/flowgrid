package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"flowgrid/internal/collector"
	"flowgrid/internal/config"
	"flowgrid/internal/database"
	"flowgrid/internal/detection"
	"flowgrid/internal/enrichment"
	"flowgrid/internal/metrics"
	"flowgrid/internal/snmp"
	"flowgrid/internal/storage"
	"flowgrid/pkg/types"
	"flowgrid/pkg/utils"
)

type App struct {
	cfg            *types.Config
	conn           clickhouse.Conn
	interfaceMap   *snmp.InterfaceMap
	interfacesPath string
	pipeline       *collector.Pipeline
	detector       *detection.Detector
	resolver       *enrichment.Resolver
	geo            *enrichment.GeoIPService
	threats        *enrichment.ThreatIntelService
	backup         *storage.BackupManager
	sampler        *collector.AdaptiveSampler
	startTime      time.Time
	configMux      sync.RWMutex
	configPath     string
	alertRules     []types.AlertRule
	alertPath      string
	whitelist      *types.Whitelist
	whitelistPath  string
	peersMux       sync.RWMutex
	peersCache     map[string][]types.BGPNeighbor
	peersPath      string
}

func Run(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	cfgPath := "configs/config.json"
	alertsPath := "configs/alert_rules.json"
	whitelistPath := "configs/whitelist.json"

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	rules, err := config.LoadAlertRules(alertsPath)
	if err != nil {
		return err
	}

	whitelist, err := config.LoadWhitelist(whitelistPath)
	if err != nil {
		log.Printf("AVISO: Falha ao carregar whitelist: %v", err)
	}

	conn, err := database.Connect(ctx, cfg)
	if err != nil {
		return err
	}

	if err := database.EnsureTables(conn); err != nil {
		return err
	}

	interfacePath := "interfaces.json"
	interfaceMap := snmp.NewInterfaceMap()
	if err := interfaceMap.LoadFromFile(interfacePath); err != nil {
		return err
	}

	peersPath := "peers.json"
	peersCache := make(map[string][]types.BGPNeighbor)
	if data, err := os.ReadFile(peersPath); err == nil {
		if err := json.Unmarshal(data, &peersCache); err != nil {
			log.Printf("AVISO: falha ao carregar peers salvos (%s): %v", peersPath, err)
			peersCache = make(map[string][]types.BGPNeighbor)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	detector := detection.NewDetector(rules, conn, cfg.LocalNetworks, cfg.Performance.AlertQueueSize)
	detector.StartAlertWriter(ctx)
	go detector.CleanupTask(ctx)

	geoService := enrichment.NewGeoIPService(cfg.GeoIPEnabled)
	resolver := enrichment.NewResolver(utils.NewCircuitBreaker(
		cfg.CircuitBreaker.MaxFailures,
		time.Duration(cfg.CircuitBreaker.ResetTimeout)*time.Second,
	))
	threatService := enrichment.NewThreatIntelService()
	threatService.UpdateBlocklist()

	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				threatService.UpdateBlocklist()
			}
		}
	}()

	pipeline := collector.NewPipeline(cfg, conn, interfaceMap, resolver, geoService, threatService, detector)
	backupManager := storage.NewBackupManager("./backups", 30)

	go backupManager.StartScheduler(ctx)
	go snmp.UpdateWithRetry(interfaceMap, cfg, cfg.MaxRetries)
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.UpdateInterval) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snmp.UpdateWithRetry(interfaceMap, cfg, cfg.MaxRetries)
			}
		}
	}()

	sampler := collector.NewAdaptiveSampler(cfg)
	if sampler != nil {
		go sampler.MonitorTask(ctx)
	}

	cmd, stdout, stderr, err := collector.StartGoflow(ctx, cfg.NetFlowPort)
	if err != nil {
		return err
	}
	go collector.LogGoflowErrors(stderr)

	pipeline.Start(ctx, stdout)

	app := &App{
		cfg:            cfg,
		conn:           conn,
		interfaceMap:   interfaceMap,
		interfacesPath: interfacePath,
		pipeline:       pipeline,
		detector:       detector,
		resolver:       resolver,
		geo:            geoService,
		threats:        threatService,
		backup:         backupManager,
		sampler:        sampler,
		startTime:      time.Now(),
		configPath:     cfgPath,
		alertRules:     rules,
		alertPath:      alertsPath,
		whitelist:      whitelist,
		whitelistPath:  whitelistPath,
		peersCache:     peersCache,
		peersPath:      peersPath,
	}

	server := app.startHTTPServer()

	go collector.WaitForShutdown(cancel, server, cmd)

	<-ctx.Done()
	geoService.Close()
	close(pipeline.FlowChannel())
	return nil
}

func (a *App) metricsSnapshot() metrics.Snapshot {
	return metrics.Global().Snapshot()
}

func (a *App) saveConfig() error {
	data, err := json.MarshalIndent(a.cfg, "", "  ")
	if err != nil {
		return err
	}
	if a.configPath == "" {
		a.configPath = "configs/config.json"
	}
	return os.WriteFile(a.configPath, data, 0644)
}
