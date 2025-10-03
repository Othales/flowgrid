package collector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"flowgrid/internal/metrics"
	"flowgrid/internal/snmp"
	"flowgrid/pkg/types"
)

type AdaptiveSampler struct {
	mu           sync.Mutex
	config       types.AdaptiveSamplingConfig
	lastChange   time.Time
	currentRate  int
	targetSource *types.Source
}

func NewAdaptiveSampler(cfg *types.Config) *AdaptiveSampler {
	if !cfg.AdaptiveSampling.Enabled {
		return nil
	}

	var target *types.Source
	for i := range cfg.Sources {
		if cfg.Sources[i].Name == cfg.AdaptiveSampling.TargetRouter {
			target = &cfg.Sources[i]
			break
		}
	}

	if target == nil {
		log.Printf("AVISO: Amostragem adaptativa: roteador alvo '%s' não encontrado.", cfg.AdaptiveSampling.TargetRouter)
		return nil
	}

	if cfg.AdaptiveSampling.MinRate == 0 {
		cfg.AdaptiveSampling.MinRate = 100
	}

	return &AdaptiveSampler{
		config:       cfg.AdaptiveSampling,
		targetSource: target,
		currentRate:  cfg.AdaptiveSampling.MinRate,
	}
}

func (as *AdaptiveSampler) MonitorTask(ctx context.Context) {
	if as == nil || as.targetSource == nil || !as.config.Enabled {
		return
	}

	log.Printf("Monitor de amostragem adaptativa iniciado para %s (%s)",
		as.targetSource.Name, as.targetSource.Vendor)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	var lastFlowCount float64
	metricsProvider := metrics.Global()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			as.mu.Lock()
			current := float64(metricsProvider.Snapshot().FlowsProcessed)
			flowRate := current - lastFlowCount
			lastFlowCount = current

			log.Printf("Taxa de fluxo: %.0f FPM (Limite: %d FPM) - Vendor: %s",
				flowRate, as.config.ThresholdFPM, as.targetSource.Vendor)

			if time.Since(as.lastChange) < time.Duration(as.config.CooldownSeconds)*time.Second {
				as.mu.Unlock()
				continue
			}

			if flowRate > float64(as.config.ThresholdFPM) && as.currentRate < as.config.MaxRate {
				newRate := as.currentRate + as.config.IncrementStep
				if newRate > as.config.MaxRate {
					newRate = as.config.MaxRate
				}

				log.Printf("AMOSTRAGEM ADAPTATIVA: Tentando ajustar taxa para 1:%d (Vendor: %s)", newRate, as.targetSource.Vendor)
				if err := setSNMPSamplingRate(as.targetSource, as.config.SamplingRateOID, newRate); err != nil {
					log.Printf("ERRO ao ajustar amostragem: %v", err)
				} else {
					log.Printf("Sucesso! Nova taxa de amostragem: 1:%d", newRate)
					as.currentRate = newRate
					as.lastChange = time.Now()
				}
			}
			as.mu.Unlock()
		}
	}
}

func setSNMPSamplingRate(source *types.Source, oid string, rate int) error {
	if source.SNMP.Community == "" {
		return fmt.Errorf("comunidade SNMP de escrita não configurada para %s", source.Name)
	}

	samplingRateOID := oid
	if samplingRateOID == "" {
		samplingRateOID = snmp.SamplingRateOID(source.Vendor)
	}

	params := &gosnmp.GoSNMP{
		Target:    source.SNMP.IP,
		Port:      source.SNMP.Port,
		Community: source.SNMP.Community,
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
	}
	if err := params.Connect(); err != nil {
		return fmt.Errorf("falha ao conectar para SNMP SET: %v", err)
	}
	defer params.Conn.Close()

	pdu := gosnmp.SnmpPDU{
		Name:  samplingRateOID + ".1",
		Type:  gosnmp.Integer,
		Value: rate,
	}

	_, err := params.Set([]gosnmp.SnmpPDU{pdu})
	return err
}
