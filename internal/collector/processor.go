package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"flowgrid/internal/detection"
	"flowgrid/internal/enrichment"
	"flowgrid/internal/metrics"
	"flowgrid/internal/snmp"
	"flowgrid/pkg/types"
)

type Pipeline struct {
	cfg          *types.Config
	conn         clickhouse.Conn
	interfaceMap *snmp.InterfaceMap
	resolver     *enrichment.Resolver
	geo          *enrichment.GeoIPService
	threats      *enrichment.ThreatIntelService
	detector     *detection.Detector
	metrics      *metrics.Metrics
	flowChan     chan types.Flow
}

func NewPipeline(
	cfg *types.Config,
	conn clickhouse.Conn,
	interfaceMap *snmp.InterfaceMap,
	resolver *enrichment.Resolver,
	geo *enrichment.GeoIPService,
	threats *enrichment.ThreatIntelService,
	detector *detection.Detector,
) *Pipeline {
	return &Pipeline{
		cfg:          cfg,
		conn:         conn,
		interfaceMap: interfaceMap,
		resolver:     resolver,
		geo:          geo,
		threats:      threats,
		detector:     detector,
		metrics:      metrics.Global(),
		flowChan:     make(chan types.Flow, cfg.Performance.FlowQueueSize),
	}
}

func (p *Pipeline) FlowChannel() chan types.Flow {
	return p.flowChan
}

func (p *Pipeline) Start(ctx context.Context, reader io.Reader) {
	go p.processFlows(ctx, reader)
	go p.dbWriter(ctx)
}

func (p *Pipeline) processFlows(ctx context.Context, reader io.Reader) {
	decoder := json.NewDecoder(reader)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			var raw types.GoflowRecord
			if err := decoder.Decode(&raw); err != nil {
				if err != io.EOF {
					log.Printf("Erro ao decodificar JSON: %v", err)
					p.metrics.IncFlowErrors()
				} else {
					log.Println("goflow2 encerrou a saída.")
				}
				return
			}

			p.metrics.AddActiveFlows(1)
			flow := p.enrichFlow(raw)

			select {
			case p.flowChan <- flow:
				p.metrics.IncFlowsProcessed()
				p.metrics.SetQueueLength(int64(len(p.flowChan)))
			case <-ctx.Done():
				p.metrics.AddActiveFlows(-1)
				return
			}
			p.metrics.AddActiveFlows(-1)
		}
	}
}

func (p *Pipeline) enrichFlow(raw types.GoflowRecord) types.Flow {
	finalProto := raw.Proto
	if protoNum, err := strconv.Atoi(raw.Proto); err == nil {
		if protoName, ok := protocolMap[uint8(protoNum)]; ok {
			finalProto = protoName
		}
	}

	if raw.SamplingRate > 1 {
		raw.Bytes *= raw.SamplingRate
		raw.Packets *= raw.SamplingRate
	}

	duration := float64(raw.TimeFlowEndNS-raw.TimeFlowStartNS) / 1e9
	var bps, bpp uint64
	if duration > 0 {
		bps = uint64((float64(raw.Bytes) * 8) / duration)
	}
	if raw.Packets > 0 {
		bpp = raw.Bytes / raw.Packets
	}

	sourceName := snmp.FindSourceNameByIP(p.cfg, raw.SamplerAddress)
	flow := types.Flow{
		TimeReceived:   time.Unix(0, int64(raw.TimeReceivedNS)),
		TimeFlowStart:  time.Unix(0, int64(raw.TimeFlowStartNS)),
		TimeFlowEnd:    time.Unix(0, int64(raw.TimeFlowEndNS)),
		Duration:       duration,
		Bytes:          raw.Bytes,
		Packets:        raw.Packets,
		Bps:            bps,
		Bpp:            bpp,
		SrcAddr:        raw.SrcAddr,
		DstAddr:        raw.DstAddr,
		Etype:          raw.Etype,
		Proto:          finalProto,
		SrcPort:        uint16(raw.SrcPort),
		DstPort:        uint16(raw.DstPort),
		InIf:           raw.InIf,
		OutIf:          raw.OutIf,
		TCPFlags:       uint8(raw.TCPFlags),
		SrcAS:          raw.SrcAS,
		DstAS:          raw.DstAS,
		NextHop:        raw.NextHop,
		BGPCommunities: raw.BGPCommunities,
		ASPath:         raw.ASPath,
		SourceName:     sourceName,
	}

	if ifInfo, ok := p.interfaceMap.GetInterface(sourceName, raw.InIf); ok {
		flow.InIfName = ifInfo.Name
		flow.InIfDesc = ifInfo.Desc
	}

	if ifInfo, ok := p.interfaceMap.GetInterface(sourceName, raw.OutIf); ok {
		flow.OutIfName = ifInfo.Name
		flow.OutIfDesc = ifInfo.Desc
	}

	if sourceInfo, exists := p.interfaceMap.GetSource(sourceName); exists {
		flow.Vendor = sourceInfo.Vendor
	} else {
		flow.Vendor = "Unknown"
	}

	if p.resolver != nil {
		flow.SrcHostname = p.resolver.Lookup(raw.SrcAddr)
		flow.DstHostname = p.resolver.Lookup(raw.DstAddr)
	}

	if p.geo != nil {
		p.geo.Enrich(&flow)
	}

	if p.threats != nil {
		flow.ThreatInfo = p.threats.Check(raw.DstAddr)
	}

	if p.detector != nil {
		p.detector.CheckFlow(flow, raw.SamplerAddress)
	}

	return flow
}

func (p *Pipeline) dbWriter(ctx context.Context) {
	batch := make([]types.Flow, 0, p.cfg.BatchSize)
	ticker := time.NewTicker(time.Duration(p.cfg.BatchTimeout) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				p.insertBatchWithRetry(ctx, batch)
			}
			return
		case flow, ok := <-p.flowChan:
			if !ok {
				if len(batch) > 0 {
					p.insertBatchWithRetry(ctx, batch)
				}
				return
			}
			batch = append(batch, flow)
			if len(batch) >= p.cfg.BatchSize {
				p.insertBatchWithRetry(ctx, batch)
				batch = make([]types.Flow, 0, p.cfg.BatchSize)
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.insertBatchWithRetry(ctx, batch)
				batch = make([]types.Flow, 0, p.cfg.BatchSize)
			}
		}
	}
}

func (p *Pipeline) insertBatch(ctx context.Context, flows []types.Flow) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for i := range flows {
		b, _ := json.Marshal(flows[i].ThreatInfo)
		flows[i].ThreatInfoJSON = string(b)
	}

	batch, err := p.conn.PrepareBatch(ctx, "INSERT INTO flows")
	if err != nil {
		return fmt.Errorf("erro ao preparar lote: %w", err)
	}
	for _, flow := range flows {
		if err := batch.AppendStruct(&flow); err != nil {
			return fmt.Errorf("erro ao adicionar flow ao lote: %w", err)
		}
	}
	return batch.Send()
}

func (p *Pipeline) insertBatchWithRetry(ctx context.Context, flows []types.Flow) {
	for i := 0; i < p.cfg.MaxRetries; i++ {
		if err := p.insertBatch(ctx, flows); err == nil {
			log.Printf("Lote de %d flows inserido com sucesso.", len(flows))
			return
		} else {
			log.Printf("Tentativa %d/%d de inserção falhou: %v", i+1, p.cfg.MaxRetries, err)
		}
		time.Sleep(time.Duration(i) * time.Second)
	}
	log.Printf("Falha definitiva: descartando %d flows", len(flows))
	p.metrics.AddFlowErrors(uint64(len(flows)))
}

var protocolMap = map[uint8]string{
	0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP",
	10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP",
	18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1",
	26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP",
	34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP",
	43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP", 51: "AH",
	52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "Min-IPv4", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
	60: "IPv6-Opts", 62: "CFTP", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 69: "SAT-MON", 70: "VISA",
	71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON",
	79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "IPTM", 85: "NSFNET-IGP", 86: "DGP",
	87: "TCF", 88: "EIGRP", 89: "OSPFIGP", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "IPIP",
	95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM",
	104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP",
	112: "VRRP", 113: "PGM", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP",
	122: "SM", 123: "PTP", 124: "ISIS over IPv4", 125: "FIRE", 126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT",
	130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite",
	137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC", 143: "Ethernet",
	144: "AGGFRAG", 145: "NSH", 255: "Reserved",
}
