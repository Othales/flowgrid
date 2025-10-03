package types

import "time"

type SNMPConfig struct {
	IP        string `json:"ip"`
	Version   string `json:"version"`
	Port      uint16 `json:"port"`
	Community string `json:"community"`
	User      string `json:"user,omitempty"`
	Auth      string `json:"auth,omitempty"`
	AuthPass  string `json:"authpass,omitempty"`
	Priv      string `json:"priv,omitempty"`
	PrivPass  string `json:"privpass,omitempty"`
}

type Source struct {
	Name   string     `json:"name"`
	Vendor string     `json:"vendor"`
	SNMP   SNMPConfig `json:"snmp"`
}

type CircuitBreakerConfig struct {
	MaxFailures  int `json:"max_failures"`
	ResetTimeout int `json:"reset_timeout_seconds"`
}

type AdaptiveSamplingConfig struct {
	Enabled         bool   `json:"enabled"`
	TargetRouter    string `json:"target_router_name"`
	SamplingRateOID string `json:"sampling_rate_oid"`
	ThresholdFPM    int64  `json:"threshold_fpm"`
	CooldownSeconds int    `json:"cooldown_seconds"`
	MinRate         int    `json:"min_rate"`
	MaxRate         int    `json:"max_rate"`
	IncrementStep   int    `json:"increment_step"`
}

type PerformanceConfig struct {
	MaxGoroutines         int `json:"max_goroutines"`
	FlowQueueSize         int `json:"flow_queue_size"`
	AlertQueueSize        int `json:"alert_queue_size"`
	MaxOpenConnections    int `json:"max_open_connections"`
	MaxIdleConnections    int `json:"max_idle_connections"`
	ConnectionMaxLifetime int `json:"connection_max_lifetime_minutes"`
}

type TelegramConfig struct {
	Enabled      bool     `json:"enabled"`
	BotToken     string   `json:"bot_token"`
	ChatIDs      []string `json:"chat_ids"`
	ReplyIDs     []string `json:"reply_ids"`
	NotifyAlerts bool     `json:"notify_alerts"`
	NotifySystem bool     `json:"notify_system"`
	Proxy        string   `json:"proxy"`
}

type EmailConfig struct {
	Enabled  bool     `json:"enabled"`
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	ReplyTo  []string `json:"reply_to"`
	UseTLS   bool     `json:"use_tls"`
	StartTLS bool     `json:"start_tls"`
}

type NotificationConfig struct {
	Telegram TelegramConfig `json:"telegram"`
	Email    EmailConfig    `json:"email"`
}

type FirewallConfig struct {
	NetFlowAllowed  []string `json:"netflow_allowed"`
	SflowAllowed    []string `json:"sflow_allowed"`
	APIAllowed      []string `json:"api_allowed"`
	InterfaceExport []string `json:"interface_export"`
}

type Config struct {
	Sources          []Source               `json:"sources"`
	LocalNetworks    []string               `json:"local_networks"`
	UpdateInterval   int                    `json:"update_interval_minutes"`
	BatchSize        int                    `json:"batch_size"`
	BatchTimeout     int                    `json:"batch_timeout_seconds"`
	GeoIPEnabled     bool                   `json:"geoip_enabled"`
	SNMPEnabled      bool                   `json:"snmp_enabled"`
	HTTPPort         int                    `json:"http_port"`
	NetFlowPort      int                    `json:"netflow_port"`
	SflowPort        int                    `json:"sflow_port"`
	ClickHouseDSN    string                 `json:"clickhouse_dsn"`
	MaxRetries       int                    `json:"max_retries"`
	CircuitBreaker   CircuitBreakerConfig   `json:"circuit_breaker"`
	ClickHouseAddr   string                 `json:"clickhouse_addr"`
	AdaptiveSampling AdaptiveSamplingConfig `json:"adaptive_sampling"`
	Performance      PerformanceConfig      `json:"performance"`
	// NOVOS
	DataPath            string             `json:"data_path"`
	ClickhouseCleanTime int                `json:"clickhouse_clean_time"`
	Password            string             `json:"password"`
	MaximumDiskGB       int                `json:"maximum_disk_gb"`
	APINetwork          []string           `json:"api_network"`
	InternalIPBlocks    []string           `json:"internal_ip_blocks"`
	InternalASNs        []uint32           `json:"internal_asns"`
	FavoriteIPs         []string           `json:"favorite_ips"`
	FavoriteASNs        []uint32           `json:"favorite_asns"`
	IgnoredIPs          []string           `json:"ignored_ips"`
	IgnoredASNs         []uint32           `json:"ignored_asns"`
	FavoriteServices    []string           `json:"favorite_services"`
	Notification        NotificationConfig `json:"notification"`
	Firewall            FirewallConfig     `json:"firewall"`
}

type Whitelist struct {
	IPs   []string `json:"ips"`
	CIDRs []string `json:"cidrs"`
}

type AlertRule struct {
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Filter            string   `json:"filter"`
	Condition         string   `json:"condition"`
	TimeWindowSeconds int64    `json:"time_window_seconds"`
	Actions           []string `json:"actions"`
	Comment           string   `json:"comment,omitempty"`
}

type GoflowRecord struct {
	Type                       string   `json:"type"`
	TimeReceivedNS             uint64   `json:"time_received_ns"`
	SequenceNum                uint32   `json:"sequence_num"`
	SamplingRate               uint64   `json:"sampling_rate"`
	SamplerAddress             string   `json:"sampler_address"`
	TimeFlowStartNS            uint64   `json:"time_flow_start_ns"`
	TimeFlowEndNS              uint64   `json:"time_flow_end_ns"`
	Bytes                      uint64   `json:"bytes"`
	Packets                    uint64   `json:"packets"`
	SrcAddr                    string   `json:"src_addr"`
	DstAddr                    string   `json:"dst_addr"`
	Etype                      string   `json:"etype"`
	Proto                      string   `json:"proto"`
	SrcPort                    uint32   `json:"src_port"`
	DstPort                    uint32   `json:"dst_port"`
	InIf                       uint32   `json:"in_if"`
	OutIf                      uint32   `json:"out_if"`
	SrcMac                     string   `json:"src_mac"`
	DstMac                     string   `json:"dst_mac"`
	SrcVlan                    uint32   `json:"src_vlan"`
	DstVlan                    uint32   `json:"dst_vlan"`
	VlanID                     uint32   `json:"vlan_id"`
	IPTos                      uint32   `json:"ip_tos"`
	ForwardingStatus           uint32   `json:"forwarding_status"`
	IPTTL                      uint32   `json:"ip_ttl"`
	TCPFlags                   uint32   `json:"tcp_flags"`
	ICMPType                   uint32   `json:"icmp_type"`
	ICMPCode                   uint32   `json:"icmp_code"`
	IPv6FlowLabel              uint32   `json:"ipv6_flow_label"`
	FragmentID                 uint32   `json:"fragment_id"`
	FragmentOffset             uint32   `json:"fragment_offset"`
	SrcAS                      uint32   `json:"src_as"`
	DstAS                      uint32   `json:"dst_as"`
	NextHop                    string   `json:"next_hop"`
	NextHopAS                  uint32   `json:"next_hop_as"`
	SrcNet                     string   `json:"src_net"`
	DstNet                     string   `json:"dst_net"`
	BGPNexthop                 string   `json:"bgp_next_hop"`
	BGPCommunities             []uint32 `json:"bgp_communities"`
	ASPath                     []uint32 `json:"as_path"`
	MPLSLabel                  []uint32 `json:"mpls_label"`
	MPLSIP                     []string `json:"mpls_ip"`
	ObservationDomainID        uint32   `json:"observation_domain_id"`
	ObservationPointID         uint64   `json:"observation_point_id"`
	IPv6RoutingHeaderAddresses []string `json:"ipv6_routing_header_addresses"`
	IPv6RoutingHeaderSegLeft   uint32   `json:"ipv6_routing_header_seg_left"`
}

type ThreatIntel struct {
	IsMalicious bool     `json:"is_malicious"`
	ThreatTypes []string `json:"threat_types,omitempty"`
	Confidence  float64  `json:"confidence"`
	LastUpdated int64    `json:"last_updated"`
}

type Flow struct {
	TimeReceived     time.Time   `json:"time_received" ch:"TimeReceived"`
	TimeFlowStart    time.Time   `json:"time_flow_start" ch:"TimeFlowStart"`
	TimeFlowEnd      time.Time   `json:"time_flow_end" ch:"TimeFlowEnd"`
	Duration         float64     `json:"duration" ch:"Duration"`
	Bytes            uint64      `json:"bytes" ch:"Bytes"`
	Packets          uint64      `json:"packets" ch:"Packets"`
	Bps              uint64      `json:"bps" ch:"Bps"`
	Bpp              uint64      `json:"bpp" ch:"Bpp"`
	SrcAddr          string      `json:"src_addr" ch:"SrcAddr"`
	DstAddr          string      `json:"dst_addr" ch:"DstAddr"`
	SrcHostname      string      `json:"src_hostname,omitempty" ch:"SrcHostname"`
	DstHostname      string      `json:"dst_hostname,omitempty" ch:"DstHostname"`
	Etype            string      `json:"etype" ch:"Etype"`
	Proto            string      `json:"proto" ch:"Proto"`
	SrcPort          uint16      `json:"src_port" ch:"SrcPort"`
	DstPort          uint16      `json:"dst_port" ch:"DstPort"`
	InIf             uint32      `json:"in_if" ch:"InIf"`
	OutIf            uint32      `json:"out_if" ch:"OutIf"`
	InIfName         string      `json:"in_if_name,omitempty" ch:"InIfName"`
	InIfDesc         string      `json:"in_if_desc,omitempty" ch:"InIfDesc"`
	OutIfName        string      `json:"out_if_name,omitempty" ch:"OutIfName"`
	OutIfDesc        string      `json:"out_if_desc,omitempty" ch:"OutIfDesc"`
	SrcMac           string      `json:"src_mac" ch:"SrcMac"`
	DstMac           string      `json:"dst_mac" ch:"DstMac"`
	SrcVlan          uint32      `json:"src_vlan" ch:"SrcVlan"`
	DstVlan          uint32      `json:"dst_vlan" ch:"DstVlan"`
	IPTos            uint8       `json:"ip_tos" ch:"IPTos"`
	ForwardingStatus uint8       `json:"forwarding_status" ch:"ForwardingStatus"`
	IPTTL            uint8       `json:"ip_ttl" ch:"IPTTL"`
	TCPFlags         uint8       `json:"tcp_flags" ch:"TCPFlags"`
	SrcAS            uint32      `json:"src_as" ch:"SrcAS"`
	DstAS            uint32      `json:"dst_as" ch:"DstAS"`
	NextHop          string      `json:"next_hop" ch:"NextHop"`
	BGPCommunities   []uint32    `json:"bgp_communities" ch:"BGPCommunities"`
	ASPath           []uint32    `json:"as_path" ch:"ASPath"`
	SrcCountry       string      `json:"src_country,omitempty" ch:"SrcCountry"`
	SrcCity          string      `json:"src_city,omitempty" ch:"SrcCity"`
	DstCountry       string      `json:"dst_country,omitempty" ch:"DstCountry"`
	DstCity          string      `json:"dst_city,omitempty" ch:"DstCity"`
	ASN              uint32      `json:"asn,omitempty" ch:"ASN"`
	Vendor           string      `json:"vendor,omitempty" ch:"Vendor"`
	SourceName       string      `json:"source_name" ch:"SourceName"`
	ThreatInfo       ThreatIntel `json:"-" ch:"-"`
	ThreatInfoJSON   string      `json:"threat_info,omitempty" ch:"ThreatInfo"`
}

type Alert struct {
	Timestamp     time.Time `json:"timestamp" ch:"Timestamp"`
	RuleName      string    `json:"rule_name" ch:"RuleName"`
	Condition     string    `json:"condition" ch:"Condition"`
	SourceIP      string    `json:"source_ip" ch:"SourceIP"`
	DestinationIP string    `json:"destination_ip" ch:"DestinationIP"`
	Vendor        string    `json:"vendor" ch:"Vendor"`
	SourceName    string    `json:"source_name" ch:"SourceName"`
	Metadata      string    `json:"metadata" ch:"Metadata"`
}

type HealthStatus struct {
	Status           string `json:"status"`
	ClickHouse       string `json:"clickhouse"`
	GoFlow2          string `json:"goflow2"`
	FlowQueueLength  int    `json:"flow_queue_length"`
	AlertQueueLength int    `json:"alert_queue_length"`
	Uptime           string `json:"uptime"`
	Goroutines       int    `json:"goroutines"`
}

type DashboardStats struct {
	TotalFlows      uint64        `json:"total_flows"`
	TotalBytes      uint64        `json:"total_bytes"`
	TotalPackets    uint64        `json:"total_packets"`
	CurrentBPS      float64       `json:"current_bps"`
	TopSources      []SourceStats `json:"top_sources"`
	TopApplications []AppStats    `json:"top_applications"`
	ThreatsBlocked  uint64        `json:"threats_blocked"`
	AlertsLast24h   uint64        `json:"alerts_last_24h"`
}

type SourceStats struct {
	SourceName   string  `json:"source_name"`
	Vendor       string  `json:"vendor"`
	FlowCount    uint64  `json:"flow_count"`
	TotalBytes   uint64  `json:"total_bytes"`
	TotalPackets uint64  `json:"total_packets"`
	Percentage   float64 `json:"percentage"`
	AvgBps       float64 `json:"avg_bps"`
	PeakBps      float64 `json:"peak_bps"`
	LastActive   string  `json:"last_active"`
}

type BGPNeighbor struct {
	SourceName     string `json:"source_name"`
	Vendor         string `json:"vendor"`
	PeerIP         string `json:"peer_ip"`
	RemoteAS       uint32 `json:"remote_as,omitempty"`
	State          string `json:"state"`
	AdminStatus    string `json:"admin_status"`
	EstablishedFor string `json:"established_for,omitempty"`
	InputMessages  uint64 `json:"input_messages,omitempty"`
	OutputMessages uint64 `json:"output_messages,omitempty"`
}

type AppStats struct {
	Protocol   string `json:"protocol"`
	Port       uint16 `json:"port"`
	FlowCount  uint64 `json:"flow_count"`
	TotalBytes uint64 `json:"total_bytes"`
}

type TimeSeriesPoint struct {
	Time  string  `json:"time"`
	Value float64 `json:"value"`
}
