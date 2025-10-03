package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"flowgrid/pkg/types"
)

func Connect(ctx context.Context, cfg *types.Config) (clickhouse.Conn, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.ClickHouseAddr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: os.Getenv("CLICKHOUSE_USER"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		DialTimeout:     10 * time.Second,
		MaxOpenConns:    cfg.Performance.MaxOpenConnections,
		MaxIdleConns:    cfg.Performance.MaxIdleConnections,
		ConnMaxLifetime: time.Duration(cfg.Performance.ConnectionMaxLifetime) * time.Minute,
		Compression:     &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		return nil, fmt.Errorf("falha ao conectar no ClickHouse: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping no ClickHouse falhou: %w", err)
	}

	return conn, nil
}

func EnsureTables(conn clickhouse.Conn) error {
	ctx := context.Background()

	ddlFlows := `
    CREATE TABLE IF NOT EXISTS default.flows (
            TimeReceived     DateTime64(9),
            TimeFlowStart    DateTime64(9),
            TimeFlowEnd      DateTime64(9),
            Duration         Float64,
            Bytes            UInt64,
            Packets          UInt64,
            Bps              UInt64,
            Bpp              UInt64,
            SrcAddr          IPv6,
            DstAddr          IPv6,
            SrcHostname      String,
            DstHostname      String,
            Etype            String,
            Proto            String,
            SrcPort          UInt16,
            DstPort          UInt16,
            InIf             UInt32,
            OutIf            UInt32,
            InIfName         String,
            InIfDesc         String,
            OutIfName        String,
            OutIfDesc        String,
            SrcMac           String,
            DstMac           String,
            SrcVlan          UInt32,
            DstVlan          UInt32,
            IPTos            UInt8,
            ForwardingStatus UInt8,
            IPTTL            UInt8,
            TCPFlags         UInt8,
            SrcAS            UInt32,
            DstAS            UInt32,
            NextHop          IPv6,
            BGPCommunities   Array(UInt32),
            ASPath           Array(UInt32),
            SrcCountry       String,
            SrcCity          String,
            DstCountry       String,
            DstCity          String,
            ASN              UInt32,
            Vendor           String,
            SourceName       String,
            ThreatInfo       String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(TimeReceived)
    ORDER BY (TimeReceived, SourceName, Vendor, DstAddr, DstPort, SrcAddr)
    TTL TimeReceived + INTERVAL 90 DAY
    SETTINGS index_granularity = 8192
    `

	ddlAlerts := `
    CREATE TABLE IF NOT EXISTS default.alerts (
            Timestamp       DateTime64(9),
            RuleName        String,
            Condition       String,
            SourceIP        IPv6,
            DestinationIP   IPv6,
            Vendor          String,
            SourceName      String,
            Metadata        String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(Timestamp)
    ORDER BY (Timestamp, SourceName, Vendor, RuleName, SourceIP)
    `

	if err := conn.Exec(ctx, ddlFlows); err != nil {
		return fmt.Errorf("falha ao criar tabela flows: %w", err)
	}
	log.Println("Tabela 'flows' criada/verificada com sucesso")

	if err := conn.Exec(ctx, ddlAlerts); err != nil {
		return fmt.Errorf("falha ao criar tabela alerts: %w", err)
	}
	log.Println("Tabela 'alerts' criada/verificada com sucesso")

	return nil
}
