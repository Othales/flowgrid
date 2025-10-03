package enrichment

import (
	"log"
	"net"

	"github.com/oschwald/geoip2-golang"

	"flowgrid/pkg/types"
)

type GeoIPService struct {
	enabled bool
	asnDB   *geoip2.Reader
	geoDB   *geoip2.Reader
}

func NewGeoIPService(enabled bool) *GeoIPService {
	service := &GeoIPService{enabled: enabled}
	if !enabled {
		return service
	}

	asnDB, err := geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		log.Printf("AVISO: ASN DB não carregado: %v", err)
	} else {
		service.asnDB = asnDB
	}

	geoDB, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Printf("AVISO: GeoIP DB não carregado: %v", err)
	} else {
		service.geoDB = geoDB
	}

	if service.asnDB == nil && service.geoDB == nil {
		service.enabled = false
	}

	return service
}

func (s *GeoIPService) Close() {
	if s.asnDB != nil {
		s.asnDB.Close()
	}
	if s.geoDB != nil {
		s.geoDB.Close()
	}
}

func (s *GeoIPService) Enrich(flow *types.Flow) {
	if !s.enabled {
		return
	}

	if srcIP := net.ParseIP(flow.SrcAddr); srcIP != nil {
		s.lookupIP(srcIP, true, flow)
	}
	if dstIP := net.ParseIP(flow.DstAddr); dstIP != nil {
		s.lookupIP(dstIP, false, flow)
	}
}

func (s *GeoIPService) lookupIP(ip net.IP, source bool, flow *types.Flow) {
	if s.asnDB != nil {
		if record, err := s.asnDB.ASN(ip); err == nil {
			if source {
				flow.SrcAS = uint32(record.AutonomousSystemNumber)
			} else {
				flow.DstAS = uint32(record.AutonomousSystemNumber)
				flow.ASN = uint32(record.AutonomousSystemNumber)
			}
		}
	}

	if s.geoDB != nil {
		if record, err := s.geoDB.City(ip); err == nil {
			if source {
				flow.SrcCountry = record.Country.IsoCode
				if name, ok := record.City.Names["en"]; ok {
					flow.SrcCity = name
				}
			} else {
				flow.DstCountry = record.Country.IsoCode
				if name, ok := record.City.Names["en"]; ok {
					flow.DstCity = name
				}
			}
		}
	}
}
