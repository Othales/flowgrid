package enrichment

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"flowgrid/pkg/utils"
)

type Resolver struct {
	cache sync.Map
	cb    *utils.CircuitBreaker
}

func NewResolver(cb *utils.CircuitBreaker) *Resolver {
	return &Resolver{cb: cb}
}

func (r *Resolver) Lookup(ip string) string {
	if cached, ok := r.cache.Load(ip); ok {
		return cached.(string)
	}
	if r.cb != nil && !r.cb.Allow() {
		return ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		if r.cb != nil {
			r.cb.Failure()
		}
		r.cache.Store(ip, ip)
		return ip
	}

	if r.cb != nil {
		r.cb.Success()
	}
	result := strings.TrimSuffix(names[0], ".")
	r.cache.Store(ip, result)
	return result
}

func (r *Resolver) Clear() {
	r.cache.Range(func(key, _ interface{}) bool {
		r.cache.Delete(key)
		return true
	})
}
