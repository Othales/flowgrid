package utils

import (
	"sync"
	"time"
)

type CircuitBreaker struct {
	failures     int
	maxFailures  int
	resetTimeout time.Duration
	lastFailure  time.Time
	mutex        sync.Mutex
}

func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if cb.failures >= cb.maxFailures {
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.failures = 0
			return true
		}
		return false
	}
	return true
}

func (cb *CircuitBreaker) Success() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.failures = 0
}

func (cb *CircuitBreaker) Failure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
}
