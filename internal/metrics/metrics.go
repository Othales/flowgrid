package metrics

import "sync/atomic"

type Metrics struct {
	flowsProcessed atomic.Uint64
	flowErrors     atomic.Uint64
	snmpErrors     atomic.Uint64
	activeFlows    atomic.Int64
	queueLength    atomic.Int64
}

var global Metrics

func Global() *Metrics {
	return &global
}

func (m *Metrics) IncFlowsProcessed() {
	m.flowsProcessed.Add(1)
}

func (m *Metrics) AddFlowErrors(v uint64) {
	m.flowErrors.Add(v)
}

func (m *Metrics) IncFlowErrors() {
	m.AddFlowErrors(1)
}

func (m *Metrics) IncSnmpErrors() {
	m.snmpErrors.Add(1)
}

func (m *Metrics) SetActiveFlows(v int64) {
	m.activeFlows.Store(v)
}

func (m *Metrics) AddActiveFlows(delta int64) {
	m.activeFlows.Add(delta)
}

func (m *Metrics) SetQueueLength(v int64) {
	m.queueLength.Store(v)
}

func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		FlowsProcessed: m.flowsProcessed.Load(),
		FlowErrors:     m.flowErrors.Load(),
		SnmpErrors:     m.snmpErrors.Load(),
		ActiveFlows:    m.activeFlows.Load(),
		QueueLength:    m.queueLength.Load(),
	}
}

type Snapshot struct {
	FlowsProcessed uint64
	FlowErrors     uint64
	SnmpErrors     uint64
	ActiveFlows    int64
	QueueLength    int64
}
