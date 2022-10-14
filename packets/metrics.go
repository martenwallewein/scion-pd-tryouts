package packets

import (
	"time"
)

// Some Metrics to start with
// Will be extended later
// NOTE: Add per path metrics here?
type PathMetrics struct {
	ReadBytes        int64
	LastReadBytes    int64
	ReadPackets      int64
	WrittenBytes     int64
	LastWrittenBytes int64
	WrittenPackets   int64
	ReadBandwidth    []int64
	WrittenBandwidth []int64
	MaxBandwidth     int64
	UpdateInterval   time.Duration
}

func NewPathMetrics(updateInterval time.Duration) *PathMetrics {
	return &PathMetrics{
		UpdateInterval:   updateInterval,
		ReadBandwidth:    make([]int64, 0),
		WrittenBandwidth: make([]int64, 0),
	}
}

func (m *PathMetrics) Tick() {

	// TODO: FIx this
	if m.UpdateInterval == 0 {
		m.UpdateInterval = 1000 * time.Millisecond
	}

	fac := int64((1000 * time.Millisecond) / m.UpdateInterval)
	readBw := (m.ReadBytes - m.LastReadBytes) * fac
	writeBw := (m.WrittenBytes - m.LastWrittenBytes) * fac
	m.ReadBandwidth = append(m.ReadBandwidth, readBw)
	m.WrittenBandwidth = append(m.WrittenBandwidth, writeBw)
	m.LastReadBytes = m.ReadBytes
	m.LastWrittenBytes = m.WrittenBytes
}
