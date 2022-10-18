package packets

import (
	"fmt"
	"strings"
	"sync"
	"time"

	lookup "github.com/martenwallewein/scion-pathdiscovery/pathlookup"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/sirupsen/logrus"
)

type MetricsDB struct {
	UpdateInterval time.Duration
	Data           map[string]*PathMetrics
}

var singletonMetricsDB MetricsDB
var initOnce sync.Once

// host initialises and returns the singleton hostContext.
func GetMetricsDB() *MetricsDB {
	initOnce.Do(mustInitMetricsDB)
	return &singletonMetricsDB
}

func mustInitMetricsDB() {
	singletonMetricsDB = MetricsDB{
		Data: map[string]*PathMetrics{},
	}
}

func (mdb *MetricsDB) Tick() {

}

func (mdb *MetricsDB) GetBySocket(local *snet.UDPAddr) []*PathMetrics {
	logrus.Trace("[MetricsDB] Get metrics for local ", local)
	id := local.String()
	metrics := make([]*PathMetrics, 0)
	for k, v := range mdb.Data {
		if strings.Contains(k, id) {
			logrus.Trace("[MetricsDB] Got written bw ", v.WrittenBandwidth, " for path ", lookup.PathToString(*v.Path))
			metrics = append(metrics, v)
		}
	}

	return metrics
}

func (mdb *MetricsDB) GetOrCreate(local *snet.UDPAddr, path *snet.Path) *PathMetrics {
	ok := false
	var m *PathMetrics
	var id string
	if local == nil {
		id = lookup.PathToString(*path)
		for k, v := range mdb.Data {
			if strings.Contains(k, id) {
				ok = true
				m = v
				break
			}
		}
	} else {
		id = fmt.Sprintf("%s-%s", local.String(), lookup.PathToString(*path))
		m, ok = mdb.Data[id]
	}

	logrus.Trace("[MetricsDB] Check for id ", id, ", got ", ok)
	if !ok {
		pm := NewPathMetrics(mdb.UpdateInterval)
		pm.Path = path
		mdb.Data[id] = pm
		return pm
	}

	return m

}

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
	Path             *snet.Path
}

func NewPathMetrics(updateInterval time.Duration) *PathMetrics {
	return &PathMetrics{
		UpdateInterval:   updateInterval,
		ReadBandwidth:    make([]int64, 0),
		WrittenBandwidth: make([]int64, 0),
	}
}

func (m *PathMetrics) AverageReadBandwidth() int64 {
	size := len(m.ReadBandwidth)
	if size == 0 {
		return 0
	}
	var val int64
	for _, item := range m.ReadBandwidth {
		val += item
	}

	val = val / int64(size)
	return val
}

func (m *PathMetrics) AverageWriteBandwidth() int64 {
	size := len(m.WrittenBandwidth)
	if size == 0 {
		return 0
	}
	var val int64
	for _, item := range m.WrittenBandwidth {
		val += item
	}

	val = val / int64(size)
	return val
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
