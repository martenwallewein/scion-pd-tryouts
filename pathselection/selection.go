package pathselection

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/martenwallewein/scion-pathdiscovery/packets"
	lookup "github.com/martenwallewein/scion-pathdiscovery/pathlookup"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/sirupsen/logrus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

type PathSet struct {
	Address snet.UDPAddr
	Paths   []PathQuality
}

type PathEnumerator interface {
	Enumerate(addr.HostAddr) PathSet
}

type PathQuality struct {
	metrics      packets.PathMetrics
	Timestamp    time.Time
	HopCount     int
	MTU          uint16
	Latency      time.Duration
	RTT          time.Duration
	Bytes        int
	Duration     time.Duration
	MaxBandwidth int64
	Path         pan.Path
	SnetPath     snet.Path
	Id           string
}

type SelecteablePathSet interface {
	GetPathHighBandwidth(number int) PathSet
	GetPathLowLatency(number int) PathSet
	GetPathLargeMTU(number int) PathSet
	GetPathSmallHopCount(number int) PathSet
}

type PathQualityDatabase interface {
	GetPathSet(addr *snet.UDPAddr) (PathSet, error)
	SetConnections([]packets.UDPConn)
	UpdatePathQualities(addr *snet.UDPAddr, interval time.Duration) error
	UpdateMetrics()

	// TODO: Rethink those...
	//GetPathFunc takes as second argument a function that is
	//then called recursively over all PathQuality pairs, always
	//retaining the returned result as the first input for the
	//next call. The path associated with the last returned
	//PathQuality struct is then picked.
	// GetPathFunc(addr.HostAddr, func(PathQuality, PathQuality) PathQuality) snet.Path
	//GetPathCustom takes as second argument a function that is
	//called with the PathQuality array of all the alternative
	//paths for the host address. The path associated with the
	//returned PathQuality is then returned
	// GetPathCustom(addr.HostAddr, func([]PathQuality) PathQuality) snet.Path
}

type InMemoryPathQualityDatabase struct {
	pathSetDB   []PathSet
	hashMap     map[string]int
	connections []packets.UDPConn
}

func (db *InMemoryPathQualityDatabase) SetConnections(conns []packets.UDPConn) {
	db.connections = conns
}

func (db *InMemoryPathQualityDatabase) UpdateMetrics() {
	logrus.Debug("[PathDB] UpdateMetrics called")
	// TODO: Do listen Cons have paths?
	for _, v := range db.connections {

		connMetrics := v.GetMetrics()
		connMetrics.Tick()

		if v.GetRemote() == nil {
			continue
		}
		pathQuality, err := db.getPathQuality(v.GetRemote(), v.GetPath())
		if err != nil {
			log.Fatal(err)
		}

		// Incoming conn may not have path
		if pathQuality != nil {
			pathQuality.metrics = *connMetrics

			var maxBw int64 = 0
			for _, v := range pathQuality.metrics.ReadBandwidth {
				if v > maxBw {
					maxBw = v
				}
			}

			for _, v := range pathQuality.metrics.WrittenBandwidth {
				if v > maxBw {
					maxBw = v
				}
			}

			pathQuality.MaxBandwidth = maxBw
		}

	}
}

func (db *InMemoryPathQualityDatabase) getPathQuality(addr *snet.UDPAddr, path *snet.Path) (*PathQuality, error) {
	var pathQuality *PathQuality
	pathSet, err := db.GetPathSet(addr)
	if err != nil {
		return nil, err
	}

	for _, v := range pathSet.Paths {
		if path != nil && bytes.Compare(v.SnetPath.Path().Raw, (*path).Path().Raw) == 0 {
			pathQuality = &v
		}
	}

	// TODO: Warning
	// if pathQuality == nil {
	//	return nil, errors.New(fmt.Sprintf("No PathQuality found for path"))
	//}

	return pathQuality, nil

}

func asSha256(o interface{}) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", o)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func calcAddrHash(addr *snet.UDPAddr) string {
	var partHash strings.Builder
	h1 := asSha256(addr.IA.I.String())
	h2 := asSha256(addr.IA.A.String())
	partHash.WriteString(h1)
	partHash.WriteString(h2)
	return asSha256(partHash.String())
}

func (db *InMemoryPathQualityDatabase) GetPathSet(addr *snet.UDPAddr) (PathSet, error) {
	// logrus.Error("Get entry ", addr.String())
	// logrus.Error(db.hashMap)
	hash := calcAddrHash(addr)
	index, contained := db.hashMap[hash]
	if contained {
		return db.pathSetDB[index], nil
	} else {
		return PathSet{}, errors.New("404")
	}
}

/*
type MeasuringReaderWriter interface {
	io.Reader
	io.Writer
	Measure(snet.Path) chan PathQuality
}
*/
//TODO: can be removed?
//func NewPathSet() QualityDB {
//	//return &PathSet{}
//	return nil
//}

func SelectPaths(count int, pathSet *PathSet) *PathSet {
	newPathSet := &PathSet{
		Paths: make([]PathQuality, 0),
	}
	lenPaths := len(pathSet.Paths)
	numPathsToReturn := 0
	if lenPaths > 0 {
		if lenPaths < count {
			numPathsToReturn = lenPaths
		} else {
			numPathsToReturn = count
		}
		for i := 0; i < numPathsToReturn; i++ {
			newPathSet.Paths = append(newPathSet.Paths, pathSet.Paths[i])
		}
	}
	return newPathSet
}

type CustomPathSelection interface {
	CustomPathSelectAlg(*PathSet) (*PathSet, error)
}

func NewInMemoryPathQualityDatabase() *InMemoryPathQualityDatabase {
	return &InMemoryPathQualityDatabase{
		hashMap: make(map[string]int),
	}
}

func (db *InMemoryPathQualityDatabase) UpdatePathQualities(addr *snet.UDPAddr, metricsInterval time.Duration) error {
	// TODO: Fix with pan
	// paths := make([]snet.Path, 0)
	logrus.Debug("[PathDB] UpdatePathQualities called for ", addr.String())
	paths, err := lookup.PathLookup(addr.String())
	if err != nil {
		return err
	}
	var pathQualities []PathQuality
	for _, path := range paths {

		cachedPathQuality, err := db.getPathQuality(addr, &path)
		if err != nil && cachedPathQuality != nil {
			pathQualities = append(pathQualities, *cachedPathQuality)
		} else {
			// TODO: Add local addr in hashing to support multiple conns over the same path
			h := sha256.New()
			h.Write(path.Path().Raw)
			bs := h.Sum(nil)
			id := fmt.Sprintf("%x", bs)
			pathEntry := PathQuality{SnetPath: path, Id: id, metrics: *packets.NewPathMetrics(metricsInterval)}
			pathQualities = append(pathQualities, pathEntry)
		}

	}
	tmpPathSet := PathSet{Address: *addr, Paths: pathQualities}

	if i, contained := db.hashMap[calcAddrHash(addr)]; contained {
		//update PathSetDB entry if already existing
		db.pathSetDB[i] = tmpPathSet
	} else {
		logrus.Debug("[PathDB] Add new entry ", addr.String())
		db.pathSetDB = append(db.pathSetDB, tmpPathSet)
		hash := calcAddrHash(addr)
		db.hashMap[hash] = len(db.pathSetDB) - 1
	}
	return nil
}

func UnwrapPathset(pathset PathSet) []snet.Path {
	paths := make([]snet.Path, 0)
	for _, p := range pathset.Paths {
		paths = append(paths, p.SnetPath)
	}

	return paths
}

func WrapPathset(paths []snet.Path) PathSet {
	pathQualities := make([]PathQuality, 0)
	for _, p := range paths {
		pq := PathQuality{
			SnetPath: p,
		}
		pathQualities = append(pathQualities, pq)
	}
	pathsSet := PathSet{
		Paths: pathQualities,
	}

	return pathsSet
}

func FindIndexByPathString(pq []PathQuality, s string) int {
	for i, v := range pq {
		if s == lookup.PathToString(v.SnetPath) {
			return i
		}
	}

	return -1
}
