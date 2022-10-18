package main

import (
	"flag"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	smp "github.com/martenwallewein/scion-pathdiscovery/api"
	"github.com/martenwallewein/scion-pathdiscovery/packets"
	lookup "github.com/martenwallewein/scion-pathdiscovery/pathlookup"
	"github.com/martenwallewein/scion-pathdiscovery/pathselection"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/sirupsen/logrus"
)

var localAddr *string = flag.String("l", "localhost:9999", "Set the local address")
var remoteAddr *string = flag.String("r", "18-ffaa:1:ef8,[127.0.0.1]:12345", "Set the remote address")
var isServer *bool = flag.Bool("s", false, "Run as Server (otherwise, client)")

func numPathsConflict(path1, path2 snet.Path) int {
	path1Interfaces := path1.Metadata().Interfaces
	path2Interfaces := path2.Metadata().Interfaces
	conflicts := 0
	for i, intP1 := range path1Interfaces {
		for j, intP2 := range path2Interfaces {
			if i == 0 && j == 0 {
				continue
			}
			if i == (len(path1Interfaces)-1) && j == (len(path2Interfaces)-1) {
				continue
			}
			if intP1.IA.Equal(intP2.IA) && intP1.ID == intP2.ID {
				conflicts++
			}
		}
	}
	return conflicts
}

func (dj *DisjointPathselection) GetPathConflictEntries() ([]PathWrap, error) {
	// Put all paths in one list and sort them according to number of hops
	allPaths := make([]PathWrap, 0)
	paths, err := lookup.PathLookup(dj.remote.Peer.String())
	if err != nil {
		return nil, err
	}

	for _, pp := range paths {
		pw := PathWrap{
			Address: *dj.remote.Peer,
			Path:    pp,
		}
		allPaths = append(allPaths, pw)
	}

	sort.Slice(allPaths, func(i, j int) bool {
		return len(allPaths[i].Path.Metadata().Interfaces) < len(allPaths[j].Path.Metadata().Interfaces)
	})

	// Add conflicts
	for i, path := range allPaths {
		for _, path2 := range allPaths[i:] {
			curConflicts := numPathsConflict(path.Path, path2.Path)
			path.NumConflicts += curConflicts
		}
	}

	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].NumConflicts < allPaths[j].NumConflicts
	})

	logrus.Debug("[DisjointPathselection] Updated PathConflictEntries to remote ", dj.remote.Peer.String(), " got ", len(allPaths), " entries")

	return allPaths, nil
}

type PathWrap struct {
	Address      snet.UDPAddr
	Path         snet.Path
	NumConflicts int
}

type DisjointPathselection struct {
	local                    *smp.PanSocket
	remote                   *smp.PanSocket
	NumExploreConns          int
	NumConns                 int
	metricsMap               map[string]*packets.PathMetrics // Indicates the performance of the particular pathset -> id = path1|path2|path3 etc
	latestBestWriteBandwidth int64
	numUpdates               int64
	latestPathSet            []snet.Path
	currentPathSet           []snet.Path
}

func (dj *DisjointPathselection) GetNextProbingPathset() (pathselection.PathSet, error) {
	logrus.Debug("[DisjointPathselection] GetNextProbingPathSet called")
	alreadyCheckedPathsets := make([]string, 0)
	for k, _ := range dj.metricsMap {
		alreadyCheckedPathsets = append(alreadyCheckedPathsets, k)
	}

	conflictPaths, err := dj.GetPathConflictEntries()
	if err != nil {
		return pathselection.PathSet{}, err
	}

	psId := ""
	defaultPsId := ""

	// TODO: ExploreConns is fixed to 2, need to revisit
	fixedPaths := dj.NumConns - dj.NumExploreConns - 1
	for i := 0; i < fixedPaths; i++ {
		defaultPsId += lookup.PathToString(conflictPaths[i].Path) + "|"
	}

	// We do "breadth first search" meaning we start with the index i := fixedPath and j := fixedPath+1
	// and increase i and j until we find a match or reach the end of the list.
	i := fixedPaths
	j := fixedPaths + 1
	logrus.Debugf("Fixedpaths ", fixedPaths, " i ", i, " j ", j)
	for i < len(conflictPaths) && j < len(conflictPaths) {

		psId = defaultPsId + lookup.PathToString(conflictPaths[i].Path) + "|" + lookup.PathToString(conflictPaths[j].Path) + "|"
		if _, ok := dj.metricsMap[psId]; !ok {
			logrus.Debug("[DisjointPathselection] Found new Pathset to evaluate: ", psId)
			// return proper path set
			paths := make([]snet.Path, 0)

			for k := 0; i < fixedPaths; k++ {
				paths = append(paths, conflictPaths[k].Path)
			}

			paths = append(paths, conflictPaths[i].Path)
			paths = append(paths, conflictPaths[j].Path)
			return pathselection.WrapPathset(paths), nil

		}
		if j == len(conflictPaths)-1 {
			i++
			j = i + 1
			continue
		}

		j++

	}
	logrus.Debug("[DisjointPathselection] No new Pathset found")
	//
	return pathselection.PathSet{}, nil
}

func (dj *DisjointPathselection) InitialPathset() (pathselection.PathSet, error) {
	// Here we have our new path set, from which we start
	dj.latestPathSet = dj.currentPathSet
	// Explore new
	ps, err := dj.GetNextProbingPathset()
	if err != nil {
		return ps, err
	}
	logrus.Debug(ps.Paths)
	return ps, nil
}

func (dj *DisjointPathselection) UpdatePathSelection() (bool, error) {
	if dj.remote == nil {
		return false, nil
	}
	pathSet := dj.remote.GetCurrentPathset()
	currentId := ""
	for _, p := range pathSet.Paths {
		currentId += lookup.PathToString(p.SnetPath) + "|"
	}

	newMetrics := dj.remote.AggregateMetrics()
	dj.metricsMap[currentId] = newMetrics

	logrus.Debug("[DisjointPathselection] UpdatePathSelection called")
	dj.numUpdates++

	if dj.latestBestWriteBandwidth == 0 {
		dj.latestBestWriteBandwidth = newMetrics.AverageWriteBandwidth()
		logrus.Debug("[DisjointPathselection] Set initial latestBestWriteBandwidth to ", dj.latestBestWriteBandwidth)
	} else {
		// Compare to best, to make socket re-dial to improve performance
		if dj.numUpdates%5 == 0 {
			if newMetrics.AverageWriteBandwidth() > dj.latestBestWriteBandwidth {
				logrus.Debug("[DisjointPathselection] Got better pathset, reconnecting")
				dj.latestBestWriteBandwidth = newMetrics.AverageWriteBandwidth()

				// Here we have our new path set, from which we start
				dj.latestPathSet = dj.currentPathSet
				// Explore new
				ps, err := dj.GetNextProbingPathset()
				if err != nil {
					return false, err
				}
				logrus.Debug(ps.Paths)
				// TODO: Error handling
				dj.remote.Disconnect()

				// Reconnect
				err = dj.remote.Connect(&ps, nil)
				if err != nil {
					return false, err
				}
				logrus.Debug("[DisjointPathselection] Reconnect successfull")
				return true, nil

			} else {
				// Explore new
				ps, err := dj.GetNextProbingPathset()
				if err != nil {
					return false, err
				}
				logrus.Debug("[DisjointPathselection] Got new pathset, applying paths...")
				paths := pathselection.UnwrapPathset(ps)
				logrus.Warn(paths)
				conns := dj.remote.UnderlaySocket.GetConnections()
				if len(paths) < len(conns) {
					logrus.Warn("[DisjointPathSelection] Invalid pathset found...")
					return false, nil
				}
				// Here the number of connections won't change, so we have the same number of connections
				// as paths

				for i, c := range conns {
					c.SetPath(&paths[i])
				}
				return false, nil
			}
		}
	}
	return false, nil
}

func main() {
	// peers := []string{"peer1", "peer2", "peer3"} // Later real addresses
	flag.Parse()
	logrus.SetLevel(logrus.DebugLevel)
	mpSock := smp.NewPanSock(*localAddr, nil, &smp.PanSocketOptions{
		Transport: "QUIC",
	})
	err := mpSock.Listen()
	if err != nil {
		log.Fatal("Failed to listen PanSock: ", err)
		os.Exit(1)
	}

	if *isServer {

		disjointSel := DisjointPathselection{
			local:           mpSock,
			metricsMap:      make(map[string]*packets.PathMetrics),
			NumExploreConns: 1,
			NumConns:        2,
		}

		go func(dj *DisjointPathselection) {
			metricsTicker := time.NewTicker(1 * time.Second)
			for {
				select {
				// case <-done:
				//	return
				case <-metricsTicker.C:
					reconnect, err := disjointSel.UpdatePathSelection()
					if err != nil {
						logrus.Error("[DisjointPathSelection] Failed to update path selection ", err)
						os.Exit(1)
					}

					if reconnect {

					}
				}
			}

		}(&disjointSel)

		i := 1

		for {
			remote, err := mpSock.WaitForPeerConnect()
			if err != nil {
				log.Fatal("Failed to connect in-dialing peer: ", err)
				os.Exit(1)
			}
			log.Printf("Connected to %s", remote.String())
			conns := mpSock.UnderlaySocket.GetConnections()
			logrus.Warn(conns)

			addr, _ := pan.ResolveUDPAddr(*localAddr)
			addr.Port = addr.Port + uint16(i)*32
			// local2 := "17-ffaa:1:cf1,127.0.0.1:8999"
			mps := smp.NewPanSock(addr.String(), nil, &smp.PanSocketOptions{
				Transport: "QUIC",
			})
			disjointSel.remote = mps
			err = mps.Listen()
			if err != nil {
				log.Fatal("Failed to listen mps: ", err)
				os.Exit(1)
			}

			// Here we need to reset the dialing socket
			// remote.Host.Port = 7999
			mps.SetPeer(remote)
			// Pathselection
			/*paths, _ := mps.GetAvailablePaths()
			logrus.Warn(paths)
			pathset := pathselection.WrapPathset(paths)*/
			pathset, err := disjointSel.InitialPathset()
			if err != nil {
				log.Fatal("Failed to obtain pathset", err)
				os.Exit(1)
			}
			pathset.Address = *remote
			err = mps.Connect(&pathset, nil)
			if err != nil {
				log.Fatal("Failed to connect MPPeerSock", err)
				os.Exit(1)
			}
			logrus.Error("SUCCESS")
			i++
			go func(mps *smp.PanSocket) {
				WriteAllConns(mps)
				logrus.Warn("Done writing all conns to ", mps.Peer.String())
			}(mps)
		}

	} else {
		peerAddr, err := snet.ParseUDPAddr(*remoteAddr)
		if err != nil {
			log.Fatalf("Failed to parse remote addr %s, err: %v", *remoteAddr, err)
			os.Exit(1)
		}
		mpSock.SetPeer(peerAddr)
		paths, _ := mpSock.GetAvailablePaths()
		logrus.Warn(paths)
		pathset := pathselection.WrapPathset(paths)
		pathset.Address = *peerAddr
		err = mpSock.Connect(&pathset, nil)
		if err != nil {
			log.Fatal("Failed to connect MPPeerSock", err)
			os.Exit(1)
		}
		conns := mpSock.UnderlaySocket.GetConnections()
		logrus.Warn(conns)

		// TODO: Listen on Disconnect Event
		for {
			mpSock.Disconnect()
			new, err := mpSock.WaitForPeerConnect()
			if err != nil {
				log.Fatal("Failed to wait for back MPPeerSock", err)
				os.Exit(1)
			}
			logrus.Info("Got conn back from remote ", new.String())
			ReadAllConns(mpSock)
		}
	}

	// mpSock.
	// mpSock.SetPeer(remote)
	// mpSock.Connect(customPathSelectAlg)
	// defer mpSock.Disconnect()

}

func ReadAllConns(mps *smp.PanSocket) {
	var wg sync.WaitGroup
	conns := mps.UnderlaySocket.GetConnections()
	for _, c := range conns {
		wg.Add(1)
		go func(c packets.UDPConn) {
			bts := make([]byte, packets.PACKET_SIZE)
			for {
				_, err := c.Read(bts)
				if err != nil {
					logrus.Error(err)
					wg.Done()
				}
			}
		}(c)
	}

	wg.Wait()
}

func WriteAllConns(mps *smp.PanSocket) {
	var wg sync.WaitGroup
	conns := mps.UnderlaySocket.GetConnections()
	for _, c := range conns {
		wg.Add(1)
		go func(c packets.UDPConn) {
			bts := make([]byte, packets.PACKET_SIZE)
			for {
				_, err := c.Write(bts)
				if err != nil {
					logrus.Error(err)
					wg.Done()
				}
			}
		}(c)
	}

	wg.Wait()
}
