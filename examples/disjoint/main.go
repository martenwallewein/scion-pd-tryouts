package main

import (
	"flag"
	"log"
	"os"

	smp "github.com/martenwallewein/scion-pathdiscovery/api"
	"github.com/martenwallewein/scion-pathdiscovery/pathselection"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/sirupsen/logrus"
)

var localAddr *string = flag.String("l", "localhost:9999", "Set the local address")
var remoteAddr *string = flag.String("r", "18-ffaa:1:ef8,[127.0.0.1]:12345", "Set the remote address")
var isServer *bool = flag.Bool("s", false, "Run as Server (otherwise, client)")

type DisjointPathselection struct {
	local         *smp.PanSocket
	remoteSockets []*smp.PanSocket
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
			local:         mpSock,
			remoteSockets: make([]*smp.PanSocket, 0),
		}
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
			disjointSel.remoteSockets = append(disjointSel.remoteSockets, mps)
			err = mps.Listen()
			if err != nil {
				log.Fatal("Failed to listen mps: ", err)
				os.Exit(1)
			}

			// Here we need to reset the dialing socket
			// remote.Host.Port = 7999
			mps.SetPeer(remote)
			paths, _ := mps.GetAvailablePaths()
			logrus.Warn(paths)
			pathset := pathselection.WrapPathset(paths)
			pathset.Address = *remote
			err = mps.Connect(&pathset, nil)
			if err != nil {
				log.Fatal("Failed to connect MPPeerSock", err)
				os.Exit(1)
			}
			logrus.Error("SUCCESS")
			i++
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

		/*local2 := "17-ffaa:1:cf1,127.0.0.1:7999"
		mps := smp.NewPanSock(local2, nil, &smp.PanSocketOptions{
			Transport: "QUIC",
		})
		err = mps.Listen()
		if err != nil {
			log.Fatal("Failed to listen mps: ", err)
			os.Exit(1)
		}

		new, err := mps.WaitForPeerConnect()
		if err != nil {
			log.Fatal("Failed to wait for back MPPeerSock", err)
			os.Exit(1)
		}*/
		mpSock.Disconnect()
		new, err := mpSock.WaitForPeerConnect()
		if err != nil {
			log.Fatal("Failed to wait for back MPPeerSock", err)
			os.Exit(1)
		}

		logrus.Error(new)
	}

	// mpSock.
	// mpSock.SetPeer(remote)
	// mpSock.Connect(customPathSelectAlg)
	defer mpSock.Disconnect()

}
