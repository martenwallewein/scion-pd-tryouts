package main

import (
	"flag"
	"log"
	"os"

	smp "github.com/martenwallewein/scion-pathdiscovery/api"
	"github.com/martenwallewein/scion-pathdiscovery/packets"
	"github.com/martenwallewein/scion-pathdiscovery/pathselection"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/sirupsen/logrus"
)

var localAddr *string = flag.String("l", "localhost:9999", "Set the local address")
var remoteAddr *string = flag.String("r", "18-ffaa:1:ef8,[127.0.0.1]:12345", "Set the remote address")
var isServer *bool = flag.Bool("s", false, "Run as Server (otherwise, client)")

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
		remote, err := mpSock.WaitForPeerConnect()
		if err != nil {
			log.Fatal("Failed to connect in-dialing peer: ", err)
			os.Exit(1)
		}
		conns := mpSock.UnderlaySocket.GetConnections()
		log.Printf("Connected to %s", remote.String())
		bts := make([]byte, packets.PACKET_SIZE)
		logrus.Warn(conns)
		for {
			n, err := conns[0].Read(bts)
			logrus.Warn("READ")
			if err != nil {
				log.Fatalf("Failed to read bytes from peer %s, err: %v", remote.String(), err)
				os.Exit(1)
			}
			log.Printf("Read %d bytes from %s", n, remote.String())

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
		bts := make([]byte, packets.PACKET_SIZE)
		for {
			n, err := conns[0].Write(bts)
			// n, err := mpSock.Write(bts)
			if err != nil {
				log.Fatalf("Failed to write bytes from peer %s, err: %v", *remoteAddr, err)
				os.Exit(1)
			}
			log.Printf("Wrote %d bytes to %s", n, *remoteAddr)
		}

	}

	// mpSock.
	// mpSock.SetPeer(remote)
	// mpSock.Connect(customPathSelectAlg)
	defer mpSock.Disconnect()

}
