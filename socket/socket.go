package socket

import (
	"github.com/martenwallewein/scion-pathdiscovery/packets"
	"github.com/martenwallewein/scion-pathdiscovery/pathselection"
	"github.com/scionproto/scion/go/lib/snet"
)

type ConnectOptions struct {
	SendAddrPacket      bool
	NoMetricsCollection bool
}

type DialOptions struct {
	SendAddrPacket bool
	NumPaths       int
}

type DialPacketQuic struct {
	Addr snet.UDPAddr
	Path snet.Path
}

type HandshakePacketQuic struct {
	Addr     snet.UDPAddr
	NumPorts int
	Ports    []int
}

type UnderlaySocket interface {
	Listen() error
	WaitForDialIn() (*snet.UDPAddr, error)
	WaitForIncomingConn(snet.UDPAddr) (packets.UDPConn, error)
	NextIncomingConn() (packets.UDPConn, error)
	/*Dial(remote snet.UDPAddr, path snet.Path, options DialOptions, i int) (packets.UDPConn, error)*/
	DialAll(remote snet.UDPAddr, path []pathselection.PathQuality, options DialOptions) ([]packets.UDPConn, error)
	CloseAll() []error
	GetConnections() []packets.UDPConn
}
