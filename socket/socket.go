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

type DialPacket struct {
	Addr snet.UDPAddr
	Path snet.Path
}

type HandshakePacket struct {
	Addr     snet.UDPAddr
	NumPorts int
	Ports    []int
}

type UnderlaySocket interface {
	Listen() error
	Local() *snet.UDPAddr
	AggregateMetrics() *packets.PathMetrics
	WaitForDialIn() (*snet.UDPAddr, error)
	WaitForIncomingConn(snet.UDPAddr) (packets.UDPConn, error)
	DialAll(remote snet.UDPAddr, path []pathselection.PathQuality, options DialOptions) ([]packets.UDPConn, error)
	CloseAll() []error
	GetConnections() []packets.UDPConn
}
