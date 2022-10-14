package packets

import (
	"net"

	"github.com/scionproto/scion/go/lib/snet"
)

const (
	PACKET_SIZE = 1400 // At the moment we work only with normal MTUs, no jumbo frames
)

func ConnTypeToString(connType int) string {
	switch connType {
	case ConnectionTypes.Bidirectional:
		return "bidirectional"

	case ConnectionTypes.Outgoing:
		return "outgoing"

	case ConnectionTypes.Incoming:
		return "incoming"
	}

	return ""
}

var ConnectionTypes = newConnectionTypes()

func newConnectionTypes() *connectionTypes {
	return &connectionTypes{
		Incoming:      1,
		Outgoing:      2,
		Bidirectional: 3,
	}
}

type connectionTypes struct {
	Incoming      int
	Outgoing      int
	Bidirectional int
}

var ConnectionStates = newConnectionStates()

func newConnectionStates() *connectionStates {
	return &connectionStates{
		Pending: 1,
		Open:    2,
		Closed:  3,
	}
}

type connectionStates struct {
	Pending int
	Open    int
	Closed  int
}

type BasicConn struct {
	state int
}

func (c *BasicConn) GetState() int {
	return c.state
}

type UDPConn interface {
	net.Conn
	GetMetrics() *PathMetrics
	GetPath() *snet.Path
	SetPath(*snet.Path) error
	GetRemote() *snet.UDPAddr
}

type TransportConstructor func() UDPConn
