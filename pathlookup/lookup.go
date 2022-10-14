package lookup

import (
	"context"

	"github.com/martenwallewein/scion-pathdiscovery/scionhost"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/go/lib/snet"
)

// This wraps the usage of appnet to query paths
// May later be put into an interface or struct
func PathLookup(peer string) ([]snet.Path, error) {
	host := scionhost.Host()
	udpAddr, err := pan.ResolveUDPAddr(peer)
	if err != nil {
		return nil, err
	}
	return host.QueryPaths(context.Background(), udpAddr.IA)
}
