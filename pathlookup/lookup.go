package lookup

import (
	"context"
	"fmt"
	"strings"

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

func PathToString(path snet.Path) string {
	if path == nil {
		return ""
	}
	intfs := path.Metadata().Interfaces
	if len(intfs) == 0 {
		return ""
	}
	var hops []string
	intf := intfs[0]
	hops = append(hops, fmt.Sprintf("%s %s",
		intf.IA,
		intf.ID,
	))
	for i := 1; i < len(intfs)-1; i += 2 {
		inIntf := intfs[i]
		outIntf := intfs[i+1]
		hops = append(hops, fmt.Sprintf("%s %s %s",
			inIntf.ID,
			inIntf.IA,
			outIntf.ID,
		))
	}
	intf = intfs[len(intfs)-1]
	hops = append(hops, fmt.Sprintf("%s %s",
		intf.ID,
		intf.IA,
	))
	return fmt.Sprintf("[%s]", strings.Join(hops, ">"))
}
