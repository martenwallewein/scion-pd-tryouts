package pathselection

import (
	"fmt"
	"strings"
	"sync"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/sirupsen/logrus"
)

// Fixed is a Selector for a single dialed socket using a fixed path.

type FixedSelector struct {
	mutex     sync.Mutex
	paths     []*pan.Path
	current   int
	FixedPath *pan.Path
}

func NewDefaultSelector() *FixedSelector {
	return &FixedSelector{}
}

func (s *FixedSelector) Path() *pan.Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.paths) == 0 {
		return nil
	}
	return s.paths[s.current]
}

func (s *FixedSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	logrus.Debug("[FixedSelector] Initialize to remote ", remote.String())
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.paths = paths
	s.current = 0

	if s.FixedPath != nil {
		for i, p := range s.paths {
			if p.Fingerprint == s.FixedPath.Fingerprint {
				s.current = i
				break
			}
		}
	}

}

func (s *FixedSelector) Refresh(paths []*pan.Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	newcurrent := 0
	if len(s.paths) > 0 {
		currentFingerprint := s.paths[s.current].Fingerprint
		for i, p := range paths {
			if p.Fingerprint == currentFingerprint {
				newcurrent = i
				break
			}
		}
	}
	s.paths = paths
	s.current = newcurrent
}

func (s *FixedSelector) PathDown(pf pan.PathFingerprint, pi pan.PathInterface) {
	// s.mutex.Lock()
	// defer s.mutex.Unlock()

	// We react to this externally...
	/*current := s.paths[s.current]
	if isInterfaceOnPath(current, pi) || pf == current.Fingerprint {
		fmt.Println("down:", s.current, len(s.paths))
		better := stats.FirstMoreAlive(current, s.paths)
		if better >= 0 {
			// Try next path. Note that this will keep cycling if we get down notifications
			s.current = better
			fmt.Println("failover:", s.current, len(s.paths))
		}
	}*/
}

func (s *FixedSelector) SetPathFromSnet(p snet.Path) {
	ifIDs := make([]pan.IfID, len(p.Metadata().Interfaces))
	for i, iface := range p.Metadata().Interfaces {
		ifIDs[i] = pan.IfID(iface.ID)
	}
	path := &pan.Path{}

	if len(ifIDs) == 0 {
		path.Fingerprint = ""
		return
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "%d", ifIDs[0])
	for _, ifID := range ifIDs[1:] {
		fmt.Fprintf(b, " %d", ifID)
	}
	path.Fingerprint = pan.PathFingerprint(b.String())
	s.FixedPath = path

	if s.FixedPath != nil {
		for i, p := range s.paths {
			if p.Fingerprint == s.FixedPath.Fingerprint {
				s.current = i
				break
			}
		}
	}
}

func (s *FixedSelector) Close() error {
	return nil
}

func isInterfaceOnPath(p *pan.Path, pi pan.PathInterface) bool {
	for _, c := range p.Metadata.Interfaces {
		if c == pi {
			return true
		}
	}
	return false
}
