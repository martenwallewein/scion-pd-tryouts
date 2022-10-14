package pathselection

import (
	"sort"
)

type byHopCount []PathQuality

func (pathSet byHopCount) Len() int {
	return len(pathSet)
}

func (pathSet byHopCount) Swap(i, j int) {
	pathSet[i].Path, pathSet[j].Path = pathSet[j].Path, pathSet[i].Path
}

func (pathSet byHopCount) Less(i, j int) bool {
	return len(pathSet[i].Path.Metadata().Interfaces) < len(pathSet[j].Path.Metadata().Interfaces)
}

// GetPathSmallHopCount Select the shortest paths from given path array
func (pathSet *PathSet) GetPathSmallHopCount(number int) *PathSet {
	sort.Sort(byHopCount(pathSet.Paths))
	return SelectPaths(number, pathSet)
}
