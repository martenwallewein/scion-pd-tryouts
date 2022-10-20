package pathselection

import "sort"

type byMTU []PathQuality

func (pathQualities byMTU) Len() int {
	return len(pathQualities)
}

func (pathQualities byMTU) Swap(i, j int) {
	pathQualities[i].Path, pathQualities[j].Path = pathQualities[j].Path, pathQualities[i].Path
}

func (pathQualities byMTU) Less(i, j int) bool {
	// switched so that lager MTUs are at index 0
	return pathQualities[i].SnetPath.Metadata().MTU > pathQualities[j].SnetPath.Metadata().MTU
}

func (pathSet *PathSet) GetPathLargeMTU(number int) *PathSet {
	sort.Sort(byMTU(pathSet.Paths))
	return SelectPaths(number, pathSet)
}
