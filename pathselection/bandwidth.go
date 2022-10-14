package pathselection

type byBandwidth []PathQuality

func (pathSet byBandwidth) Len() int {
	return len(pathSet)
}

func (pathSet byBandwidth) Swap(i, j int) {
	pathSet[i].Path, pathSet[j].Path = pathSet[j].Path, pathSet[i].Path
}

func (pathSet byBandwidth) Less(i, j int) bool {
	return pathSet[i].MaxBandwidth < pathSet[j].MaxBandwidth

}

// GetPathHighBandwidth Select the shortest paths from given path array
func (pathSet *PathSet) GetPathHighBandwidth(number int) *PathSet {
	return SelectPaths(number, pathSet)
}
