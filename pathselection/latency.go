package pathselection

import (
	"sort"
	"time"
)

type byLatency []PathQuality

func (pathSet byLatency) Len() int {
	return len(pathSet)
}

func (pathSet byLatency) Swap(i, j int) {
	pathSet[i].Path, pathSet[j].Path = pathSet[j].Path, pathSet[i].Path
}

func (pathSet byLatency) Less(i, j int) bool {
	return sumupLatencies(pathSet[i].Path.Metadata().Latency) < sumupLatencies(pathSet[j].Path.Metadata().Latency)
}

func sumupLatencies(latencies []time.Duration) (totalLatency time.Duration) {
	totalLatency = 0
	for _, latency := range latencies {
		if latency > 0 {
			totalLatency += latency
		}
	}
	return totalLatency
}

// GetPathLowLatency Select the paths from given path array with lowest total latency
func (pathSet *PathSet) GetPathLowLatency(number int) *PathSet {
	sort.Sort(byLatency(pathSet.Paths))
	return SelectPaths(number, pathSet)
}
