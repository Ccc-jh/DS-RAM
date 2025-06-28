package KMedoids

import (
	"blockEmulator/shard"
	"math/rand"
	"sort"
)

func KMedoids(nodes []shard.Node, k, maxIterations, maxNodesPerCluster int) ([]shard.Node, map[int][]shard.Node) {
	if k <= 0 || k > len(nodes) {
		panic("Invalid number of clusters")
	}
	//Initialize k centroids.
	medoids := make([]shard.Node, k)
	for i := 0; i < k; i++ {
		medoids[i] = nodes[rand.Intn(len(nodes))]
	}

	//Assign nodes to clusters.
	clusters := make(map[int][]shard.Node)
	for _, node := range nodes {
		clusterIndex := 0
		minDistance := CalculateWeightedDistance(node, medoids[0])
		for j := 1; j < k; j++ {
			distance := CalculateWeightedDistance(node, medoids[j])
			if distance < minDistance {
				minDistance = distance
				clusterIndex = j
			}
		}
		clusters[clusterIndex] = append(clusters[clusterIndex], node)
	}

	//Use PAM algorithm to select replacement for each cluster's current medoid to reduce total clustering cost.
	for iter := 0; iter < maxIterations; iter++ {
		//Iterate through each cluster.
		for i := 0; i < k; i++ {
			currentMedoid := medoids[i]
			bestMedoid := currentMedoid
			minCost := calculateClusterCost(clusters[i], currentMedoid)

			//Try each node in the cluster as a medoid.
			for _, node := range clusters[i] {
				cost := calculateClusterCost(clusters[i], node)
				if cost < minCost {
					minCost = cost
					bestMedoid = node
				}
			}

			//Update medoid if a better one is found.
			if bestMedoid != currentMedoid {
				medoids[i] = bestMedoid
				//Reassign nodes to clusters based on updated medoids.
				clusters = make(map[int][]shard.Node)
				for _, node := range nodes {
					clusterIndex := 0
					minDistance := CalculateWeightedDistance(node, medoids[0])
					for j := 1; j < k; j++ {
						distance := CalculateWeightedDistance(node, medoids[j])
						if distance < minDistance {
							minDistance = distance
							clusterIndex = j
						}
					}
					clusters[clusterIndex] = append(clusters[clusterIndex], node)
				}
			}
		}
	}

	for i := 0; i < k; i++ {
		if len(clusters[i]) > maxNodesPerCluster {
			// Sort based on the distance to the centroids.
			sort.SliceStable(clusters[i], func(a, b int) bool {
				return CalculateWeightedDistance(clusters[i][a], medoids[i]) < CalculateWeightedDistance(clusters[i][b], medoids[i])
			})
			// Assign to the second most similar cluster.
			for j := maxNodesPerCluster; j < len(clusters[i]); j++ {
				nextCluster := (i + 1) % k // Next cluster index (wrap around if last cluster)
				clusters[nextCluster] = append(clusters[nextCluster], clusters[i][j])
			}
			// Remove nodes from the current cluster.
			clusters[i] = clusters[i][:maxNodesPerCluster]
		}
	}

	return medoids, clusters
}

// Calculate the total cost of a cluster (the sum of the weighted distances between all nodes and the centroid).
func calculateClusterCost(cluster []shard.Node, medoid shard.Node) float64 {
	cost := 0.0
	for _, node := range cluster {
		cost += CalculateWeightedDistance(node, medoid)
	}
	return cost
}
