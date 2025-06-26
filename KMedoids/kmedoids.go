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
	//---初始化k个质心
	medoids := make([]shard.Node, k)
	for i := 0; i < k; i++ {
		medoids[i] = nodes[rand.Intn(len(nodes))]
	}

	// ---分配节点
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

	// ---（更新质心）使用PAM算法来选择替换每个簇中的当前medoid以减少总体聚类代价
	for iter := 0; iter < maxIterations; iter++ {
		// Iterate through each cluster
		for i := 0; i < k; i++ {
			currentMedoid := medoids[i]
			bestMedoid := currentMedoid
			minCost := calculateClusterCost(clusters[i], currentMedoid)

			// Try each node in the cluster as a medoid
			for _, node := range clusters[i] {
				cost := calculateClusterCost(clusters[i], node)
				if cost < minCost {
					minCost = cost
					bestMedoid = node
				}
			}

			// Update medoid if a better one is found
			if bestMedoid != currentMedoid {
				medoids[i] = bestMedoid
				// Reassign nodes to clusters based on updated medoids
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

	// ---每个簇的数量进行处理
	for i := 0; i < k; i++ {
		if len(clusters[i]) > maxNodesPerCluster {
			// ---根据到质心的距离进行排序
			sort.SliceStable(clusters[i], func(a, b int) bool {
				return CalculateWeightedDistance(clusters[i][a], medoids[i]) < CalculateWeightedDistance(clusters[i][b], medoids[i])
			})
			// ---划分到次相似的簇
			for j := maxNodesPerCluster; j < len(clusters[i]); j++ {
				nextCluster := (i + 1) % k // Next cluster index (wrap around if last cluster)
				clusters[nextCluster] = append(clusters[nextCluster], clusters[i][j])
			}
			// ---将节点移除
			clusters[i] = clusters[i][:maxNodesPerCluster]
		}
	}

	return medoids, clusters
}

// ---计算每个簇的总代价（簇中所有节点与簇中心的加权欧氏距离之和）
func calculateClusterCost(cluster []shard.Node, medoid shard.Node) float64 {
	cost := 0.0
	for _, node := range cluster {
		cost += CalculateWeightedDistance(node, medoid)
	}
	return cost
}
