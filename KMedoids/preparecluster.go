package KMedoids

import (
	"blockEmulator/core"
	"blockEmulator/shard"
	"math"
)

// ---获取节点之间的交互频率
func CalculateInteractionFrequency(transactions []*core.Transaction) map[string]map[string]float64 {
	// 初始化节点间交互频率映射
	interactionFrequency := make(map[string]map[string]float64)

	// 遍历交易记录，更新交互频率映射
	for _, tx := range transactions {
		// 检查发送者和接收者是否为空
		if tx.Sender == "" || tx.Recipient == "" {
			continue
		}
		sender := tx.Sender
		recipient := tx.Recipient
		// 检查发送者节点在映射中是否存在，如果不存在则创建
		if interactionFrequency[sender] == nil {
			interactionFrequency[sender] = make(map[string]float64)
		}
		// 检查接收者节点在映射中是否存在，如果不存在则创建
		if interactionFrequency[recipient] == nil {
			interactionFrequency[recipient] = make(map[string]float64)
		}
		// 更新交互频率
		interactionFrequency[sender][recipient]++
		interactionFrequency[recipient][sender]++
	}
	// 计算频率
	return interactionFrequency
}

// ----计算节点的相似度（余弦）

func CalculateSimilarity(node1, node2 shard.Node) float64 {
	numerator := node1.Delay*node2.Delay + node1.TransactionFrequency*node2.TransactionFrequency
	denominator := math.Sqrt(node1.Delay*node1.Delay+node1.TransactionFrequency*node1.TransactionFrequency) *
		math.Sqrt(node2.Delay*node2.Delay+node2.TransactionFrequency*node2.TransactionFrequency)
	return numerator / denominator
}

// ---计算节点之间的相似度权重（用于聚类）

func CalculateWeight(node1, node2 shard.Node) float64 {
	similarity := CalculateSimilarity(node1, node2)
	return 1 / (1 + similarity)
}

// ---计算质心和节点之间的加权距离
func CalculateWeightedDistance(node, medoid shard.Node) float64 {
	weight := CalculateWeight(node, medoid)
	delayDiff := node.Delay - medoid.Delay
	freqDiff := node.TransactionFrequency - medoid.TransactionFrequency
	return math.Sqrt(weight * (delayDiff*delayDiff + freqDiff*freqDiff))
}
