package KMedoids

import (
	"blockEmulator/core"
	"blockEmulator/shard"
	"math"
)

// Obtain the interaction frequency between nodes.
func CalculateInteractionFrequency(transactions []*core.Transaction) map[string]map[string]float64 {
	// Initialize the interaction frequency map between nodes.
	interactionFrequency := make(map[string]map[string]float64)

	// Traverse the transaction records and update the interaction frequency map.
	for _, tx := range transactions {
		// Check if the sender and recipient are empty.

		if tx.Sender == "" || tx.Recipient == "" {
			continue
		}
		sender := tx.Sender
		recipient := tx.Recipient
		if interactionFrequency[sender] == nil {
			interactionFrequency[sender] = make(map[string]float64)
		}
		if interactionFrequency[recipient] == nil {
			interactionFrequency[recipient] = make(map[string]float64)
		}
		interactionFrequency[sender][recipient]++
		interactionFrequency[recipient][sender]++
	}
	// Calculate the frequency.
	return interactionFrequency
}

// Calculate the similarity between nodes
func CalculateSimilarity(node1, node2 shard.Node) float64 {
	numerator := node1.Delay*node2.Delay + node1.TransactionFrequency*node2.TransactionFrequency
	denominator := math.Sqrt(node1.Delay*node1.Delay+node1.TransactionFrequency*node1.TransactionFrequency) *
		math.Sqrt(node2.Delay*node2.Delay+node2.TransactionFrequency*node2.TransactionFrequency)
	return numerator / denominator
}

func CalculateWeight(node1, node2 shard.Node) float64 {
	similarity := CalculateSimilarity(node1, node2)
	return 1 / (1 + similarity)
}

func CalculateWeightedDistance(node, medoid shard.Node) float64 {
	weight := CalculateWeight(node, medoid)
	delayDiff := node.Delay - medoid.Delay
	freqDiff := node.TransactionFrequency - medoid.TransactionFrequency
	return math.Sqrt(weight * (delayDiff*delayDiff + freqDiff*freqDiff))
}
