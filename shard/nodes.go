// definition of node and shard

package shard

import (
	"fmt"
	"math/rand"
)

// 定义节点类型
const (
	ConsensusNodeType       = "ConsensusNode"
	CandidateNodeType       = "CandidateNode"
	CandidateMasterNodeType = "CandidateMasterNode"
)

type Node struct {
	NodeID               uint64
	ShardID              uint64  // Shard ID before clustering
	IPaddr               string  // IP address
	Delay                float64 // Node communication delay
	TransactionFrequency float64 // Node transaction frequency
	ShardAfter           uint64  // Shard ID after clustering
	Reputation           float64 //Node reputation value

	Role string //Node Type

}

func (n *Node) PrintNode() {
	v := []interface{}{
		n.NodeID,
		n.ShardID,
		n.IPaddr,
		n.Delay,
		n.TransactionFrequency,
		n.ShardAfter,
	}
	fmt.Printf("%v\n", v)
}
func (n *Node) GetNodeReputationInfo() []interface{} {
	return []interface{}{
		n.NodeID,
		n.ShardID,
		n.ShardAfter,
		n.Reputation,
	}
}

func GenerateNodes(snm, nnm uint64, interactionFrequency map[string]map[string]float64) []Node {
	nodes := make([]Node, 0)
	for i := uint64(0); i < snm; i++ {
		for j := uint64(0); j < nnm; j++ {
			nodeID := i*nnm + j
			nodes = append(nodes, Node{
				NodeID:               nodeID,
				ShardID:              i,
				Delay:                rand.Float64() * 120,
				TransactionFrequency: calculateAverageFrequency(interactionFrequency), //Node transaction frequency
			})
		}
	}

	return nodes
}

// Calculate node interaction frequency
func calculateAverageFrequency(interactionFreq map[string]map[string]float64) float64 {
	totalFreq := 0.0
	nodeCount := len(interactionFreq)

	// Iterate through the interaction frequency of each node
	for _, freqMap := range interactionFreq {
		// For each node, accumulate its interaction frequency with other nodes
		for _, freq := range freqMap {
			totalFreq += freq
		}
	}

	// Calculate average frequency
	if nodeCount > 0 {
		return totalFreq / float64(nodeCount)
	} else {
		return 0.0
	}
}
