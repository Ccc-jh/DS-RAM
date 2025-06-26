package node_status

import (
	"blockEmulator/consensus_shard/pbft_all"
)

const (
	CandidateMainNodes = iota
	ConsensusNodes
	CandidateNodes
)

func DetermineNodeRole(reputation float64) int {
	if reputation > 80 {
		return CandidateMainNodes
	} else if reputation > 50 {
		return ConsensusNodes
	} else {
		return CandidateNodes
	}
}

/*type NodeRole interface {
	HandleMessage(message []byte)
}*/

// 候选主节点

type CandidateMasterNode struct {
	// 候选主节点特有的字段...
	CMNode     *pbft_all.PbftConsensusNode
	IsMainNode bool //是否为主节点
}

/*func NewCandidateMasterNode(shardID, nodeID uint64, pcc *params.ChainConfig, messageHandleType string) *CandidateMasterNode {
	cm := new(CandidateMasterNode)

}*/
