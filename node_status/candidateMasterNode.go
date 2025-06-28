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

type CandidateMasterNode struct {
	CMNode     *pbft_all.PbftConsensusNode
	IsMainNode bool
}
