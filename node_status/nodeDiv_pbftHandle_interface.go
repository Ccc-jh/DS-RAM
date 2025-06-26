package node_status

import "blockEmulator/message"

type NodeDivExtraOpInConsensus interface {
	NodeDivHandleinCommitResult(*message.Commit) bool
	// do for need

}

type NodeDivOpInterShards interface {
	// operation inter-shards
	NodeDivHandleMessageOutsidePBFT(message.MessageType, []byte) bool
}
