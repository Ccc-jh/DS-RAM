package node_status

import (
	"blockEmulator/chain"
	"blockEmulator/consensus_shard/pbft_all/pbft_log"
	"blockEmulator/params"
	"blockEmulator/shard"
	"net"
	"sync"

	"github.com/ethereum/go-ethereum/ethdb"
)

type CandidateNode struct {
	RunningNode *shard.Node
	ShardID     uint64
	NodeID      uint64

	CurChain        *chain.BlockChain
	db              ethdb.Database
	pbftChainConfig *params.ChainConfig

	sequenceLock sync.Mutex
	lock         sync.Mutex
	askForLock   sync.Mutex
	stopLock     sync.Mutex

	pl *pbft_log.PbftLog

	tcpln       net.Listener
	tcpPoolLock sync.Mutex
	ihm         NodeDivExtraOpInConsensus
	ohm         NodeDivOpInterShards
}
