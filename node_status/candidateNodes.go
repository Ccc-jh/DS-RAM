package node_status

import (
	"blockEmulator/chain"
	"blockEmulator/consensus_shard/pbft_all/pbft_log"
	"blockEmulator/params"
	"blockEmulator/shard"
	"github.com/ethereum/go-ethereum/ethdb"
	"net"
	"sync"
)

type CandidateNode struct {
	// 候选节点特有的字段...
	RunningNode *shard.Node // 节点信息
	ShardID     uint64      // 分片ID
	NodeID      uint64      // 节点ID

	// 数据结构
	CurChain *chain.BlockChain // 区块链
	db       ethdb.Database    // 用于保存MPT

	// PBFT配置
	pbftChainConfig *params.ChainConfig // PBFT链配置

	// 锁
	sequenceLock sync.Mutex // 序列锁
	lock         sync.Mutex // 阶段锁
	askForLock   sync.Mutex // 请求锁
	stopLock     sync.Mutex // 停止锁

	// 日志记录
	pl *pbft_log.PbftLog
	// TCP控制
	tcpln       net.Listener
	tcpPoolLock sync.Mutex

	// 处理PBFT消息(分片内)
	ihm NodeDivExtraOpInConsensus
	// 处理分片间消息（分片间）
	ohm NodeDivOpInterShards
}
