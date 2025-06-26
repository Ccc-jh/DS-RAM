package message

import (
	"blockEmulator/core"
	"blockEmulator/shard"
	"encoding/json"
	"time"
)

var prefixMSGtypeLen = 30

type MessageType string
type RequestType string

const (
	CPrePrepare        MessageType = "preprepare"
	CPrepare           MessageType = "prepare"
	CCommit            MessageType = "commit"
	CRequestOldrequest MessageType = "requestOldrequest"
	CSendOldrequest    MessageType = "sendOldrequest"
	CStop              MessageType = "stop"

	CRelay  MessageType = "relay"
	CInject MessageType = "inject"

	CBlockInfo MessageType = "BlockInfo"
	CSeqIDinfo MessageType = "SequenceID"

	CNodeDivision MessageType = "nodeDivision"

	//用来将节点的身份发送到supervisor
	CRegisterNodeMessage        MessageType = "RegisterNode"
	CCandidateMasterNodeMessage MessageType = "CandidateMasterNode"
	CStarMessge                 MessageType = "StartProcessingMessage"
	CFinishMessage              MessageType = "FinishProcessingMessage"
	CReputationMessage          MessageType = "ReputationMessage"
	CMaliciousNodeMessage       MessageType = "MaliciousNodeMessage"
	CTimeoutMessage             MessageType = "TimeoutNodeMessage"

	CConsensusRateMessage MessageType = "ConsensusRateMessage"
)

var (
	BlockRequest RequestType = "Block"
	// add more types
	// ...
)

// 节点注册消息
type RegisterNode struct {
	NodeID     uint64
	ShardID    uint64
	Role       string
	IsMainNode bool
	SeqID      uint64
}

// 候选主节点消息
type CandidateMasterNodeMessage struct {
	NodeID     uint64
	ShardID    uint64
	IsMainNode bool
}

// 信誉消息
type ReputationMessage struct {
	NodeID     uint64
	ShardID    uint64
	Reputation float64
}

// 开始处理消息
type StartProcessingMessage struct {
	NodeID  uint64
	ShardID uint64
}

// 结束处理消息
type FinishProcessingMessage struct {
	NodeIDs []uint64
	ShardID uint64
	NodeId  uint64
}

type MaliciousNodeMessage struct {
	ShardID uint64
	NodeIDs []uint64
}

type TimeoutNodeMessage struct {
	ShardID uint64
	NodeIDs []uint64
	NodeId  uint64
}

// 共识率相关
type ConsensusRateMessage struct {
	ShardID              uint64
	TotalConsensusRounds uint64
	SuccessfulRounds     uint64
}

type RawMessage struct {
	Content []byte // the content of raw message, txs and blocks (most cases) included
}

type Request struct {
	RequestType RequestType
	Msg         RawMessage // request message
	ReqTime     time.Time  // request time
}

type PrePrepare struct {
	RequestMsg *Request // the request message should be pre-prepared
	Digest     []byte   // the digest of this request, which is the only identifier
	SeqID      uint64
}

type Prepare struct {
	Digest     []byte // To identify which request is prepared by this node
	SeqID      uint64
	SenderNode *shard.Node // To identify who send this message
}

type Commit struct {
	Digest     []byte // To identify which request is prepared by this node
	SeqID      uint64
	SenderNode *shard.Node // To identify who send this message
}

type Reply struct {
	MessageID  uint64
	SenderNode *shard.Node
	Result     bool
}

type RequestOldMessage struct {
	SeqStartHeight uint64
	SeqEndHeight   uint64
	ServerNode     *shard.Node // send this request to the server node
	SenderNode     *shard.Node
}

type SendOldMessage struct {
	SeqStartHeight uint64
	SeqEndHeight   uint64
	OldRequest     []*Request
	SenderNode     *shard.Node
}

type InjectTxs struct {
	Txs       []*core.Transaction
	ToShardID uint64
}

type BlockInfoMsg struct {
	BlockBodyLength int
	ExcutedTxs      []*core.Transaction // txs which are excuted completely
	Epoch           int

	ProposeTime   time.Time // record the propose time of this block (txs)
	CommitTime    time.Time // record the commit time of this block (txs)
	SenderShardID uint64

	// for transaction relay
	Relay1TxNum uint64              // the number of cross shard txs
	Relay1Txs   []*core.Transaction // cross transactions in chain first time

	// for broker
	Broker1TxNum uint64              // the number of broker 1
	Broker1Txs   []*core.Transaction // cross transactions at first time by broker
	Broker2TxNum uint64              // the number of broker 2
	Broker2Txs   []*core.Transaction // cross transactions at second time by broker
}

type SeqIDinfo struct {
	SenderShardID uint64
	SenderSeq     uint64
}

func MergeMessage(msgType MessageType, content []byte) []byte {
	b := make([]byte, prefixMSGtypeLen)
	for i, v := range []byte(msgType) {
		b[i] = v
	}
	merge := append(b, content...)
	return merge
}

func SplitMessage(message []byte) (MessageType, []byte) {
	msgTypeBytes := message[:prefixMSGtypeLen]
	msgType_pruned := make([]byte, 0)
	for _, v := range msgTypeBytes {
		if v != byte(0) {
			msgType_pruned = append(msgType_pruned, v)
		}
	}
	msgType := string(msgType_pruned)
	content := message[prefixMSGtypeLen:]
	return MessageType(msgType), content
}

// 将消息编码为 JSON 字符串
func (msg *RegisterNode) Encode1() []byte {
	data, _ := json.Marshal(msg)
	return data
}

// 从 JSON 字符串解码为消息结构
func DecodeRegisterNodeMessage(data []byte) (*RegisterNode, error) {
	var msg RegisterNode
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}
