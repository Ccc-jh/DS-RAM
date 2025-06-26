// The pbft consensus process

package pbft_all

import (
	"blockEmulator/chain"
	"blockEmulator/consensus_shard/pbft_all/audit"
	"blockEmulator/consensus_shard/pbft_all/pbft_log"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/shard"
	"bufio"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

/*var allNodes map[uint64]map[uint64]PbftConsensusNode*/
var (
	ReputationMap map[uint64]map[uint64]float64
	//totalMaliciousNodes int
)

type PbftConsensusNode struct {
	// the local config about pbft
	RunningNode *shard.Node // the node information
	ShardID     uint64      // denote the ID of the shard (or pbft), only one pbft consensus in a shard
	NodeID      uint64      // denote the ID of the node in the pbft (shard)

	//ReputationMap map[uint64]map[uint64]float64

	// the data structure for blockchain
	CurChain *chain.BlockChain // all node in the shard maintain the same blockchain
	db       ethdb.Database    // to save the mpt

	// the global config about pbft
	pbftChainConfig *params.ChainConfig          // the chain config in this pbft
	ip_nodeTable    map[uint64]map[uint64]string // denote the ip of the specific node
	node_nums       uint64                       // the number of nodes in this pfbt, denoted by N
	malicious_nums  uint64                       // f, 3f + 1 = N
	view            uint64                       // denote the view of this pbft, the main node can be inferred from this variant

	// the control message and message checking utils in pbft
	sequenceID        uint64                          // the message sequence id of the pbft
	stop              bool                            // send stop signal
	pStop             chan uint64                     // channle for stopping consensus
	requestPool       map[string]*message.Request     // RequestHash to Request
	cntPrepareConfirm map[string]map[*shard.Node]bool // count the prepare confirm message, [messageHash][Node]bool
	cntCommitConfirm  map[string]map[*shard.Node]bool // count the commit confirm message, [messageHash][Node]bool
	isCommitBordcast  map[string]bool                 // denote whether the commit is broadcast
	isReply           map[string]bool                 // denote whether the message is reply
	height2Digest     map[uint64]string               // sequence (block height) -> request, fast read

	// locks about pbft
	sequenceLock sync.Mutex // the lock of sequence
	lock         sync.Mutex // lock the stage
	askForLock   sync.Mutex // lock for asking for a serise of requests
	stopLock     sync.Mutex // lock the stop varient

	// ---其他分片的消息序列号 seqID of other Shards, to synchronize
	seqIDMap   map[uint64]uint64 //---分片+序列号
	seqMapLock sync.Mutex

	// logger
	pl *pbft_log.PbftLog
	// tcp control
	tcpln       net.Listener
	tcpPoolLock sync.Mutex
	// to handle the message in the pbft
	ihm ExtraOpInConsensus
	// to handle the message outside of pbft
	ohm OpInterShards

	//  节点的划分逻辑--定义一个通道来触发节点的划分
	pNodeDiv chan uint64
	division bool //节点划分标志

	//	响应超时检测
	prepareTimeout time.Duration
	commitTimeout  time.Duration
	prepareTimers  map[string]*time.Timer
	commitTimers   map[string]*time.Timer

	//	可疑节点
	// 其他属性...

	IsSuspicious   bool // 是否被标记为可疑节点
	auditNode      *audit.AuditNode
	MaliciousNodes map[uint64]map[uint64]bool
	TimeoutNodes   map[uint64]map[uint64]bool

	//共识成功率相关变量
	totalConsensusRounds      uint64
	successfulConsensusRounds uint64
	//currentRoundInProgress    bool

	//totalMaliciousNodes int
}

// ---构造函数，创建PBFT共识节点实例  generate a pbft consensus for a node
func NewPbftNode(shardID, nodeID uint64, pcc *params.ChainConfig, messageHandleType string) *PbftConsensusNode {
	p := new(PbftConsensusNode)
	p.ip_nodeTable = params.IPmap_nodeTable
	p.node_nums = pcc.Nodes_perShard
	p.ShardID = shardID
	p.NodeID = nodeID
	p.pbftChainConfig = pcc
	fp := "./record/ldb/s" + strconv.FormatUint(shardID, 10) + "/n" + strconv.FormatUint(nodeID, 10)
	var err error
	p.db, err = rawdb.NewLevelDBDatabase(fp, 0, 1, "accountState", false)
	if err != nil {
		log.Panic(err)
	}
	//---创建区块链实例
	p.CurChain, err = chain.NewBlockChain(pcc, p.db)
	if err != nil {
		log.Panic("cannot new a blockchain")
	}
	p.RunningNode = &shard.Node{
		NodeID:  nodeID,
		ShardID: shardID,
		IPaddr:  p.ip_nodeTable[shardID][nodeID],
		//Reputation:           reputation,
		Delay:                rand.Float64() * 100,
		TransactionFrequency: rand.Float64() * 10,
	}

	//p.auditNode = auditNode

	//go auditNode.DetectMaliciousBehavior(p.RunningNode)
	p.stop = false
	p.sequenceID = p.CurChain.CurrentBlock.Header.Number + 1
	p.pStop = make(chan uint64)
	p.requestPool = make(map[string]*message.Request)
	p.cntPrepareConfirm = make(map[string]map[*shard.Node]bool)
	p.cntCommitConfirm = make(map[string]map[*shard.Node]bool)
	p.isCommitBordcast = make(map[string]bool)
	p.isReply = make(map[string]bool)
	p.height2Digest = make(map[uint64]string)

	//超时模块
	p.prepareTimeout = 5 * time.Second // 设置超时时间为5秒
	p.commitTimeout = 5 * time.Second  // 设置超时时间为5秒
	p.prepareTimers = make(map[string]*time.Timer)
	p.commitTimers = make(map[string]*time.Timer)

	//---设置恶意节点的数量
	//p.malicious_nums = (p.node_nums - 1) / 3

	//---当前视图为0
	p.view = 0
	p.seqIDMap = make(map[uint64]uint64)
	p.pl = pbft_log.NewPbftLog(shardID, nodeID)

	ReputationMap = make(map[uint64]map[uint64]float64)
	p.MaliciousNodes = make(map[uint64]map[uint64]bool)
	p.TimeoutNodes = make(map[uint64]map[uint64]bool)
	p.malicious_nums = uint64(p.TotalMaliciousNodes())
	//p.successfulConsensusRounds = 0
	//p.totalConsensusRounds = 0
	//p.currentRoundInProgress = false

	//节点划分(创建通道)
	p.pNodeDiv = make(chan uint64)
	p.division = false
	p.InitMaliciousAndTimeoutNodes()

	//p.totalMaliciousNodes = p.TotalMaliciousNodes()
	// ---选择适当的委员会处理PBFT内部或者外部的消息  choose how to handle the messages in pbft or beyond pbft

	p.ihm = &RawRelayPbftExtraHandleMod{
		pbftNode: p,
	}
	p.ohm = &RawRelayOutsideModule{
		pbftNode: p,
	}

	return p
}

// handle the raw message, send it to corresponded interfaces
func (p *PbftConsensusNode) handleMessage(msg []byte) {
	msgType, content := message.SplitMessage(msg)
	switch msgType {
	// pbft inside message type
	case message.CPrePrepare:
		go p.handlePrePrepare(content)
	case message.CPrepare:
		go p.handlePrepare(content)
	case message.CCommit:
		go p.handleCommit(content)
		go p.CalculateSuccessRate()
	case message.CRequestOldrequest:
		p.handleRequestOldSeq(content)
	case message.CSendOldrequest:
		p.handleSendOldSeq(content)
	case message.CStop:
		p.WaitToStop()
	case message.CNodeDivision:
		p.HandleNodeDiv()
	/*case message.CReputation:
	p.handleReputation()*/
	// handle the message from outside
	default:
		p.ohm.HandleMessageOutsidePBFT(msgType, content)
	}

}

func (p *PbftConsensusNode) handleClientRequest(con net.Conn) {
	defer con.Close()

	clientReader := bufio.NewReader(con)
	for {
		clientRequest, err := clientReader.ReadBytes('\n')
		if p.getStopSignal() {
			return
		}
		switch err {
		case nil:
			p.tcpPoolLock.Lock()
			//---引入节点的随机行为
			//p.randomBehavior()
			p.handleMessage(clientRequest)
			p.tcpPoolLock.Unlock()
		case io.EOF:
			log.Println("client closed the connection by terminating the process")
			return
		default:
			log.Printf("error: %v\n", err)
			return
		}
	}
}

func (p *PbftConsensusNode) TcpListen() {
	ln, err := net.Listen("tcp", p.RunningNode.IPaddr)
	p.tcpln = ln
	if err != nil {
		log.Panic(err)
	}

	for {

		conn, err := p.tcpln.Accept()
		if err != nil {
			return
		}

		go p.handleClientRequest(conn)
	}

}

// listen to the request
func (p *PbftConsensusNode) OldTcpListen() {
	ipaddr, err := net.ResolveTCPAddr("tcp", p.RunningNode.IPaddr)
	if err != nil {
		log.Panic(err)
	}
	ln, err := net.ListenTCP("tcp", ipaddr)
	p.tcpln = ln
	if err != nil {
		log.Panic(err)
	}
	p.pl.Plog.Printf("S%dN%d begins listening：%s\n", p.ShardID, p.NodeID, p.RunningNode.IPaddr)

	for {
		if p.getStopSignal() {
			p.closePbft()
			return
		}
		conn, err := p.tcpln.Accept()
		if err != nil {
			log.Panic(err)
		}
		b, err := io.ReadAll(conn)
		if err != nil {
			log.Panic(err)
		}
		p.handleMessage(b)
		conn.(*net.TCPConn).SetLinger(0)
		defer conn.Close()
	}
}

// when received stop
func (p *PbftConsensusNode) WaitToStop() {
	p.pl.Plog.Println("handling stop message")
	p.stopLock.Lock()
	p.stop = true
	p.stopLock.Unlock()
	if p.NodeID == p.view {
		p.pStop <- 1
	}
	networks.CloseAllConnInPool()
	p.tcpln.Close()
	p.closePbft()
	p.pl.Plog.Println("handled stop message")
}

func (p *PbftConsensusNode) getStopSignal() bool {
	p.stopLock.Lock()
	defer p.stopLock.Unlock()
	return p.stop
}

// close the pbft
func (p *PbftConsensusNode) closePbft() {
	p.CurChain.CloseBlockChain()
}

func (p *PbftConsensusNode) HandleNodeDiv() {
	p.pl.Plog.Println("在这里执行节点划分逻辑")
}
func (p *PbftConsensusNode) InitMaliciousAndTimeoutNodes() {
	shardCount := len(p.ip_nodeTable)
	nodesPerShard := int(p.node_nums)
	maliciousRatio := 0.2 // 20%为恶意节点
	timeoutRatio := 0.3   // 30%为超时节点
	for shardID := 0; shardID < shardCount; shardID++ {
		nodeIDs := make([]uint64, 0, nodesPerShard)
		for i := 0; i < nodesPerShard; i++ {
			nodeIDs = append(nodeIDs, uint64(i))
		}
		// 打乱顺序
		rand.Shuffle(len(nodeIDs), func(i, j int) {
			nodeIDs[i], nodeIDs[j] = nodeIDs[j], nodeIDs[i]
		})

		maliciousNum := int(float64(nodesPerShard) * maliciousRatio)
		timeoutNum := int(float64(nodesPerShard) * timeoutRatio)

		maliciousNodes := nodeIDs[:maliciousNum]
		timeoutNodes := nodeIDs[maliciousNum : maliciousNum+timeoutNum]

		p.SetMaliciousNodes(uint64(shardID), maliciousNodes)
		p.SetTimeoutNodes(uint64(shardID), timeoutNodes)
	}
}
func (p *PbftConsensusNode) TotalMaliciousNodes() int {
	totalMaliciousNodes := 0
	// 检查分片 0 是否存在
	if nodes, exists := p.TimeoutNodes[0]; exists {
		// 遍历节点并计数
		totalMaliciousNodes = len(nodes)
	}
	return totalMaliciousNodes
}

// 计算共识成功率
func (p *PbftConsensusNode) CalculateSuccessRate() float64 {
	if p.totalConsensusRounds == 0 {
		p.pl.Plog.Printf("totalConsensusRounds is 0\n")
	}
	successRate := float64(p.successfulConsensusRounds) / float64(p.totalConsensusRounds)
	p.pl.Plog.Printf("successRate: %.2f%%((successRounds: %d, TotalRounds: %d))\n", successRate*100, p.successfulConsensusRounds, p.totalConsensusRounds)
	return successRate
}
