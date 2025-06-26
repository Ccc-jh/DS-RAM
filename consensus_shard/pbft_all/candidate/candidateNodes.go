package candidate

import (
	"blockEmulator/chain"
	"blockEmulator/consensus_shard/pbft_all/candidate/candidate_log"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/shard"
	"bufio"
	"encoding/json"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
)

type PbftCandidateNode struct {
	// the local config about pbft
	RunningNode *shard.Node // ---当前共识节点的信息the node information
	ShardID     uint64      // denote the ID of the shard (or pbft), only one pbft consensus in a shard
	NodeID      uint64      // denote the ID of the node in the pbft (shard)

	CurChain *chain.BlockChain
	db       ethdb.Database

	pbftChainConfig *params.ChainConfig          //---链的配置信息 the chain config in this pbft
	ip_nodeTable    map[uint64]map[uint64]string // ---节点ID到IP地址的映射表denote the ip of the specific node
	node_nums       uint64                       // the number of nodes in this pfbt, denoted by N
	view            uint64

	sequenceID  uint64
	pStop       chan uint64
	stop        bool
	requestPool map[string]*message.Request
	isReply     map[string]bool

	// the global config about pbft

	sequenceLock sync.Mutex // the lock of sequence
	lock         sync.Mutex // lock the stage
	askForLock   sync.Mutex // lock for asking for a serise of requests
	stopLock     sync.Mutex // lock the stop varient
	//malicious_nums  uint64                       // ---恶意节点的数量f, 3f + 1 = N

	// logger
	cl *candidate_log.CandidateLog
	// tcp control
	tcpln net.Listener

	tcpPoolLock sync.Mutex
}

func NewCandidateNode(shardID, nodeID uint64, pcc *params.ChainConfig) *PbftCandidateNode {
	c := new(PbftCandidateNode)
	c.ip_nodeTable = params.IPmap_nodeTable
	if c.ip_nodeTable == nil {
		log.Panic("IPmap_nodeTable is nil")
	}
	c.node_nums = pcc.Nodes_perShard
	c.ShardID = shardID
	c.NodeID = nodeID
	c.pbftChainConfig = pcc
	c.requestPool = make(map[string]*message.Request)

	fp := "./record/ldb/s" + strconv.FormatUint(shardID, 10) + "/n" + strconv.FormatUint(nodeID, 10)
	var err error
	//---创建了一个LevelDB数据库
	c.db, err = rawdb.NewLevelDBDatabase(fp, 0, 1, "accountState", false)
	if err != nil {
		log.Panic(err)
	}
	c.CurChain, err = chain.NewBlockChain(pcc, c.db)
	if err != nil {
		log.Panic("cannot new a blockchain")
	}

	c.RunningNode = &shard.Node{
		NodeID:  nodeID,
		ShardID: shardID,
		IPaddr:  c.ip_nodeTable[shardID][nodeID],
		//Reputation:           reputation,
		Delay:                rand.Float64() * 100,
		TransactionFrequency: rand.Float64() * 10,
	}
	c.stop = false
	c.pStop = make(chan uint64)
	c.view = 0
	c.isReply = make(map[string]bool)
	c.sequenceID = c.CurChain.CurrentBlock.Header.Number + 1

	c.cl = candidate_log.NewPbftLog(shardID, nodeID)

	return c
}

func (c *PbftCandidateNode) PrintCanMessg() {
	c.cl.Plog.Println("我是候选节点")
}

func (c *PbftCandidateNode) handleMessage(msg []byte) {
	msgType, content := message.SplitMessage(msg)
	switch msgType {
	case message.CCommit:
		c.handleCanCommit(content)
	case message.CStop:
		c.WaitToStop()
	default:
		c.PrintCanMessg()
	}

}

// when received stop
func (c *PbftCandidateNode) WaitToStop() {
	c.cl.Plog.Println("handling stop message")
	c.stopLock.Lock()
	c.stop = true
	c.stopLock.Unlock()
	if c.NodeID == c.view {
		c.pStop <- 1
	}
	networks.CloseAllConnInPool()
	c.tcpln.Close()
	c.closePbft()
	c.cl.Plog.Println("handled stop message")
}
func (c *PbftCandidateNode) closePbft() {
	c.CurChain.CloseBlockChain()
}

// ---TCP监听器，接受来自其他节点的请求并处理
func (c *PbftCandidateNode) TcpListen() {
	//---利用当前节点IP和端口创建TCP监听器
	ln, err := net.Listen("tcp", c.RunningNode.IPaddr)
	c.tcpln = ln
	if err != nil {
		log.Panic(err)
	}
	for {
		conn, err := c.tcpln.Accept()
		if err != nil {
			return
		}
		//---在循环中启动新线程，实现同时处理多个请求
		go c.handleClientRequest(conn)
	}
}

// ---处理客户的请求消息
func (c *PbftCandidateNode) handleClientRequest(con net.Conn) {
	defer con.Close()
	clientReader := bufio.NewReader(con)
	for {
		//---不断读取数据
		clientRequest, err := clientReader.ReadBytes('\n')
		//---是否接收到停止信号
		if c.getStopSignal() {
			return
		}
		switch err {
		case nil:
			c.tcpPoolLock.Lock()
			c.handleMessage(clientRequest)
			c.tcpPoolLock.Unlock()
		case io.EOF:
			log.Println("client closed the connection by terminating the process")
			return
		default:
			log.Printf("error: %v\n", err)
			return
		}
	}
}

func (c *PbftCandidateNode) getStopSignal() bool {
	c.stopLock.Lock()
	defer c.stopLock.Unlock()
	return c.stop
}

func (c *PbftCandidateNode) handleCanCommit(content []byte) {
	cmsg := new(message.Commit)
	err := json.Unmarshal(content, cmsg)
	if err != nil {
		log.Panic(err)
	}
	c.cl.Plog.Printf("S%dN%d received the Commit from ...%d\n", c.ShardID, c.NodeID, cmsg.SenderNode.NodeID)
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.isReply[string(cmsg.Digest)] {
		return
	}
	if _, ok := c.requestPool[string(cmsg.Digest)]; !ok {
		c.isReply[string(cmsg.Digest)] = true
		c.askForLock.Lock()
		sn := &shard.Node{
			NodeID:  c.view,
			ShardID: c.ShardID,
			IPaddr:  c.ip_nodeTable[c.ShardID][c.view],
		}
		orequest := message.RequestOldMessage{
			SeqStartHeight: c.sequenceID + 1,
			SeqEndHeight:   cmsg.SeqID,
			ServerNode:     sn,
			SenderNode:     c.RunningNode,
		}
		bromyte, err := json.Marshal(orequest)
		if err != nil {
			log.Panic()
		}

		c.cl.Plog.Printf("S%dN%d : is now requesting message (seq %d to %d) ... \n", c.ShardID, c.NodeID, orequest.SeqStartHeight, orequest.SeqEndHeight)
		msg_send := message.MergeMessage(message.CRequestOldrequest, bromyte)
		networks.TcpDial(msg_send, orequest.ServerNode.IPaddr)
	} else {
		// 更新状态或记录共识结果
		//c.ihm.HandleinCommit(cmsg)
		c.isReply[string(cmsg.Digest)] = true
		c.cl.Plog.Printf("S%dN%d: this round of pbft %d is end \n", c.ShardID, c.NodeID, c.sequenceID)
		c.sequenceID += 1
	}
}
