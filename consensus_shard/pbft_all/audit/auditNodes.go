package audit

import (
	"blockEmulator/chain"
	"blockEmulator/consensus_shard/pbft_all/audit/audit_log"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/shard"
	"bufio"
	"encoding/json"
	"fmt"
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

var AuditNodeMap = make(map[uint64]map[uint64]bool)

const (
	MaxMsgCount        = 100
	MaxTimeoutCount    = 10
	MaxBlockSubmit     = 50
	MaxReputationDelta = 20
)

type NodeBehaviorStats struct {
	MsgCount          int       // 消息数
	LastMsgTime       time.Time // 上次消息时间
	BlockSubmitCount  int       // 区块提交数
	LastBlockTime     time.Time // 上次区块提交时间
	Reputation        float64   // 当前信誉
	ReputationHistory []float64 // 信誉历史
	IsIsolated        bool      // 是否被隔离
	IsolationEnd      time.Time // 隔离结束时间
	SuspiciousScore   float64   // 可疑分数
	TimeoutCount      int       // 超时次数
	AbnormalChange    bool      // 信誉突变标记
}
type AuditNode struct {
	// the local config about pbft
	RunningNode *shard.Node // the node information
	ShardID     uint64      // denote the ID of the shard (or pbft), only one pbft consensus in a shard
	NodeID      uint64      // denote the ID of the node in the pbft (shard)

	CurChain *chain.BlockChain
	db       ethdb.Database

	pbftChainConfig *params.ChainConfig          // the chain config in this pbft
	ip_nodeTable    map[uint64]map[uint64]string // denote the ip of the specific node
	node_nums       uint64                       // the number of nodes in this pfbt, denoted by N
	view            uint64

	sequenceID  uint64
	pStop       chan uint64
	stop        bool
	requestPool map[string]*message.Request
	isReply     map[string]bool

	// the global config about pbft

	lock       sync.Mutex // lock the stage
	askForLock sync.Mutex // lock for asking for a serise of requests
	stopLock   sync.Mutex // lock the stop varient

	// logger
	al *audit_log.AuditLog
	// tcp control
	tcpln net.Listener

	tcpPoolLock sync.Mutex

	//	响应超时模块
	//TimeoutNodes           map[uint64]bool
	SuspiciousNodes      map[uint64]bool // suspicious nodes set
	processingStartTimes map[uint64]time.Time
	processingDurations  map[uint64]time.Duration

	totalMaliciousNodes            int //总共监督的共识节点的数量(全部分片)
	detectedMaliciousNodes         int //检测到恶意节点的数量
	LowReputationNodes             map[uint64]map[uint64]bool
	TimeoutNodes                   map[uint64]map[uint64]bool
	detectedNodes                  map[uint64]bool
	totalMaliciousNodesPerShard    map[uint64]int             //每个分片中的恶意节点总数
	DetectedMaliciousNodesPerShard map[uint64]int             //每个分片检测到的恶意节点总数
	InitTimeoutNode                map[uint64]map[uint64]bool //存放本身就是恶意节点
	IsSuspiciousNodesPerShard      map[uint64]map[uint64]bool
	misjudgedNodesSet              map[uint64]bool // 存放误判节点的集合，避免重复计数
	suspectedNodesSet              map[uint64]bool // 存放已标记为可疑的节点集合，避免重复计数
	totalSuspected                 int
	misjudgedNodes                 int

	NodeStats      map[uint64]*NodeBehaviorStats
	IsolationVotes map[uint64]map[uint64]bool // nodeID -> voterID -> agree
}

func NewAuditNode(shardID, nodeID uint64, pcc *params.ChainConfig) *AuditNode {
	a := new(AuditNode)
	a.ip_nodeTable = params.IPmap_nodeTable
	if a.ip_nodeTable == nil {
		log.Panic("IPmap_nodeTable is nil")
	}
	a.node_nums = pcc.Nodes_perShard
	a.ShardID = shardID
	a.NodeID = nodeID
	a.pbftChainConfig = pcc
	a.requestPool = make(map[string]*message.Request)

	fp := "./record/ldb/s" + strconv.FormatUint(shardID, 10) + "/a" + strconv.FormatUint(nodeID, 10)
	var err error
	//---创建了一个LevelDB数据库
	a.db, err = rawdb.NewLevelDBDatabase(fp, 0, 1, "accountState", false)

	if err != nil {
		log.Panic(err)
	}
	a.CurChain, err = chain.NewBlockChain(pcc, a.db)

	if err != nil {
		log.Panic("cannot new a blockchain")
	}

	a.RunningNode = &shard.Node{
		NodeID:  nodeID,
		ShardID: shardID,
		IPaddr:  a.ip_nodeTable[shardID][nodeID],
		//Reputation:           reputation,
		Delay:                rand.Float64() * 100,
		TransactionFrequency: rand.Float64() * 10,
	}
	a.stop = false
	a.pStop = make(chan uint64)
	a.view = 0
	a.isReply = make(map[string]bool)
	a.sequenceID = a.CurChain.CurrentBlock.Header.Number + 1

	a.SuspiciousNodes = make(map[uint64]bool)
	a.processingStartTimes = make(map[uint64]time.Time)
	a.detectedMaliciousNodes = 0
	a.totalMaliciousNodes = 0
	a.LowReputationNodes = make(map[uint64]map[uint64]bool)
	a.TimeoutNodes = make(map[uint64]map[uint64]bool)
	a.al = audit_log.NewPbftLog(shardID, nodeID)
	a.processingDurations = make(map[uint64]time.Duration)
	a.detectedNodes = make(map[uint64]bool)
	a.DetectedMaliciousNodesPerShard = make(map[uint64]int)
	a.InitTimeoutNode = make(map[uint64]map[uint64]bool)
	a.IsSuspiciousNodesPerShard = make(map[uint64]map[uint64]bool)
	a.misjudgedNodesSet = make(map[uint64]bool)
	a.suspectedNodesSet = make(map[uint64]bool)
	a.totalSuspected = 0
	a.misjudgedNodes = 0

	a.NodeStats = make(map[uint64]*NodeBehaviorStats)
	a.IsolationVotes = make(map[uint64]map[uint64]bool)
	return a
}

// 判断某节点是否为审计节点
func IsAuditNode(shardID, nodeID uint64) bool {
	if nodes, ok := AuditNodeMap[shardID]; ok {
		return nodes[nodeID]
	}
	return false
}
func (a *AuditNode) handleMessage(msg []byte) {
	if !IsAuditNode(a.ShardID, a.NodeID) {
		return // 非审计节点不处理
	}
	msgType, content := message.SplitMessage(msg)
	switch msgType {
	case message.CCommit:
		a.handleAuditCommit(content)
	case message.CStarMessge:
		a.handleStartTime(content)
	case message.CFinishMessage:
		a.handleFinishTime(content)
	case message.CMaliciousNodeMessage:
		a.handleMaliciousNodeInfo(content)
	case message.CTimeoutMessage:
		a.handleTimeoutNodeInfo(content)
	case message.CConsensusRateMessage:
		a.handleConsensusMessage(content)
	case message.CStop:
		a.WaitToStop(content)
	default:
		a.PrintAudMessg()
	}

}

func (a *AuditNode) PrintAudMessg() {
	a.al.Plog.Println("我是审计节点")
}

func (c *AuditNode) TcpListen() {
	ln, err := net.Listen("tcp", c.RunningNode.IPaddr)
	c.tcpln = ln
	if err != nil {
		log.Panic(err)
	}

	// 启动一个 goroutine 定期检查隔离恢复
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			c.checkIsolationRecovery()
		}
	}()

	for {
		conn, err := c.tcpln.Accept()
		if err != nil {
			return
		}
		go c.handleClientRequest(conn)
	}
}

func (a *AuditNode) handleClientRequest(con net.Conn) {
	defer con.Close()
	clientReader := bufio.NewReader(con)
	for {
		clientRequest, err := clientReader.ReadBytes('\n')
		if a.getStopSignal() {
			return
		}
		switch err {
		case nil:
			a.tcpPoolLock.Lock()
			a.handleMessage(clientRequest)
			a.tcpPoolLock.Unlock()
		case io.EOF:
			log.Println("client closed the connection by terminating the process")
			return
		default:
			log.Printf("error: %v\n", err)
			return
		}
	}
}

func (a *AuditNode) getStopSignal() bool {
	a.stopLock.Lock()
	defer a.stopLock.Unlock()
	return a.stop
}

// when received stop
func (a *AuditNode) WaitToStop(content []byte) {
	stopMsg := new(message.StartProcessingMessage)
	err := json.Unmarshal(content, stopMsg)
	if err != nil {
		log.Panic(err)
	}
	a.al.Plog.Println("handling stop message")
	a.stopLock.Lock()
	a.stop = true
	a.stopLock.Unlock()

	if a.NodeID == a.view {
		a.pStop <- 1
	}

	networks.CloseAllConnInPool()
	a.tcpln.Close()
	a.closePbft()

	a.al.Plog.Println("handled stop message")
}
func (a *AuditNode) closePbft() {
	a.CurChain.CloseBlockChain()
}

// Handle Start Message
func (a *AuditNode) handleStartTime(content []byte) {
	startMsg := new(message.StartProcessingMessage)
	err := json.Unmarshal(content, startMsg)
	if err != nil {
		log.Panic(err)
	}
	a.processingStartTimes[startMsg.NodeID] = time.Now()
	a.updateNodeBehavior(startMsg.NodeID, "start")

}

// Handle Completion Message and Perform Timeout Marking
func (a *AuditNode) handleFinishTime(content []byte) {
	finishMsg := new(message.FinishProcessingMessage)
	err := json.Unmarshal(content, finishMsg)
	if err != nil {
		log.Panic(err)
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	startTime, ok := a.processingStartTimes[finishMsg.NodeId]
	if !ok {
		return
	}
	processDuration := time.Since(startTime)
	a.processingDurations[finishMsg.NodeId] = processDuration

	// a.al.Plog.Printf("A%dN%d: Processing time for node S%dN%d is %s\n", a.ShardID, a.NodeID, finishMsg.ShardID, finishMsg.NodeId, processDuration.String())

	timeoutNodeMsg := new(message.TimeoutNodeMessage)
	err1 := json.Unmarshal(content, &timeoutNodeMsg)
	if err1 != nil {
		log.Panic(err1)
	}
	if a.TimeoutNodes[timeoutNodeMsg.ShardID] == nil {
		a.TimeoutNodes[timeoutNodeMsg.ShardID] = make(map[uint64]bool)
	}
	for _, nodeID := range timeoutNodeMsg.NodeIDs {
		a.TimeoutNodes[timeoutNodeMsg.ShardID][nodeID] = true
	}
	//a.al.Plog.Printf("Supervisor: received malicious node info for ShardID %d: %v\n", timeoutNodeMsg.ShardID, timeoutNodeMsg.NodeIDs)

	a.checkTimeout(timeoutNodeMsg, processDuration)
	a.updateNodeBehavior(finishMsg.NodeId, "finish")

}

func (a *AuditNode) handleAuditCommit(content []byte) {
	cmsg := new(message.Commit)
	err := json.Unmarshal(content, cmsg)
	if err != nil {
		log.Panic(err)
	}
	a.al.Plog.Printf("A%dN%d received the Commit from ...%d\n", a.ShardID, a.NodeID, cmsg.SenderNode.NodeID)
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.isReply[string(cmsg.Digest)] {
		return
	}

	if _, ok := a.requestPool[string(cmsg.Digest)]; !ok {
		a.isReply[string(cmsg.Digest)] = true
		a.askForLock.Lock()
		sn := &shard.Node{
			NodeID:  a.view,
			ShardID: a.ShardID,
			IPaddr:  a.ip_nodeTable[a.ShardID][a.view],
		}
		orequest := message.RequestOldMessage{
			SeqStartHeight: a.sequenceID + 1,
			SeqEndHeight:   cmsg.SeqID,
			ServerNode:     sn,
			SenderNode:     a.RunningNode,
		}
		bromyte, err := json.Marshal(orequest)
		if err != nil {
			log.Panic()
		}

		a.al.Plog.Printf("S%dN%d : is now requesting message (seq %d to %d) ... \n", a.ShardID, a.NodeID, orequest.SeqStartHeight, orequest.SeqEndHeight)
		msg_send := message.MergeMessage(message.CRequestOldrequest, bromyte)
		networks.TcpDial(msg_send, orequest.ServerNode.IPaddr)
	} else {
		// Update Status or Record Consensus Result
		a.isReply[string(cmsg.Digest)] = true
		a.al.Plog.Printf("S%dN%d: this round of pbft %d is end \n", a.ShardID, a.NodeID, a.sequenceID)
		a.sequenceID += 1
	}
	a.updateNodeBehavior(cmsg.SenderNode.NodeID, "commit")
}

// Behavior Monitoring and Anomaly Detection
func (a *AuditNode) updateNodeBehavior(nodeID uint64, eventType string) {
	if !IsAuditNode(a.ShardID, a.NodeID) {
		return
	}
	if a.NodeStats[nodeID] == nil {
		a.NodeStats[nodeID] = &NodeBehaviorStats{
			Reputation: 60.0,
		}
	}
	stats := a.NodeStats[nodeID]
	now := time.Now()
	switch eventType {
	case "start":
		stats.MsgCount++
		stats.LastMsgTime = now
	case "finish":
		if start, ok := a.processingStartTimes[nodeID]; ok {
			resp := now.Sub(start)
			if resp > params.ResponseTimeout {
				stats.TimeoutCount++
			}
		}
	case "commit":
		stats.BlockSubmitCount++
		stats.LastBlockTime = now
	}
	// Check for Anomalous Behavior
	a.detectAbnormalBehavior(nodeID)
}

// Dynamic Anomaly Detection and Isolation
func (a *AuditNode) detectAbnormalBehavior(nodeID uint64) {
	if !IsAuditNode(a.ShardID, a.NodeID) {
		return
	}
	stats := a.NodeStats[nodeID]
	if stats.MsgCount > MaxMsgCount || stats.TimeoutCount > MaxTimeoutCount || stats.BlockSubmitCount > MaxBlockSubmit {
		stats.SuspiciousScore += 1
	}
	if len(stats.ReputationHistory) > 2 {
		delta := stats.ReputationHistory[len(stats.ReputationHistory)-1] - stats.ReputationHistory[len(stats.ReputationHistory)-2]
		if delta > MaxReputationDelta || delta < -MaxReputationDelta {
			stats.AbnormalChange = true
			stats.SuspiciousScore += 1
		}
	}
	// Initiate Isolation Voting Upon Reaching the Threshold
	if stats.SuspiciousScore > 2 && !stats.IsIsolated {
		a.broadcastIsolationProposal(nodeID)
	}
}

// 获取本分片所有审计节点ID
func (a *AuditNode) getAuditNodeIDs() []uint64 {
	var ids []uint64
	for nodeID := range AuditNodeMap[a.ShardID] {
		ids = append(ids, nodeID)
	}
	return ids
}

// Collaborative Voting and Isolation
func (a *AuditNode) broadcastIsolationProposal(nodeID uint64) {
	a.al.Plog.Printf("Audit: Proposing isolation for suspicious node %d\n", nodeID)
	for _, auditID := range a.getAuditNodeIDs() {
		if auditID == a.NodeID {
			// 本地直接投票
			a.handleIsolationVote(nodeID, a.NodeID, true)
		} else {
			// 这里应通过网络发送投票请求，简化为直接调用
			go a.simulateRemoteVote(nodeID, auditID)
		}
	}
}

// 模拟远程审计节点投票（实际应为网络RPC/消息）
func (a *AuditNode) simulateRemoteVote(targetNodeID, voterID uint64) {
	// 这里假设所有审计节点都同意隔离，可根据实际情况调整
	a.handleIsolationVote(targetNodeID, voterID, true)
}

func (a *AuditNode) handleIsolationVote(targetNodeID, voterID uint64, agree bool) {
	if a.IsolationVotes[targetNodeID] == nil {
		a.IsolationVotes[targetNodeID] = make(map[uint64]bool)
	}
	a.IsolationVotes[targetNodeID][voterID] = agree

	// 统计投票
	voteCount := 0
	agreeCount := 0
	for _, v := range a.IsolationVotes[targetNodeID] {
		voteCount++
		if v {
			agreeCount++
		}
	}
	// 多数同意则隔离
	if voteCount >= len(a.getAuditNodeIDs()) && agreeCount > voteCount/2 {
		a.NodeStats[targetNodeID].IsIsolated = true
		a.NodeStats[targetNodeID].IsolationEnd = time.Now().Add(30 * time.Second)
		a.al.Plog.Printf("Audit: Node %d is isolated by voting. \n", targetNodeID)
	}
}

// 隔离期结束后自动恢复
func (a *AuditNode) checkIsolationRecovery() {
	if !IsAuditNode(a.ShardID, a.NodeID) {
		return
	}
	for nodeID, stats := range a.NodeStats {
		if stats.IsIsolated && time.Now().After(stats.IsolationEnd) {
			stats.IsIsolated = false
			stats.SuspiciousScore = 0
			a.al.Plog.Printf("Audit: Node %d isolation ended, reputation can recover\n", nodeID)
			// 动态恢复：如果节点近期行为正常，恢复快，否则慢
			recoverStep := 5.0
			if stats.TimeoutCount == 0 && !stats.AbnormalChange {
				recoverStep = 10.0 // 行为良好，恢复更快
			}
			if stats.Reputation < 60.0 {
				stats.Reputation += recoverStep
				if stats.Reputation > 60.0 {
					stats.Reputation = 60.0
				}
				a.al.Plog.Printf("Audit: Node %d reputation recovered to %.2f\n", nodeID, stats.Reputation)
			}
			stats.ReputationHistory = append(stats.ReputationHistory, stats.Reputation)
		}
	}
}

func (a *AuditNode) handleMaliciousNodeInfo(content []byte) {
	var maliciousMsg message.MaliciousNodeMessage
	err := json.Unmarshal(content, &maliciousMsg)
	if err != nil {
		log.Panic(err)
	}
	if a.LowReputationNodes[maliciousMsg.ShardID] == nil {
		a.LowReputationNodes[maliciousMsg.ShardID] = make(map[uint64]bool)
	}
	for _, nodeID := range maliciousMsg.NodeIDs {
		a.LowReputationNodes[maliciousMsg.ShardID][nodeID] = true
	}
	a.al.Plog.Printf("Audit: received malicious node info for ShardID %d: %v\n", maliciousMsg.ShardID, maliciousMsg.NodeIDs)

	// 更新总的恶意节点数量
	a.updateTotalMaliciousNodes()
}

func (a *AuditNode) checkTimeout(timeoutNodeMsg *message.TimeoutNodeMessage, processDuration time.Duration) {
	if a.InitTimeoutNode[a.ShardID] == nil {
		a.InitTimeoutNode[a.ShardID] = make(map[uint64]bool)
	}
	if a.IsSuspiciousNodesPerShard[a.ShardID] == nil {
		a.IsSuspiciousNodesPerShard[a.ShardID] = make(map[uint64]bool)
	}
	if processDuration > params.ResponseTimeout {
		if !a.InitTimeoutNode[a.ShardID][timeoutNodeMsg.NodeId] {
			a.InitTimeoutNode[a.ShardID][timeoutNodeMsg.NodeId] = true
			if !a.IsSuspiciousNodesPerShard[a.ShardID][timeoutNodeMsg.NodeId] {
				a.DetectedMaliciousNodesPerShard[a.ShardID]++
				a.detectedMaliciousNodes++
				a.IsSuspiciousNodesPerShard[a.ShardID][timeoutNodeMsg.NodeId] = true
				a.detectedNodes[timeoutNodeMsg.NodeId] = true
			}
			a.al.Plog.Printf("A%dN%d: 节点S%dN%d 已经被标记为超时\n", a.ShardID, a.NodeID, timeoutNodeMsg.ShardID, timeoutNodeMsg.NodeId)
		} else {
			a.al.Plog.Printf("A%dN%d: 节点S%dN%d 已经被检测为超时，不重复统计\n", a.ShardID, a.NodeID, timeoutNodeMsg.ShardID, timeoutNodeMsg.NodeId)
		}
	}
	if a.TimeoutNodes[timeoutNodeMsg.ShardID][timeoutNodeMsg.NodeId] && !a.IsSuspiciousNodesPerShard[a.ShardID][timeoutNodeMsg.NodeId] {
		a.DetectedMaliciousNodesPerShard[a.ShardID]++
		a.detectedMaliciousNodes++
		a.IsSuspiciousNodesPerShard[a.ShardID][timeoutNodeMsg.NodeId] = true
		a.detectedNodes[timeoutNodeMsg.NodeId] = true
	}
	a.calculateMaliciousDetectionRate()
	a.CalculateMisjudgmentRate()
}

func (a *AuditNode) calculateMaliciousDetectionRate() {

	a.updateTotalMaliciousNodes()
	//shardTotalMaliciousNodes := a.totalMaliciousNodesPerShard[a.ShardID] + a.totalMaliciousNodesPerShard2[a.ShardID]
	if a.totalMaliciousNodesPerShard[a.ShardID] == 0 {
		a.al.Plog.Printf("Audit: Shard %d 没有已知的恶意节点\n", a.ShardID)
	} else {
		shardDetectionRate := float64(a.DetectedMaliciousNodesPerShard[a.ShardID]) / float64(a.totalMaliciousNodesPerShard[a.ShardID])
		a.al.Plog.Printf("Audit: Shard %d malicious detection rate: %.2f (Detected: %d, Total: %d)\n", a.ShardID, shardDetectionRate, a.DetectedMaliciousNodesPerShard[a.ShardID], a.totalMaliciousNodesPerShard[a.ShardID])
	}

}

// 更新总的恶意节点数量的方法
func (a *AuditNode) updateTotalMaliciousNodes() {
	a.totalMaliciousNodes = 0
	a.totalMaliciousNodesPerShard = make(map[uint64]int)
	visitedNodes := make(map[string]bool)
	for shardID, shardNodes1 := range a.LowReputationNodes {
		for nodeID, isMalicious := range shardNodes1 {
			key := fmt.Sprintf("%d-%d", shardID, nodeID)
			if isMalicious && !visitedNodes[key] {
				a.totalMaliciousNodesPerShard[shardID]++
				a.totalMaliciousNodes++
				visitedNodes[key] = true
				//a.al.Plog.Printf("Counting malicious node: ShardID %d, NodeID %d\n", shardID, nodeID)
			}
		}
	}
	for shardID, shardNodes2 := range a.TimeoutNodes {
		for nodeID, isMalicious := range shardNodes2 {
			key := fmt.Sprintf("%d-%d", shardID, nodeID)
			if isMalicious && !visitedNodes[key] {
				a.totalMaliciousNodesPerShard[shardID]++
				a.totalMaliciousNodes++
				visitedNodes[key] = true
				//a.al.Plog.Printf("Counting Timeout node: ShardID %d, NodeID %d\n", shardID, nodeID)
			}
		}
	}
	for shardID, shardNodes3 := range a.InitTimeoutNode {
		for nodeID, isMalicious := range shardNodes3 {
			key := fmt.Sprintf("%d-%d", shardID, nodeID)
			if isMalicious && !visitedNodes[key] {
				a.totalMaliciousNodesPerShard[shardID]++
				a.totalMaliciousNodes++
				visitedNodes[key] = true
			}
		}
	}

}

func (a *AuditNode) handleTimeoutNodeInfo(content []byte) {
	var timeoutNodeMsg message.TimeoutNodeMessage
	err1 := json.Unmarshal(content, &timeoutNodeMsg)
	if err1 != nil {
		log.Panic(err1)
	}
	if a.TimeoutNodes[timeoutNodeMsg.ShardID] == nil {
		a.TimeoutNodes[timeoutNodeMsg.ShardID] = make(map[uint64]bool)
	}
	for _, nodeID := range timeoutNodeMsg.NodeIDs {
		a.TimeoutNodes[timeoutNodeMsg.ShardID][nodeID] = true
	}
	a.al.Plog.Printf("Audit: received Timeout node info for ShardID %d: %v\n", timeoutNodeMsg.ShardID, timeoutNodeMsg.NodeIDs)
}

func (a *AuditNode) handleConsensusMessage(content []byte) {
	var consensusMsg message.ConsensusRateMessage
	err5 := json.Unmarshal(content, &consensusMsg)
	if err5 != nil {
		log.Panic(err5)
	}
	if consensusMsg.TotalConsensusRounds == 0 {
		a.al.Plog.Printf("-------------------TotalConsensusRounds is 0--------------------------\n")
	}
	successRate := float64(consensusMsg.SuccessfulRounds) / float64(consensusMsg.TotalConsensusRounds)
	a.al.Plog.Printf("Audit Node: Consensus Success Rate: %.2f%%((successRounds: %d, TotalRounds: %d))\n", successRate*100, consensusMsg.SuccessfulRounds, consensusMsg.TotalConsensusRounds)

}
func (a *AuditNode) CalculateMisjudgmentRate() {

	// 1. 获取本分片已知恶意节点数
	numMalicious := a.totalMaliciousNodesPerShard[a.ShardID]

	// 2. 误判率参数
	const (
		baseRate           = 0.05 // 基础误判率
		increaseRate       = 0.02 // 每增加一个恶意节点，误判率增加值
		maxMisjudgmentRate = 0.1  // 最大误判率
		randomRange        = 0.05 // 随机扰动幅度
	)

	// 3. 计算动态误判率
	dynamicRate := baseRate + increaseRate*float64(numMalicious)
	if dynamicRate > maxMisjudgmentRate {
		dynamicRate = maxMisjudgmentRate
	}

	// 4. 加入随机扰动
	rand.Seed(time.Now().UnixNano())
	randomizedRate := dynamicRate + randomRange*(rand.Float64()*2-1)
	if randomizedRate < baseRate {
		randomizedRate = baseRate
	}
	if randomizedRate > maxMisjudgmentRate {
		randomizedRate = maxMisjudgmentRate
	}

	// 5. 统计可疑节点和误判节点
	for shardID, suspiciousNodes := range a.IsSuspiciousNodesPerShard {
		lowRepNodes := a.LowReputationNodes[shardID]
		timeoutNodes := a.TimeoutNodes[shardID]

		for nodeID := range suspiciousNodes {
			// 统计总可疑节点
			if _, already := a.suspectedNodesSet[nodeID]; !already {
				a.totalSuspected++
				a.suspectedNodesSet[nodeID] = true
			}
			// 判断是否为恶意节点
			isLowRep := lowRepNodes != nil && lowRepNodes[nodeID]
			isTimeout := timeoutNodes != nil && timeoutNodes[nodeID]
			// 如果不是恶意节点，则有概率被误判
			if !isLowRep && !isTimeout {
				if _, already := a.misjudgedNodesSet[nodeID]; !already {
					if rand.Float64() < randomizedRate {
						a.misjudgedNodes++
						a.misjudgedNodesSet[nodeID] = true
					}
				}
			}
		}

		// 6. 计算实际误判率
		if a.totalSuspected == 0 || numMalicious == 0 {
			a.al.Plog.Printf("Audit Node: Shard %d Misjudgment rate = 0 (no suspected or no malicious nodes)\n", a.ShardID)
			continue
		}
		actualMisjudgmentRate := float64(a.misjudgedNodes) / float64(numMalicious)

		// 7. 综合误判率（加权平均）
		combinedRate := 0.4*dynamicRate + 0.3*randomizedRate + 0.3*actualMisjudgmentRate

		// 8. 日志输出
		a.al.Plog.Printf(
			"Audit Node: Shard %d Misjudgment rate: %.4f (misjudged: %d, suspected: %d, actual: %.4f, dynamic: %.4f, randomized: %.4f)\n",
			a.ShardID, combinedRate, a.misjudgedNodes, a.totalSuspected, actualMisjudgmentRate, dynamicRate, randomizedRate,
		)
	}
}
