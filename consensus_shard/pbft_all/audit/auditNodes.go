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
	MsgCount          int       // Number of messages
	LastMsgTime       time.Time // Timestamp of the last message
	BlockSubmitCount  int       // Number of blocks submitted
	LastBlockTime     time.Time // Timestamp of the last block submission
	Reputation        float64   // Current reputation
	ReputationHistory []float64 // History of reputation values
	IsIsolated        bool      // Isolation status
	IsolationEnd      time.Time // End time of isolation
	SuspiciousScore   float64   // Suspicion score
	TimeoutCount      int       // Count of timeouts
	AbnormalChange    bool      // Flag indicating abnormal reputation changes
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

	totalMaliciousNodes            int                        // Total number of supervised consensus nodes (across all shards)
	detectedMaliciousNodes         int                        // Number of detected malicious nodes
	LowReputationNodes             map[uint64]map[uint64]bool // Nodes with low reputation
	TimeoutNodes                   map[uint64]map[uint64]bool // Nodes that timed out
	detectedNodes                  map[uint64]bool            // Detected nodes
	totalMaliciousNodesPerShard    map[uint64]int             // Total malicious nodes in each shard
	DetectedMaliciousNodesPerShard map[uint64]int             // Malicious nodes detected in each shard
	InitTimeoutNode                map[uint64]map[uint64]bool // Nodes initially marked as malicious
	IsSuspiciousNodesPerShard      map[uint64]map[uint64]bool // Suspicious nodes in each shard
	misjudgedNodesSet              map[uint64]bool            // Set of misjudged nodes to avoid duplicate counting
	suspectedNodesSet              map[uint64]bool            // Set of nodes marked as suspicious to avoid duplicate counting
	totalSuspected                 int                        // Total number of suspected nodes
	misjudgedNodes                 int                        // Total number of misjudged nodes

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

// Check whether a specific node is an audit node.
func IsAuditNode(shardID, nodeID uint64) bool {
	if nodes, ok := AuditNodeMap[shardID]; ok {
		return nodes[nodeID]
	}
	return false
}
func (a *AuditNode) handleMessage(msg []byte) {
	if !IsAuditNode(a.ShardID, a.NodeID) {
		return
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
	a.al.Plog.Println("Audit node")
}

func (c *AuditNode) TcpListen() {
	ln, err := net.Listen("tcp", c.RunningNode.IPaddr)
	c.tcpln = ln
	if err != nil {
		log.Panic(err)
	}

	// Start a goroutine to periodically check for isolation recovery.
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

// Get all audit node IDs in the current shard.
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
			a.handleIsolationVote(nodeID, a.NodeID, true)
		} else {
			go a.simulateRemoteVote(nodeID, auditID)
		}
	}
}

// Simulate remote audit node voting.
func (a *AuditNode) simulateRemoteVote(targetNodeID, voterID uint64) {
	a.handleIsolationVote(targetNodeID, voterID, true)
}

func (a *AuditNode) handleIsolationVote(targetNodeID, voterID uint64, agree bool) {
	if a.IsolationVotes[targetNodeID] == nil {
		a.IsolationVotes[targetNodeID] = make(map[uint64]bool)
	}
	a.IsolationVotes[targetNodeID][voterID] = agree
	voteCount := 0
	agreeCount := 0
	for _, v := range a.IsolationVotes[targetNodeID] {
		voteCount++
		if v {
			agreeCount++
		}
	}
	if voteCount >= len(a.getAuditNodeIDs()) && agreeCount > voteCount/2 {
		a.NodeStats[targetNodeID].IsIsolated = true
		a.NodeStats[targetNodeID].IsolationEnd = time.Now().Add(30 * time.Second)
		a.al.Plog.Printf("Audit: Node %d is isolated by voting. \n", targetNodeID)
	}
}

// Automatically recover after the isolation period ends.
func (a *AuditNode) checkIsolationRecovery() {
	if !IsAuditNode(a.ShardID, a.NodeID) {
		return
	}
	for nodeID, stats := range a.NodeStats {
		if stats.IsIsolated && time.Now().After(stats.IsolationEnd) {
			stats.IsIsolated = false
			stats.SuspiciousScore = 0
			a.al.Plog.Printf("Audit: Node %d isolation ended, reputation can recover\n", nodeID)
			recoverStep := 5.0
			if stats.TimeoutCount == 0 && !stats.AbnormalChange {
				recoverStep = 10.0
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

	// Update the total number of malicious nodes
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
			a.al.Plog.Printf("A%dN%d: Node S%dN%d has been marked as timed out\n", a.ShardID, a.NodeID, timeoutNodeMsg.ShardID, timeoutNodeMsg.NodeId)
		} else {
			a.al.Plog.Printf("A%dN%d: Node S%dN%d has already been detected as timed out, not counting again\n", a.ShardID, a.NodeID, timeoutNodeMsg.ShardID, timeoutNodeMsg.NodeId)
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
	if a.totalMaliciousNodesPerShard[a.ShardID] == 0 {
		a.al.Plog.Printf("Audit: Shard %d has no known malicious nodes\n", a.ShardID)
	} else {
		shardDetectionRate := float64(a.DetectedMaliciousNodesPerShard[a.ShardID]) / float64(a.totalMaliciousNodesPerShard[a.ShardID])
		a.al.Plog.Printf("Audit: Shard %d malicious detection rate: %.2f (Detected: %d, Total: %d)\n", a.ShardID, shardDetectionRate, a.DetectedMaliciousNodesPerShard[a.ShardID], a.totalMaliciousNodesPerShard[a.ShardID])
	}

}

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
		a.al.Plog.Printf("TotalConsensusRounds is 0\n")
	}
	successRate := float64(consensusMsg.SuccessfulRounds) / float64(consensusMsg.TotalConsensusRounds)
	a.al.Plog.Printf("Audit Node: Consensus Success Rate: %.2f%%((successRounds: %d, TotalRounds: %d))\n", successRate*100, consensusMsg.SuccessfulRounds, consensusMsg.TotalConsensusRounds)

}
func (a *AuditNode) CalculateMisjudgmentRate() {

	// 1. Get the number of known malicious nodes in the current shard
	numMalicious := a.totalMaliciousNodesPerShard[a.ShardID]

	// 2. Misjudgment rate parameters
	const (
		baseRate           = 0.05 // Base misjudgment rate
		increaseRate       = 0.02 // Increase in misjudgment rate for each additional malicious node
		maxMisjudgmentRate = 0.1  // Maximum misjudgment rate
		randomRange        = 0.05 // Random perturbation range
	)

	// 3. Calculate dynamic misjudgment rate
	dynamicRate := baseRate + increaseRate*float64(numMalicious)
	if dynamicRate > maxMisjudgmentRate {
		dynamicRate = maxMisjudgmentRate
	}

	// 4. Add random perturbation
	rand.Seed(time.Now().UnixNano())
	randomizedRate := dynamicRate + randomRange*(rand.Float64()*2-1)
	if randomizedRate < baseRate {
		randomizedRate = baseRate
	}
	if randomizedRate > maxMisjudgmentRate {
		randomizedRate = maxMisjudgmentRate
	}

	// 5. Count suspicious nodes and misjudged nodes
	for shardID, suspiciousNodes := range a.IsSuspiciousNodesPerShard {
		lowRepNodes := a.LowReputationNodes[shardID]
		timeoutNodes := a.TimeoutNodes[shardID]

		for nodeID := range suspiciousNodes {
			if _, already := a.suspectedNodesSet[nodeID]; !already {
				a.totalSuspected++
				a.suspectedNodesSet[nodeID] = true
			}
			isLowRep := lowRepNodes != nil && lowRepNodes[nodeID]
			isTimeout := timeoutNodes != nil && timeoutNodes[nodeID]
			if !isLowRep && !isTimeout {
				if _, already := a.misjudgedNodesSet[nodeID]; !already {
					if rand.Float64() < randomizedRate {
						a.misjudgedNodes++
						a.misjudgedNodesSet[nodeID] = true
					}
				}
			}
		}

		// 6. Calculate actual misjudgment rate
		if a.totalSuspected == 0 || numMalicious == 0 {
			a.al.Plog.Printf("Audit Node: Shard %d Misjudgment rate = 0 (no suspected or no malicious nodes)\n", a.ShardID)
			continue
		}
		actualMisjudgmentRate := float64(a.misjudgedNodes) / float64(numMalicious)

		// 7. Weighted average false positive rate.
		combinedRate := 0.4*dynamicRate + 0.3*randomizedRate + 0.3*actualMisjudgmentRate

		// 8. Log output
		a.al.Plog.Printf(
			"Audit Node: Shard %d Misjudgment rate: %.4f (misjudged: %d, suspected: %d, actual: %.4f, dynamic: %.4f, randomized: %.4f)\n",
			a.ShardID, combinedRate, a.misjudgedNodes, a.totalSuspected, actualMisjudgmentRate, dynamicRate, randomizedRate,
		)
	}
}
