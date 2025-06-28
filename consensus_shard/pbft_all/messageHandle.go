package pbft_all

import (
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/shard"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"
)

// this func is only invoked by main node
func init() {
	rand.Seed(time.Now().UnixNano())
}
func (p *PbftConsensusNode) Propose() {
	if p.view != p.NodeID {
		return
	}
	for {

		select {
		case <-p.pStop:
			p.pl.Plog.Printf("S%dN%d stop...\n", p.ShardID, p.NodeID)
			return
		default:
		}
		time.Sleep(time.Duration(int64(p.pbftChainConfig.BlockInterval)) * time.Millisecond)

		p.sequenceLock.Lock()

		p.pl.Plog.Printf("S%dN%d get sequenceLock locked, now trying to propose...\n", p.ShardID, p.NodeID)

		// propose
		_, r := p.ihm.HandleinPropose()

		digest := getDigest(r)
		p.requestPool[string(digest)] = r
		p.pl.Plog.Printf("S%dN%d put the request into the pool ...\n", p.ShardID, p.NodeID)

		ppmsg := message.PrePrepare{
			RequestMsg: r,
			Digest:     digest,
			SeqID:      p.sequenceID,
		}
		nrmsg := message.RegisterNode{
			ShardID:    p.ShardID,
			NodeID:     p.NodeID,
			Role:       getNodeRole(ReputationMap[p.ShardID][p.NodeID]),
			IsMainNode: true,
		}
		p.height2Digest[p.sequenceID] = string(digest)
		// marshal and broadcast
		ppbyte, err := json.Marshal(ppmsg)
		if err != nil {
			log.Panic()
		}
		nrbyte, err := json.Marshal(nrmsg)
		if err != nil {
			log.Panic()
		}
		msg_send1 := message.MergeMessage(message.CPrePrepare, ppbyte)
		networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send1)
		msg_send2 := message.MergeMessage(message.CRegisterNodeMessage, nrbyte)
		networks.TcpDial(msg_send2, p.ip_nodeTable[params.DeciderShard][0])

	}

}

func (p *PbftConsensusNode) handlePrePrepare(content []byte) {
	p.sendMaliciousNodeInfo()
	p.sendTimeoutNodeInfo()

	p.RunningNode.PrintNode()
	fmt.Println("received the PrePrepare ...")
	startMsg := message.StartProcessingMessage{
		ShardID: p.ShardID,
		NodeID:  p.NodeID,
	}
	startMsgBytes, err1 := json.Marshal(startMsg)
	if err1 != nil {
		log.Panic()
	}

	start_msg_send := message.MergeMessage(message.CStarMessge, startMsgBytes)
	networks.TcpDial(start_msg_send, p.ip_nodeTable[p.ShardID][2])

	// Simulate node timeout behavior under specific conditions.
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		time.Sleep(300 * time.Millisecond)
	}
	// decode the message
	ppmsg := new(message.PrePrepare)
	err := json.Unmarshal(content, ppmsg)
	if err != nil {
		log.Panic(err)
	}
	flag := false
	if digest := getDigest(ppmsg.RequestMsg); string(digest) != string(ppmsg.Digest) {
		p.pl.Plog.Printf("S%dN%d : the digest is not consistent, so refuse to prepare. \n", p.ShardID, p.NodeID)
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
	} else if p.sequenceID < ppmsg.SeqID {
		p.requestPool[string(getDigest(ppmsg.RequestMsg))] = ppmsg.RequestMsg
		p.height2Digest[ppmsg.SeqID] = string(getDigest(ppmsg.RequestMsg))
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
		p.pl.Plog.Printf("S%dN%d : the Sequence id is not consistent, so refuse to prepare. \n", p.ShardID, p.NodeID)

	} else {
		// do your operation in this interface
		flag = p.ihm.HandleinPrePrepare(ppmsg)
		p.requestPool[string(getDigest(ppmsg.RequestMsg))] = ppmsg.RequestMsg
		p.height2Digest[ppmsg.SeqID] = string(getDigest(ppmsg.RequestMsg))

	}
	//if the message is true, broadcast the prepare message
	if flag {
		pre := message.Prepare{
			Digest:     ppmsg.Digest,
			SeqID:      ppmsg.SeqID,
			SenderNode: p.RunningNode,
		}
		prepareByte, err := json.Marshal(pre)
		if err != nil {
			log.Panic()
		}
		// broadcast
		msg_send := message.MergeMessage(message.CPrepare, prepareByte)
		networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
		p.pl.Plog.Printf("S%dN%d : has broadcast the prepare message \n", p.ShardID, p.NodeID)

		for _, nodes := range p.TimeoutNodes {
			nodeIDs := make([]uint64, 0, len(nodes))
			for nodeID := range nodes {
				nodeIDs = append(nodeIDs, nodeID)
			}
			finishMsg := message.FinishProcessingMessage{
				ShardID: p.ShardID,
				NodeId:  p.NodeID,
				NodeIDs: nodeIDs,
			}

			finishtMsgBytes, err2 := json.Marshal(finishMsg)
			if err2 != nil {
				log.Panic()
			}
			finish_msg_send := message.MergeMessage(message.CFinishMessage, finishtMsgBytes)
			networks.TcpDial(finish_msg_send, p.ip_nodeTable[p.ShardID][2])
		}
		// decode the message
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)

	}
}

func (p *PbftConsensusNode) handlePrepare(content []byte) {
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		p.pl.Plog.Printf("S%dN%d : is a malicious node, skipping Commit message.\n", p.ShardID, p.NodeID)
		return
	}
	flag := false
	p.pl.Plog.Printf("S%dN%d : received the Prepare ...\n", p.ShardID, p.NodeID)
	// decode the message
	pmsg := new(message.Prepare)
	err := json.Unmarshal(content, pmsg)
	if err != nil {
		log.Panic(err)
	}

	if _, ok := p.requestPool[string(pmsg.Digest)]; !ok {
		p.pl.Plog.Printf("S%dN%d : doesn't have the digest in the requst pool, refuse to commit\n", p.ShardID, p.NodeID)
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
	} else if p.sequenceID < pmsg.SeqID {
		p.pl.Plog.Printf("S%dN%d : inconsistent sequence ID, refuse to commit\n", p.ShardID, p.NodeID)
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
	} else {
		// if needed more operations, implement interfaces
		flag = p.ihm.HandleinPrepare(pmsg)
		p.set2DMap(true, string(pmsg.Digest), pmsg.SenderNode)
		cnt := 0
		//
		for range p.cntPrepareConfirm[string(pmsg.Digest)] {
			cnt++
		}
		// the main node will not send the prepare message
		specifiedcnt := int(2 * p.malicious_nums)
		if p.NodeID != p.view {
			specifiedcnt -= 1
		}
		// if the node has received 2f messages (itself included), and it haven't committed, then it commit
		p.lock.Lock()
		defer p.lock.Unlock()

		if cnt >= specifiedcnt && !p.isCommitBordcast[string(pmsg.Digest)] {
			p.pl.Plog.Printf("S%dN%d : is going to commit\n", p.ShardID, p.NodeID)
			// generate commit and broadcast
			c := message.Commit{
				Digest:     pmsg.Digest,
				SeqID:      pmsg.SeqID,
				SenderNode: p.RunningNode,
			}
			commitByte, err := json.Marshal(c)
			if err != nil {
				log.Panic()
			}
			msg_send := message.MergeMessage(message.CCommit, commitByte)
			networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
			p.isCommitBordcast[string(pmsg.Digest)] = true
			p.pl.Plog.Printf("S%dN%d : commit is broadcast\n", p.ShardID, p.NodeID)

		}
	}
}

func (p *PbftConsensusNode) handleCommit(content []byte) {
	p.totalConsensusRounds += 1
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		p.pl.Plog.Printf("S%dN%d : is a malicious node, skipping Commit message.\n", p.ShardID, p.NodeID)
		return
	}
	startMsg := message.StartProcessingMessage{
		ShardID: p.ShardID,
		NodeID:  p.NodeID,
	}
	startMsgBytes, err1 := json.Marshal(startMsg)
	if err1 != nil {
		log.Panic()
	}
	start_msg_send := message.MergeMessage(message.CStarMessge, startMsgBytes)
	networks.TcpDial(start_msg_send, p.ip_nodeTable[p.ShardID][2])
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		time.Sleep(300 * time.Millisecond)
	}
	if p.MaliciousNodes[p.ShardID][p.NodeID] {
		time.Sleep(300 * time.Millisecond)
	}

	flag := false
	// decode the message
	cmsg := new(message.Commit)
	err := json.Unmarshal(content, cmsg)
	if err != nil {
		log.Panic(err)
	}
	p.pl.Plog.Printf("S%dN%d received the Commit from ...%d\n", p.ShardID, p.NodeID, cmsg.SenderNode.NodeID)

	p.set2DMap(false, string(cmsg.Digest), cmsg.SenderNode)
	cnt := 0
	for range p.cntCommitConfirm[string(cmsg.Digest)] {
		cnt++
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	// the main node will not send the prepare message
	required_cnt := int(2 * p.malicious_nums)

	if cnt >= required_cnt && !p.isReply[string(cmsg.Digest)] {
		p.pl.Plog.Printf("S%dN%d : has received 2f + 1 commits ... \n", p.ShardID, p.NodeID)
		//UpdateReputation(p, true)
		// if this node is left behind, so it need to requst blocks
		p.successfulConsensusRounds += 1
		//Calculate the consensus success rate.
		if _, ok := p.requestPool[string(cmsg.Digest)]; !ok {
			p.isReply[string(cmsg.Digest)] = true
			p.askForLock.Lock()
			// request the block
			sn := &shard.Node{
				NodeID:  p.view,
				ShardID: p.ShardID,
				IPaddr:  p.ip_nodeTable[p.ShardID][p.view],
			}
			orequest := message.RequestOldMessage{
				SeqStartHeight: p.sequenceID + 1,
				SeqEndHeight:   cmsg.SeqID,
				ServerNode:     sn,
				SenderNode:     p.RunningNode,
			}
			bromyte, err := json.Marshal(orequest)
			if err != nil {
				log.Panic()
			}

			p.pl.Plog.Printf("S%dN%d : is now requesting message (seq %d to %d) ... \n", p.ShardID, p.NodeID, orequest.SeqStartHeight, orequest.SeqEndHeight)
			msg_send := message.MergeMessage(message.CRequestOldrequest, bromyte)
			networks.TcpDial(msg_send, orequest.ServerNode.IPaddr)
		} else {
			// implement interface

			flag = p.ihm.HandleinCommit(cmsg)
			p.isReply[string(cmsg.Digest)] = true
			p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
			reputationMsg := message.ReputationMessage{
				ShardID:    p.ShardID,
				NodeID:     p.NodeID,
				Reputation: ReputationMap[p.ShardID][p.NodeID],
			}
			reputationMsgBytes, err := json.Marshal(reputationMsg)
			if err != nil {
				log.Panic(err)
			}
			rep_msg_send := message.MergeMessage(message.CReputationMessage, reputationMsgBytes)
			networks.TcpDial(rep_msg_send, p.ip_nodeTable[params.DeciderShard][0])
			p.pl.Plog.Printf("S%dN%d: this round of pbft %d is end \n", p.ShardID, p.NodeID, p.sequenceID)

			p.sequenceID += 1
			if p.MaliciousNodes[p.ShardID][p.NodeID] {
				TestNodeInit(ReputationMap, p.ShardID, p.NodeID)
			}

		}
		// if this node is a main node, then unlock the sequencelock
		if p.NodeID == p.view {
			p.sequenceLock.Unlock()
			p.pl.Plog.Printf("S%dN%d get sequenceLock unlocked...\n", p.ShardID, p.NodeID)
		}
	}

	//Send the collected consensus results to the audit nodes.
	p.sendConsensusInfo()
	finishMsg := message.FinishProcessingMessage{
		ShardID: p.ShardID,
		NodeId:  p.NodeID,
	}
	finishtMsgBytes, err2 := json.Marshal(finishMsg)
	if err2 != nil {
		log.Panic()
	}
	finish_msg_send := message.MergeMessage(message.CFinishMessage, finishtMsgBytes)
	networks.TcpDial(finish_msg_send, p.ip_nodeTable[p.ShardID][2])

}

// this func is only invoked by the main node,
// if the request is correct, the main node will send
// block back to the message sender.
// now this function can send both block and partition
func (p *PbftConsensusNode) handleRequestOldSeq(content []byte) {
	if p.view != p.NodeID {
		content = make([]byte, 0)
		return
	}

	rom := new(message.RequestOldMessage)
	err := json.Unmarshal(content, rom)
	if err != nil {
		log.Panic()
	}
	p.pl.Plog.Printf("S%dN%d : received the old message requst from ...", p.ShardID, p.NodeID)
	rom.SenderNode.PrintNode()

	oldR := make([]*message.Request, 0)
	for height := rom.SeqStartHeight; height <= rom.SeqEndHeight; height++ {
		if _, ok := p.height2Digest[height]; !ok {
			p.pl.Plog.Printf("S%dN%d : has no this digest to this height %d\n", p.ShardID, p.NodeID, height)
			break
		}
		if r, ok := p.requestPool[p.height2Digest[height]]; !ok {
			p.pl.Plog.Printf("S%dN%d : has no this message to this digest %d\n", p.ShardID, p.NodeID, height)
			break
		} else {
			oldR = append(oldR, r)
		}
	}
	p.pl.Plog.Printf("S%dN%d : has generated the message to be sent\n", p.ShardID, p.NodeID)

	p.ihm.HandleReqestforOldSeq(rom)

	// send the block back
	sb := message.SendOldMessage{
		SeqStartHeight: rom.SeqStartHeight,
		SeqEndHeight:   rom.SeqEndHeight,
		OldRequest:     oldR,
		SenderNode:     p.RunningNode,
	}
	sbByte, err := json.Marshal(sb)
	if err != nil {
		log.Panic()
	}
	msg_send := message.MergeMessage(message.CSendOldrequest, sbByte)
	networks.TcpDial(msg_send, rom.SenderNode.IPaddr)
	p.pl.Plog.Printf("S%dN%d : send blocks\n", p.ShardID, p.NodeID)
}

// node requst blocks and receive blocks from the main node
func (p *PbftConsensusNode) handleSendOldSeq(content []byte) {
	som := new(message.SendOldMessage)
	err := json.Unmarshal(content, som)
	if err != nil {
		log.Panic()
	}
	p.pl.Plog.Printf("S%dN%d : has received the SendOldMessage message\n", p.ShardID, p.NodeID)

	// implement interface for new consensus
	p.ihm.HandleforSequentialRequest(som)
	beginSeq := som.SeqStartHeight
	for idx, r := range som.OldRequest {
		p.requestPool[string(getDigest(r))] = r
		p.height2Digest[uint64(idx)+beginSeq] = string(getDigest(r))
		p.isReply[string(getDigest(r))] = true
		p.pl.Plog.Printf("this round of pbft %d is end \n", uint64(idx)+beginSeq)
	}
	p.sequenceID = som.SeqEndHeight + 1
	if rDigest, ok1 := p.height2Digest[p.sequenceID]; ok1 {
		if r, ok2 := p.requestPool[rDigest]; ok2 {
			ppmsg := &message.PrePrepare{
				RequestMsg: r,
				SeqID:      p.sequenceID,
				Digest:     getDigest(r),
			}
			flag := false
			flag = p.ihm.HandleinPrePrepare(ppmsg)
			if flag {
				pre := message.Prepare{
					Digest:     ppmsg.Digest,
					SeqID:      ppmsg.SeqID,
					SenderNode: p.RunningNode,
				}
				prepareByte, err := json.Marshal(pre)
				if err != nil {
					log.Panic()
				}
				// broadcast
				msg_send := message.MergeMessage(message.CPrepare, prepareByte)
				networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
				p.pl.Plog.Printf("S%dN%d : has broadcast the prepare message \n", p.ShardID, p.NodeID)
			}
		}
	}

	p.askForLock.Unlock()
}

func (p *PbftConsensusNode) UpdateReputation1(reputationMap map[uint64]map[uint64]float64, shardID, nodeID uint64, consensusResult bool) {
	if reputationMap[shardID] == nil {
		reputationMap[shardID] = make(map[uint64]float64)
	}
	if _, ok := reputationMap[shardID][nodeID]; !ok {
		reputationMap[shardID][nodeID] = 60.0
	}
	reputation := reputationMap[shardID][nodeID]
	if consensusResult && !p.IsMaliciousNode(shardID, nodeID) {
		reputation += 1
		if reputation > 100 {
			reputation = 100
		}
	} else {
		if !p.IsMaliciousNode(shardID, nodeID) {
			reputation -= 5
		}
		if reputation < 0 {
			reputation = 0
		}
	}

	reputationMap[shardID][nodeID] = reputation

}

// Reputation anomaly detection function.
func TestNodeInit(reputationMap map[uint64]map[uint64]float64, shardID, nodeID uint64) {
	if reputationMap[shardID] == nil {
		reputationMap[shardID] = make(map[uint64]float64)
	}
	if _, ok := reputationMap[shardID][nodeID]; !ok {
		reputationMap[shardID][nodeID] = 60.0
	}
	reputation := reputationMap[shardID][nodeID]
	randomReduction := rand.Float64()*10 + 1
	reputation -= randomReduction
	if reputation < 0 {
		reputation = 0

	}
	reputationMap[shardID][nodeID] = reputation
}

func (p *PbftConsensusNode) SetMaliciousNodes(shardID uint64, nodeIDs []uint64) {
	if p.MaliciousNodes[shardID] == nil {
		p.MaliciousNodes[shardID] = make(map[uint64]bool)
	}
	if ReputationMap[shardID] == nil {
		ReputationMap[shardID] = make(map[uint64]float64)
	}
	for _, nodeID := range nodeIDs {
		p.MaliciousNodes[shardID][nodeID] = true
		ReputationMap[shardID][nodeID] = float64(uint64(rand.Intn(51)))
	}
}

func (p *PbftConsensusNode) SetTimeoutNodes(shardID uint64, nodeIDs []uint64) {
	if p.TimeoutNodes[shardID] == nil {
		p.TimeoutNodes[shardID] = make(map[uint64]bool)
	}
	for _, nodeID := range nodeIDs {
		p.TimeoutNodes[shardID][nodeID] = true
	}
}

func (p *PbftConsensusNode) IsMaliciousNode(shardID, nodeID uint64) bool {
	if nodes, exists := p.MaliciousNodes[shardID]; exists {
		return nodes[nodeID]
	}

	return false
}

func (p *PbftConsensusNode) IsTimeoutNode(shardID, nodeID uint64) bool {
	if timeoutNodes, exists := p.TimeoutNodes[shardID]; exists {
		if timeoutNodes[nodeID] {
			p.IsSuspicious = true
			return true
		}
	}
	return false
}

// Send malicious node information.
func (p *PbftConsensusNode) sendMaliciousNodeInfo() {
	for shardID, nodes := range p.MaliciousNodes {
		nodeIDs := make([]uint64, 0, len(nodes))
		for nodeID := range nodes {
			nodeIDs = append(nodeIDs, nodeID)
		}
		maliciousMsg := message.MaliciousNodeMessage{
			ShardID: shardID,
			NodeIDs: nodeIDs,
		}
		maliciousMsgBytes, err := json.Marshal(maliciousMsg)
		if err != nil {
			log.Panic(err)
		}
		malicious_msg_send := message.MergeMessage(message.CMaliciousNodeMessage, maliciousMsgBytes)
		networks.TcpDial(malicious_msg_send, p.ip_nodeTable[params.DeciderShard][0])
		networks.TcpDial(malicious_msg_send, p.ip_nodeTable[p.ShardID][2])
	}

}

func (p *PbftConsensusNode) sendTimeoutNodeInfo() {
	for shardID, nodes := range p.TimeoutNodes {
		nodeIDs := make([]uint64, 0, len(nodes))
		for nodeID := range nodes {
			nodeIDs = append(nodeIDs, nodeID)
		}
		timeoutMsg := message.TimeoutNodeMessage{
			ShardID: shardID,
			NodeIDs: nodeIDs,
			NodeId:  p.NodeID,
		}
		timeoutMsgBytes, err := json.Marshal(timeoutMsg)
		if err != nil {
			log.Panic(err)
		}
		timeoutMsgSend := message.MergeMessage(message.CTimeoutMessage, timeoutMsgBytes)
		networks.TcpDial(timeoutMsgSend, p.ip_nodeTable[params.DeciderShard][0])
		networks.TcpDial(timeoutMsgSend, p.ip_nodeTable[p.ShardID][2])
	}
}

func getNodeRole(reputation float64) string {
	if reputation > 87 {
		return "CandidateMaster"

	} else if reputation >= 82 && reputation <= 87 {
		return "ConsensusNode"
	} else {
		return "CandidateNode"
	}
}

func (p *PbftConsensusNode) sendConsensusInfo() {
	ConsensusMsg := message.ConsensusRateMessage{
		ShardID:              p.ShardID,
		TotalConsensusRounds: p.totalConsensusRounds + 1,
		SuccessfulRounds:     p.successfulConsensusRounds + 1,
	}
	consensusMsgBytes, err2 := json.Marshal(ConsensusMsg)
	if err2 != nil {
		log.Panic()
	}
	consensus_msg_send := message.MergeMessage(message.CConsensusRateMessage, consensusMsgBytes)
	networks.TcpDial(consensus_msg_send, p.ip_nodeTable[p.ShardID][2])
}
