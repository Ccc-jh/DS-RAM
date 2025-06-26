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
	//确保主节点才能进行提议（更换主节点时这里需要修改）
	if p.view != p.NodeID {
		return
	}

	//--等待停止信号
	for {

		select {
		case <-p.pStop:
			p.pl.Plog.Printf("S%dN%d stop...\n", p.ShardID, p.NodeID)
			return
		default:
		}
		time.Sleep(time.Duration(int64(p.pbftChainConfig.BlockInterval)) * time.Millisecond)

		p.sequenceLock.Lock()
		//判断是否是当前轮次，对总的共识轮次进行增加
		p.pl.Plog.Printf("S%dN%d get sequenceLock locked, now trying to propose...\n", p.ShardID, p.NodeID)

		// propose
		// ---通过实现接口方法来实现区块提议  implement interface to generate propose
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
		//每个分片内都执行自己的PBFT共识算法
		msg_send1 := message.MergeMessage(message.CPrePrepare, ppbyte)
		networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send1)
		//--将节点注册信息只发送给supervisor节点
		msg_send2 := message.MergeMessage(message.CRegisterNodeMessage, nrbyte)
		//networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send2)
		networks.TcpDial(msg_send2, p.ip_nodeTable[params.DeciderShard][0])

	}

}

func (p *PbftConsensusNode) handlePrePrepare(content []byte) {
	//发送恶意节点信息到supervisor
	p.sendMaliciousNodeInfo()
	p.sendTimeoutNodeInfo()

	p.RunningNode.PrintNode()
	fmt.Println("received the PrePrepare ...")

	// 发送开始处理消息给审计节点
	p.pl.Plog.Printf("S%dN%d :PrePrepare阶段发送开始处理消息给审计节点\n", p.ShardID, p.NodeID)
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
	p.pl.Plog.Printf("S%dN%d :PrePrepare阶段发送开始处理消息成功\n", p.ShardID, p.NodeID)

	// 模拟节点在特定条件下的超时行为
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		// 延迟处理 PrePrepare 消息，模拟超时
		time.Sleep(300 * time.Millisecond)
	}
	// decode the message
	//---创建一个PrePrepare消息对象
	ppmsg := new(message.PrePrepare)
	//---将传入的消息内容 content 解析成 PrePrepare 结构体的形式
	err := json.Unmarshal(content, ppmsg)
	if err != nil {
		log.Panic(err)
	}
	//---标记消息处理的结果(可以用来增减信誉值Reputation)
	flag := false
	//---检查PrePrepare消息的有效性，检查摘要digest和序列号SeqID是否一致
	//---获取 PrePrepare 消息中请求消息的摘要（digest），并将其与 PrePrepare 消息中的摘要进行比较
	if digest := getDigest(ppmsg.RequestMsg); string(digest) != string(ppmsg.Digest) {
		//---摘要不一致，拒绝
		p.pl.Plog.Printf("S%dN%d : the digest is not consistent, so refuse to prepare. \n", p.ShardID, p.NodeID)
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
	} else if p.sequenceID < ppmsg.SeqID { //---节点的序列号小于 PrePrepare 消息中的序列号
		//---将请求消息存储在请求池中，并将序列号与摘要关联起来
		p.requestPool[string(getDigest(ppmsg.RequestMsg))] = ppmsg.RequestMsg
		p.height2Digest[ppmsg.SeqID] = string(getDigest(ppmsg.RequestMsg))
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
		//---序列号不一致，拒绝处理
		p.pl.Plog.Printf("S%dN%d : the Sequence id is not consistent, so refuse to prepare. \n", p.ShardID, p.NodeID)

	} else {
		// do your operation in this interface
		flag = p.ihm.HandleinPrePrepare(ppmsg)
		p.requestPool[string(getDigest(ppmsg.RequestMsg))] = ppmsg.RequestMsg
		p.height2Digest[ppmsg.SeqID] = string(getDigest(ppmsg.RequestMsg))
		//模拟信誉值异常

	}
	// ---如果PrePrepare消息处理成功，广播Prepare消息   if the message is true, broadcast the prepare message
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
		// ---广播PrePare消息 broadcast
		msg_send := message.MergeMessage(message.CPrepare, prepareByte)
		networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send)
		p.pl.Plog.Printf("S%dN%d : has broadcast the prepare message \n", p.ShardID, p.NodeID)
		// 发送结束处理消息给审计节点
		p.pl.Plog.Printf("S%dN%d :PrePrepare阶段发送结束处理消息给审计节点\n", p.ShardID, p.NodeID)

		for shardID, nodes := range p.TimeoutNodes {
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
			// 发送信息到Supervisor，假设Supervisor的IP地址是存储在ip_nodeTable中，并且节点ID为0
			finish_msg_send := message.MergeMessage(message.CFinishMessage, finishtMsgBytes)
			networks.TcpDial(finish_msg_send, p.ip_nodeTable[p.ShardID][2])
			p.pl.Plog.Printf("发送响应超时节点信息: ShardID: %d, NodeIDs: %v\n", shardID, nodeIDs)
		}
		p.pl.Plog.Printf("S%dN%d :PrePrepare阶段发送结束处理消息成功\n", p.ShardID, p.NodeID)
		// decode the message
		//--节点广播消息之后，对其进行增加声誉
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)

	}
}

// ---接收并处理Prepare消息，需要计算收到的消息的数量
func (p *PbftConsensusNode) handlePrepare(content []byte) {
	// 模拟如果是恶意节点，直接返回，不发送 Commit 消息，不进行投票
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		p.pl.Plog.Printf("S%dN%d : is a malicious node, skipping Commit message.\n", p.ShardID, p.NodeID)
		return
	}
	flag := false
	p.pl.Plog.Printf("S%dN%d : received the Prepare ...\n", p.ShardID, p.NodeID)
	// ---解析消息decode the message
	pmsg := new(message.Prepare)
	err := json.Unmarshal(content, pmsg)
	if err != nil {
		log.Panic(err)
	}

	//---标记消息处理的结果(可以用来增减信誉值Reputation)
	if _, ok := p.requestPool[string(pmsg.Digest)]; !ok {
		p.pl.Plog.Printf("S%dN%d : doesn't have the digest in the requst pool, refuse to commit\n", p.ShardID, p.NodeID)
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
	} else if p.sequenceID < pmsg.SeqID {
		p.pl.Plog.Printf("S%dN%d : inconsistent sequence ID, refuse to commit\n", p.ShardID, p.NodeID)
		p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
	} else {
		// ---增加额外的操作  if needed more operations, implement interfaces
		flag = p.ihm.HandleinPrepare(pmsg)
		p.set2DMap(true, string(pmsg.Digest), pmsg.SenderNode)
		cnt := 0
		//---计算已经确认的Prepare消息数量    如何让它不确认？
		for range p.cntPrepareConfirm[string(pmsg.Digest)] {
			cnt++
		}
		p.pl.Plog.Printf("S%dN%d : Prepare中的cnt=%d\n", p.ShardID, p.NodeID, cnt)
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
			//p.UpdateReputation1(ReputationMap, p.ShardID, p.NodeID, flag)
			//p.pl.Plog.Printf("----S%dN%d:当前信誉值:%.2f\n----", p.ShardID, p.NodeID, ReputationMap[p.ShardID][p.NodeID])

		}
	}
}

// ---接收并处理Commit消息，需要计算收到的消息的数量
func (p *PbftConsensusNode) handleCommit(content []byte) {
	p.totalConsensusRounds += 1
	//--------------------------------------------------------------------------------------------------------
	// 发送开始处理消息给审计节点
	p.pl.Plog.Printf("S%dN%d :Commit阶段发送开始处理消息给审计节点 \n", p.ShardID, p.NodeID)
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

	// 如果是恶意节点，直接返回，不发送 Commit 消息，不进行投票

	start_msg_send := message.MergeMessage(message.CStarMessge, startMsgBytes)
	networks.TcpDial(start_msg_send, p.ip_nodeTable[p.ShardID][2])
	p.pl.Plog.Printf("S%dN%d :Commit阶段发送开始处理消息成功\n", p.ShardID, p.NodeID)
	//---------------------------------------------------------------------------------------------------------------------

	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		// 延迟处理 PrePrepare 消息，模拟超时
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

	//---计算已经确认了的Commit消息的数量
	cnt := 0
	//恶意节点不会对cnt进行增加
	for range p.cntCommitConfirm[string(cmsg.Digest)] {
		cnt++
	}
	p.pl.Plog.Printf("S%dN%d : Commit中的cnt=%d\n", p.ShardID, p.NodeID, cnt)
	p.lock.Lock()
	defer p.lock.Unlock()
	// the main node will not send the prepare message
	required_cnt := int(2 * p.malicious_nums)
	p.pl.Plog.Printf("&&&&&&&&&&&&&&&&&&&&恶意节点数量=%d&&&&&&&&&&&&&&&&&\n", p.malicious_nums)

	if cnt >= required_cnt && !p.isReply[string(cmsg.Digest)] {
		p.pl.Plog.Printf("S%dN%d : has received 2f + 1 commits ... \n", p.ShardID, p.NodeID)
		//UpdateReputation(p, true)
		// if this node is left behind, so it need to requst blocks
		p.successfulConsensusRounds += 1
		//统计共识成功率
		p.pl.Plog.Printf("S%dN%d: 共识成功\n", p.ShardID, p.NodeID)
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
			p.pl.Plog.Printf("S%dN%d:当前信誉值:  %.2f\n", p.ShardID, p.NodeID, ReputationMap[p.ShardID][p.NodeID])

			//发送信誉值给Supervisor
			fmt.Println("发送节点的信誉值信息到Supervisor")
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
			// 这里假设Supervisor的IP地址是存储在ip_nodeTable中，并且节点ID为2
			networks.TcpDial(rep_msg_send, p.ip_nodeTable[params.DeciderShard][0])
			fmt.Println("-----发送成功-----")

			p.pl.Plog.Printf("S%dN%d: this round of pbft %d is end \n", p.ShardID, p.NodeID, p.sequenceID)

			p.sequenceID += 1
			//增加总的共识轮次

			//p.currentRoundInProgress = false
			// 本轮次处理完毕，重置状态
			if p.MaliciousNodes[p.ShardID][p.NodeID] {
				TestNodeInit(ReputationMap, p.ShardID, p.NodeID)
			}

		}
		// if this node is a main node, then unlock the sequencelock
		if p.NodeID == p.view {
			p.sequenceLock.Unlock()
			p.pl.Plog.Printf("S%dN%d get sequenceLock unlocked...\n", p.ShardID, p.NodeID)
		}
		//p.stopCommitTimer(string(cmsg.Digest))
	} else {
		//p.updateConsensusStatistics(false)
		p.pl.Plog.Printf("S%dN%d: ---------------------共识失败------------------------\n", p.ShardID, p.NodeID)

	}

	//将统计的共识结果发送给审计节点
	p.sendConsensusInfo()
	// 发送结束处理消息给审计节点
	p.pl.Plog.Printf("S%dN%d :Commit阶段发送结束处理消息给审计节点\n", p.ShardID, p.NodeID)
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
	p.pl.Plog.Printf("#####S%dN%d :Commit阶段发送结束处理消息成功####\n", p.ShardID, p.NodeID)

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
	// 获取节点的当前信誉值
	// 如果节点在映射中不存在，则创建一个新的条目
	if reputationMap[shardID] == nil {
		reputationMap[shardID] = make(map[uint64]float64)
	}
	// 如果节点的信誉值在映射中不存在，则初始化为默认值
	if _, ok := reputationMap[shardID][nodeID]; !ok {
		reputationMap[shardID][nodeID] = 60.0
	}
	reputation := reputationMap[shardID][nodeID]
	// 根据共识结果更新信誉值
	if consensusResult && !p.IsMaliciousNode(shardID, nodeID) {
		reputation += 1 // 如果处理成功，增加5个信誉值
		if reputation > 100 {
			reputation = 100 // 信誉值下限为0
		}
		/*if reputation > 90 && reputation < 100 {
			reputation = 90 - rand.Float64()*10 // 信誉值上限为100
		} else if reputation > 100 {
			reputation = 100 - rand.Float64()*10
		}*/
	} else {
		if !p.IsMaliciousNode(shardID, nodeID) {
			reputation -= 5 // 如果处理失败，减少10个信誉值
		}
		if reputation < 0 {
			reputation = 0 // 信誉值下限为0
		}
	}
	// 将更新后的信誉值存储回ReputationMap中
	reputationMap[shardID][nodeID] = reputation
	fmt.Printf("++++++++++++Updated reputation for S%dN%d: %f++++++++++++\n", shardID, nodeID, reputation)
}

// 信誉值异常行为函数
func TestNodeInit(reputationMap map[uint64]map[uint64]float64, shardID, nodeID uint64) {
	if reputationMap[shardID] == nil {
		reputationMap[shardID] = make(map[uint64]float64)
	}
	// 如果节点的信誉值在映射中不存在，则初始化为默认值
	if _, ok := reputationMap[shardID][nodeID]; !ok {
		reputationMap[shardID][nodeID] = 60.0
	}
	reputation := reputationMap[shardID][nodeID]
	randomReduction := rand.Float64()*10 + 1
	// 根据共识结果更新信誉值
	reputation -= randomReduction
	if reputation < 0 {
		reputation = 0 // 信誉值下限为0

	}
	reputationMap[shardID][nodeID] = reputation
}

// 设置恶意节点的方法
func (p *PbftConsensusNode) SetMaliciousNodes(shardID uint64, nodeIDs []uint64) {
	if p.MaliciousNodes[shardID] == nil {
		p.MaliciousNodes[shardID] = make(map[uint64]bool)
	}
	if ReputationMap[shardID] == nil {
		ReputationMap[shardID] = make(map[uint64]float64)
	}
	for _, nodeID := range nodeIDs {
		p.MaliciousNodes[shardID][nodeID] = true
		ReputationMap[shardID][nodeID] = float64(uint64(rand.Intn(51))) // 设置一个较低的信誉值
	}
}

// 设置恶意节点的方法
func (p *PbftConsensusNode) SetTimeoutNodes(shardID uint64, nodeIDs []uint64) {
	if p.TimeoutNodes[shardID] == nil {
		p.TimeoutNodes[shardID] = make(map[uint64]bool)
	}
	for _, nodeID := range nodeIDs {
		p.TimeoutNodes[shardID][nodeID] = true
		//ReputationMap[shardID][nodeID] = float64(uint64(rand.Intn(51))) // 设置一个较低的信誉值
	}
}

// 判断节点是否是低信誉值恶意节点
func (p *PbftConsensusNode) IsMaliciousNode(shardID, nodeID uint64) bool {
	if nodes, exists := p.MaliciousNodes[shardID]; exists {
		return nodes[nodeID]
	}

	return false
}

// 判断节点是否是响应超时的恶意节点
func (p *PbftConsensusNode) IsTimeoutNode(shardID, nodeID uint64) bool {
	// 检查是否是超时节点
	if timeoutNodes, exists := p.TimeoutNodes[shardID]; exists {
		if timeoutNodes[nodeID] {
			p.IsSuspicious = true
			return true
		}
	}
	return false
}

// 发送恶意节点信息
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
		// 发送信息到Supervisor，假设Supervisor的IP地址是存储在ip_nodeTable中，并且节点ID为0
		malicious_msg_send := message.MergeMessage(message.CMaliciousNodeMessage, maliciousMsgBytes)
		networks.TcpDial(malicious_msg_send, p.ip_nodeTable[params.DeciderShard][0]) //发送给supervisor
		networks.TcpDial(malicious_msg_send, p.ip_nodeTable[p.ShardID][2])           //发送给Audit审计节点
		p.pl.Plog.Printf("发送恶意节点信息: ShardID: %d, NodeIDs: %v\n", shardID, nodeIDs)
	}

}

func (p *PbftConsensusNode) sendTimeoutNodeInfo() {
	// 发送超时节点信息
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
		// 发送信息到Supervisor，假设Supervisor的IP地址是存储在ip_nodeTable中，并且节点ID为0
		timeoutMsgSend := message.MergeMessage(message.CTimeoutMessage, timeoutMsgBytes)
		networks.TcpDial(timeoutMsgSend, p.ip_nodeTable[params.DeciderShard][0]) //发送给supervisor
		networks.TcpDial(timeoutMsgSend, p.ip_nodeTable[p.ShardID][2])           //发送给Audit审计节点
		p.pl.Plog.Printf("发送超时节点信息: ShardID: %d, NodeIDs: %v\n", shardID, nodeIDs)
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

// 将收集到的共识轮次变量发送给审计节点
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
	p.pl.Plog.Printf("------发送共识总轮次和共识成功轮次到Audit-------------\n")
}

// shouldVote 是一个根据特定条件决定节点是否投票的函数
/*func (p *PbftConsensusNode) shouldVote() bool {
	if p.TimeoutNodes[p.ShardID][p.NodeID] {
		return false
	}
	if p.MaliciousNodes[p.ShardID][p.NodeID] {
		return false
	}
	return true
}*/

// 在每一轮共识结束后更新共识统计
/*func (p *PbftConsensusNode) updateConsensusStatistics(success bool) {
	p.totalConsensusRounds++
	if success {
		p.successfulConsensusRounds++
	}
}*/

/*// 计算共识成功率
func (p *PbftConsensusNode) calculateConsensusSuccessRate() float64 {
	if p.sequenceID == 0 {
		return 0.0
	}
	return float64(p.successfulConsensusRounds) / float64(p.sequenceID)
}
*/
