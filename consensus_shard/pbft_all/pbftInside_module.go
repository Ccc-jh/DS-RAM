// addtional module for new consensus
package pbft_all

import (
	"blockEmulator/core"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"
)

// simple implementation of pbftHandleModule interface ...
// only for block request and use transaction relay
type RawRelayPbftExtraHandleMod struct {
	pbftNode *PbftConsensusNode
	// pointer to pbft data
}

// ---提议不同类型请求的方法propose request with different types
func (rphm *RawRelayPbftExtraHandleMod) HandleinPropose() (bool, *message.Request) {
	// ---生成新块 new blocks
	block := rphm.pbftNode.CurChain.GenerateBlock()
	//---创建请求（区块请求）
	r := &message.Request{
		RequestType: message.BlockRequest,
		ReqTime:     time.Now(),
	}
	r.Msg.Content = block.Encode()

	return true, r
}

// the diy operation in preprepare
func (rphm *RawRelayPbftExtraHandleMod) HandleinPrePrepare(ppmsg *message.PrePrepare) bool {
	if rphm.pbftNode.CurChain.IsValidBlock(core.DecodeB(ppmsg.RequestMsg.Msg.Content)) != nil {
		rphm.pbftNode.pl.Plog.Printf("S%dN%d : not a valid block\n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID)
		rphm.pbftNode.UpdateReputation1(ReputationMap, rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, false)
		return false
	}
	rphm.pbftNode.pl.Plog.Printf("S%dN%d : the pre-prepare message is correct, putting it into the RequestPool. \n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID)
	rphm.pbftNode.requestPool[string(ppmsg.Digest)] = ppmsg.RequestMsg
	rphm.pbftNode.UpdateReputation1(ReputationMap, rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, true)

	return true
}

// the operation in prepare, and in pbft + tx relaying, this function does not need to do any.
// 把节点自身的角色信息发送到supervisor当中
func (rphm *RawRelayPbftExtraHandleMod) HandleinPrepare(pmsg *message.Prepare) bool {
	rphm.pbftNode.UpdateReputation1(ReputationMap, rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, true)
	/*//fmt.Println("-----发送节点的角色信息到Supervisor-----")
	rolemsg := message.RegisterNode{
		ShardID:    rphm.pbftNode.ShardID,
		NodeID:     rphm.pbftNode.NodeID,
		Role:       getNodeRole(ReputationMap[rphm.pbftNode.ShardID][rphm.pbftNode.NodeID]),
		IsMainNode: false,
		SeqID:      rphm.pbftNode.sequenceID,
	}
	rolebyte, err := json.Marshal(rolemsg)
	if err != nil {
		log.Panic()
	}
	role_msg_send := message.MergeMessage(message.CRegisterNodeMessage, rolebyte)
	//networks.Broadcast(p.RunningNode.IPaddr, p.getNeighborNodes(), msg_send2)
	networks.TcpDial(role_msg_send, rphm.pbftNode.ip_nodeTable[params.DeciderShard][0])
	//fmt.Println("-----发送成功-----")*/
	return true
}

// the operation in commit.
func (rphm *RawRelayPbftExtraHandleMod) HandleinCommit(cmsg *message.Commit) bool {
	r := rphm.pbftNode.requestPool[string(cmsg.Digest)]
	// requestType ...
	block := core.DecodeB(r.Msg.Content)
	rphm.pbftNode.pl.Plog.Printf("S%dN%d : adding the block %d...now height = %d \n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, block.Header.Number, rphm.pbftNode.CurChain.CurrentBlock.Header.Number)
	//---添加区块
	rphm.pbftNode.CurChain.AddBlock(block)
	rphm.pbftNode.pl.Plog.Printf("S%dN%d : added the block %d... \n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, block.Header.Number)
	rphm.pbftNode.CurChain.PrintBlockChain()
	// ---主节点将中继交易发送到其他的分片  now try to relay txs to other shards (for main nodes)
	if rphm.pbftNode.NodeID == rphm.pbftNode.view {
		rphm.pbftNode.pl.Plog.Printf("S%dN%d : main node is trying to send relay txs at height = %d \n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, block.Header.Number)
		// generate relay pool and collect txs excuted
		txExcuted := make([]*core.Transaction, 0)
		rphm.pbftNode.CurChain.Txpool.RelayPool = make(map[uint64][]*core.Transaction)
		relay1Txs := make([]*core.Transaction, 0)
		for _, tx := range block.Body {
			rsid := rphm.pbftNode.CurChain.Get_PartitionMap(tx.Recipient)
			if rsid != rphm.pbftNode.ShardID {
				ntx := tx
				ntx.Relayed = true
				rphm.pbftNode.CurChain.Txpool.AddRelayTx(ntx, rsid)
				relay1Txs = append(relay1Txs, tx)
			} else {
				txExcuted = append(txExcuted, tx)
			}
		}
		// send relay txs
		for sid := uint64(0); sid < rphm.pbftNode.pbftChainConfig.ShardNums; sid++ {
			if sid == rphm.pbftNode.ShardID {
				continue
			}
			relay := message.Relay{
				Txs:           rphm.pbftNode.CurChain.Txpool.RelayPool[sid],
				SenderShardID: rphm.pbftNode.ShardID,
				SenderSeq:     rphm.pbftNode.sequenceID,
			}
			rByte, err := json.Marshal(relay)
			if err != nil {
				log.Panic()
			}
			msg_send := message.MergeMessage(message.CRelay, rByte)
			//发送给每个分片的主节点
			go networks.TcpDial(msg_send, rphm.pbftNode.ip_nodeTable[sid][0])
			rphm.pbftNode.pl.Plog.Printf("S%dN%d : sended relay txs to %d\n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID, sid)
		}
		rphm.pbftNode.CurChain.Txpool.ClearRelayPool()
		// send txs excuted in this block to the listener
		// add more message to measure more metrics
		bim := message.BlockInfoMsg{
			BlockBodyLength: len(block.Body),
			ExcutedTxs:      txExcuted,
			Epoch:           0,
			Relay1Txs:       relay1Txs,
			Relay1TxNum:     uint64(len(relay1Txs)),
			SenderShardID:   rphm.pbftNode.ShardID,
			ProposeTime:     r.ReqTime,
			CommitTime:      time.Now(),
		}
		bByte, err := json.Marshal(bim)
		if err != nil {
			log.Panic()
		}
		msg_send := message.MergeMessage(message.CBlockInfo, bByte)
		go networks.TcpDial(msg_send, rphm.pbftNode.ip_nodeTable[params.DeciderShard][0])
		rphm.pbftNode.pl.Plog.Printf("S%dN%d : sended excuted txs\n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID)
		rphm.pbftNode.CurChain.Txpool.GetLocked()
		rphm.pbftNode.writeCSVline([]string{strconv.Itoa(len(rphm.pbftNode.CurChain.Txpool.TxQueue)), strconv.Itoa(len(txExcuted)), strconv.Itoa(int(bim.Relay1TxNum))})
		rphm.pbftNode.CurChain.Txpool.GetUnlocked()
	}
	return true
}

func (rphm *RawRelayPbftExtraHandleMod) HandleReqestforOldSeq(*message.RequestOldMessage) bool {
	fmt.Println("No operations are performed in Extra handle mod")
	return true
}

// the operation for sequential requests
func (rphm *RawRelayPbftExtraHandleMod) HandleforSequentialRequest(som *message.SendOldMessage) bool {
	if int(som.SeqEndHeight-som.SeqStartHeight+1) != len(som.OldRequest) {
		rphm.pbftNode.pl.Plog.Printf("S%dN%d : the SendOldMessage message is not enough\n", rphm.pbftNode.ShardID, rphm.pbftNode.NodeID)
	} else { // add the block into the node pbft blockchain
		for height := som.SeqStartHeight; height <= som.SeqEndHeight; height++ {
			r := som.OldRequest[height-som.SeqStartHeight]
			if r.RequestType == message.BlockRequest {
				b := core.DecodeB(r.Msg.Content)
				rphm.pbftNode.CurChain.AddBlock(b)
			}
		}
		rphm.pbftNode.sequenceID = som.SeqEndHeight + 1
		rphm.pbftNode.CurChain.PrintBlockChain()
	}
	return true
}
