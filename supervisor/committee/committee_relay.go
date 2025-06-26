package committee

import (
	"blockEmulator/core"
	"blockEmulator/message"
	"blockEmulator/networks"
	"blockEmulator/params"
	"blockEmulator/supervisor/signal"
	"blockEmulator/supervisor/supervisor_log"
	"blockEmulator/utils"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"
)

type RelayCommitteeModule struct {
	csvPath      string
	dataTotalNum int
	nowDataNum   int
	batchDataNum int
	IpNodeTable  map[uint64]map[uint64]string
	sl           *supervisor_log.SupervisorLog
	Ss           *signal.StopSignal // to control the stop message sending
}

func NewRelayCommitteeModule(Ip_nodeTable map[uint64]map[uint64]string, Ss *signal.StopSignal, slog *supervisor_log.SupervisorLog, csvFilePath string, dataNum, batchNum int) *RelayCommitteeModule {
	return &RelayCommitteeModule{
		csvPath:      csvFilePath,
		dataTotalNum: dataNum,
		batchDataNum: batchNum,
		nowDataNum:   0,
		IpNodeTable:  Ip_nodeTable,
		Ss:           Ss,
		sl:           slog,
	}
}

// transfrom, data to transaction
// check whether it is a legal txs meesage. if so, read txs and put it into the txlist
func data2tx(data []string, nonce uint64) (*core.Transaction, bool) {
	if data[6] == "0" && data[7] == "0" && len(data[3]) > 16 && len(data[4]) > 16 && data[3] != data[4] {
		val, ok := new(big.Int).SetString(data[8], 10)
		if !ok {
			log.Panic("new int failed\n")
		}
		tx := core.NewTransaction(data[3][2:], data[4][2:], val, nonce)
		//fmt.Printf("-------------------Sender=%s, Recipient=%s, Value=%s, Nonce=%d---------------\n", data[3][2:], data[4][2:], val.String(), nonce)
		return tx, true
	}
	//fmt.Println("--------Invalid Transaction Data:----------", data)
	return &core.Transaction{}, false
}

func GetTransactions1(csvPath string, dataTotalNum, batchDataNum uint64) []*core.Transaction {
	txfile, err := os.Open(csvPath)
	if err != nil {
		log.Panic(err)
	}
	defer txfile.Close()
	reader := csv.NewReader(txfile)
	txlist := make([]*core.Transaction, 0) // 保存交易列表

	nowDataNum := uint64(0) // 当前数据数

	for {
		data, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Panic(err)
		}

		// 将从 CSV 文件读取到的数据转换成交易的形式
		if tx, ok := data2tx(data, nowDataNum); ok {
			txlist = append(txlist, tx)
			nowDataNum++
		}
		/*	else {
			fmt.Println("----------Failed to parse transaction from CSV row:----------", data)
		}*/

		// 如果达到了 batchDataNum 数量或者已经读取完所有数据，则返回交易列表
		if uint64(len(txlist)) == batchDataNum || nowDataNum == dataTotalNum {
			return txlist
		}
	}

	fmt.Println("-----------txlist------------", txlist)
	return txlist
}
func (rthm *RelayCommitteeModule) HandleOtherMessage([]byte) {

}

// ---Supervisor之Relay委员会发送交易
func (rthm *RelayCommitteeModule) txSending(txlist []*core.Transaction) {
	// ---发送到分片的映射the txs will be sent
	sendToShard := make(map[uint64][]*core.Transaction)

	for idx := 0; idx <= len(txlist); idx++ {
		if idx > 0 && (idx%params.InjectSpeed == 0 || idx == len(txlist)) {
			// send to shard
			for sid := uint64(0); sid < uint64(params.ShardNum); sid++ {
				it := message.InjectTxs{
					//--Txs是要发送到分片sid的交易列表
					Txs:       sendToShard[sid],
					ToShardID: sid,
				}
				itByte, err := json.Marshal(it)
				if err != nil {
					log.Panic(err)
				}
				send_msg := message.MergeMessage(message.CInject, itByte)
				//---开启子线程，将交易发送到相应的分片的主节点
				go networks.TcpDial(send_msg, rthm.IpNodeTable[sid][0])
			}
			//---重置分片映射
			sendToShard = make(map[uint64][]*core.Transaction)
			time.Sleep(time.Second)
		}
		if idx == len(txlist) {
			break
		}
		tx := txlist[idx]
		//---调用 utils.Addr2Shard 函数来获取发送者所在的分片 ID
		sendersid := uint64(utils.Addr2Shard(tx.Sender))
		//---将交易列表添加到相应的分片中
		sendToShard[sendersid] = append(sendToShard[sendersid], tx)
	}
}

// ---读取交易，数量=batchDataNumread transactions, the Number of the transactions is - batchDataNum
func (rthm *RelayCommitteeModule) MsgSendingControl() {
	txfile, err := os.Open(rthm.csvPath)
	if err != nil {
		log.Panic(err)
	}
	defer txfile.Close()
	reader := csv.NewReader(txfile)
	txlist := make([]*core.Transaction, 0) // save the txs in this epoch (round)

	for {
		data, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Panic(err)
		}

		//---将从CSV文件读取到的数据转换成tx交易的形式
		if tx, ok := data2tx(data, uint64(rthm.nowDataNum)); ok {
			txlist = append(txlist, tx)
			rthm.nowDataNum++
		}

		// ---读取到了batchData数量，则进行交易的发送---re-shard condition, enough edges
		if len(txlist) == int(rthm.batchDataNum) || rthm.nowDataNum == rthm.dataTotalNum {
			rthm.txSending(txlist)
			// ---重置变量，方便下一次读取数据reset the variants about tx sending
			txlist = make([]*core.Transaction, 0)
			rthm.Ss.StopGap_Reset()
		}

		//--如果全部交易已经读完，则break
		if rthm.nowDataNum == rthm.dataTotalNum {
			break
		}
	}
}

// no operation here
func (rthm *RelayCommitteeModule) HandleBlockInfo(b *message.BlockInfoMsg) {
	rthm.sl.Slog.Printf("received from shard %d in epoch %d.\n", b.SenderShardID, b.Epoch)
}
