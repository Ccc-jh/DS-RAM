package params

import "time"

var (
	ConsensusMethod     = 0
	Block_Interval      = 7000  // generate new block interval
	MaxBlockSize_global = 6000  // the block contains the maximum number of transactions
	InjectSpeed         = 7000  // the transaction inject speed
	TotalDataSize       = 70000 // the total number of txs
	BatchSize           = 80000 // supervisor read a batch of txs then send them, it should be larger than inject speed
	ResponseTimeout     = 150 * time.Millisecond
	ReputationThreshold = 85.0
	BrokerNum           = 10
	NodesInShard        = 4
	ShardNum            = 4
	DataWrite_path      = "./result/"                                     // measurement data result output path
	LogWrite_path       = "./log"                                         // log output path
	SupervisorAddr      = "127.0.0.1:18800"                               //supervisor ip address
	FileInput           = `E:\code\2000000to2999999_BlockTransaction.csv` //the raw BlockTransaction data path
	// FileInput = `/home/cjh/mywork/src/2000000to2999999_BlockTransaction.csv` //the raw BlockTransaction data path
)
