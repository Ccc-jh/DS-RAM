package main

import (
	"blockEmulator/build"
	"blockEmulator/consensus_shard/pbft_all/audit"
	"blockEmulator/shard/vrf"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/pflag"
)

var (
	shardNum int
	nodeNum  int
	shardID  int
	nodeID   int
	modID    int
	isClient bool
	isGen    bool
	//randSource = rand.New(rand.NewSource(time.Now().UnixNano()))
	mutex = sync.Mutex{}
)

// 全局私钥池，模拟每个节点的私钥
var privKeyPool = make(map[int]map[int]*ecdsa.PrivateKey)
var GlobalAuditNodes = make(map[uint64]map[uint64]bool)

func main() {
	pflag.IntVarP(&shardNum, "shardNum", "S", 2, "indicate that how many shards are deployed")
	pflag.IntVarP(&nodeNum, "nodeNum", "N", 4, "indicate how many nodes of each shard are deployed")
	pflag.IntVarP(&shardID, "shardID", "s", 0, "id of the shard to which this node belongs, for example, 0")
	pflag.IntVarP(&nodeID, "nodeID", "n", 0, "id of this node, for example, 0")
	pflag.IntVarP(&modID, "modID", "m", 3, "choice Committee Method,for example, 0, [CLPA_Broker,CLPA,Broker,Relay] ")
	pflag.BoolVarP(&isClient, "client", "c", false, "whether this node is a client")
	pflag.BoolVarP(&isGen, "gen", "g", false, "generation bat")
	pflag.Parse()

	// 初始化所有分片所有节点的私钥
	initAllPrivKeys(shardNum, nodeNum)
	if isGen {
		build.GenerateBatFile(nodeNum, shardNum, modID)
		build.GenerateShellFile(nodeNum, shardNum, modID)
		return
	}
	if isClient {
		build.BuildSupervisor(uint64(nodeNum), uint64(shardNum), uint64(modID))
	} else {
		consensusNodes := uint64((nodeNum - 2) * 2 / 3)
		auditNodes := make(map[uint64]map[uint64]bool)
		for sid := 0; sid < shardNum; sid++ {
			nodes := selectAuditNodes(sid, nodeNum, 1)
			auditNodes[uint64(sid)] = nodes
			GlobalAuditNodes[uint64(sid)] = nodes
			audit.AuditNodeMap[uint64(sid)] = nodes // 赋值给audit包
		}
		build.BuildNewPbftNode(uint64(nodeID), uint64(nodeNum), uint64(shardID), uint64(shardNum), uint64(modID), auditNodes[uint64(shardID)], consensusNodes)
	}
}

// 初始化所有分片所有节点的私钥
func initAllPrivKeys(shardNum, nodeNum int) {
	for sid := 0; sid < shardNum; sid++ {
		privKeyPool[sid] = make(map[int]*ecdsa.PrivateKey)
		for nid := 0; nid < nodeNum; nid++ {
			key, err := crypto.GenerateKey()
			if err != nil {
				fmt.Println("Failed to generate key:", err)
				os.Exit(1)
			}
			privKeyPool[sid][nid] = key
		}
	}
}

// VRF随机选择审计节点
func selectAuditNodes(shardID int, nodeNum int, auditCount int) map[uint64]bool {
	type nodeScore struct {
		nodeID uint64
		score  uint64
	}
	var scores []nodeScore

	// 用当前时间戳+shardID作为种子，实际可用区块高度等
	seed := make([]byte, 16)
	binary.LittleEndian.PutUint64(seed[:8], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(seed[8:], uint64(shardID))

	for i := 0; i < nodeNum; i++ {
		nodeID := uint64(i)
		privKey := privKeyPool[shardID][i]
		vrfResult := vrf.GenerateVRF(privKey, seed)
		// 取VRF输出前8字节转为uint64作为分数
		score := uint64(0)
		for j := 0; j < 8 && j < len(vrfResult.RandomValue); j++ {
			score = (score << 8) | uint64(vrfResult.RandomValue[j])
		}
		scores = append(scores, nodeScore{nodeID, score})
	}
	// 按score升序排序，选前auditCount个
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score < scores[j].score
	})
	auditNodes := make(map[uint64]bool)
	for i := 0; i < auditCount && i < len(scores); i++ {
		auditNodes[scores[i].nodeID] = true
	}
	fmt.Printf("Shard %d audit nodes: %v\n", shardID, auditNodes)
	return auditNodes
}
