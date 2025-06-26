package build

import (
	"blockEmulator/KMedoids"
	"blockEmulator/consensus_shard/pbft_all"
	"blockEmulator/consensus_shard/pbft_all/audit"
	"blockEmulator/consensus_shard/pbft_all/candidate"
	"blockEmulator/params"
	"blockEmulator/shard"
	"blockEmulator/supervisor"
	"blockEmulator/supervisor/committee"
	"fmt"
	"sort"
	"strconv"
	"time"
)

/*
*
获取节点的交互频率
*/
var (
	AllNodes map[uint64]map[uint64]*pbft_all.PbftConsensusNode
	role     string
)

func InitConfig(nid, nnm, sid, snm uint64) *params.ChainConfig {
	csvPath := params.FileInput          // CSV 文件路径
	dataTotalNum := params.TotalDataSize // 总数据数
	batchDataNum := params.BatchSize     // 每批数据数

	txs := committee.GetTransactions1(csvPath, uint64(dataTotalNum), uint64(batchDataNum))

	fmt.Println("--------获取节点交互频率------")
	freq := KMedoids.CalculateInteractionFrequency(txs)

	fmt.Println("--------获取交互频率完成------")
	maxNodesPerCluster := nnm
	maxIterations := 550
	nodes := shard.GenerateNodes(snm, nnm, freq)
	fmt.Println("--------执行聚类算法------")
	medoids, clusters := KMedoids.KMedoids(nodes, int(snm), maxIterations, int(maxNodesPerCluster))
	fmt.Println("--------聚类完成------")
	for i := 0; i < int(snm); i++ {
		if len(clusters[i]) > int(maxNodesPerCluster) {
			// Sort nodes in the current cluster by their distance to the medoid
			sort.SliceStable(clusters[i], func(a, b int) bool {
				return KMedoids.CalculateWeightedDistance(clusters[i][a], medoids[i]) < KMedoids.CalculateWeightedDistance(clusters[i][b], medoids[i])
			})
			// 删除超出数量的节点
			for j := maxNodesPerCluster; int(j) < len(clusters[i]); j++ {
				nextCluster := (i + 1) % int(snm)
				// 移动到第二相似的簇中
				clusters[nextCluster] = append(clusters[nextCluster], clusters[i][j])
			}
			// Keep only the first maxNodesPerCluster nodes in the current cluster
			clusters[i] = clusters[i][:maxNodesPerCluster]
		}
	}

	for i, cluster := range clusters {
		shardID := i // 簇的索引作为分片ID
		for j, _ := range cluster {
			clusters[i][j].ShardAfter = uint64(shardID) // 更新clusters中对应节点的ShardAfter字段

		}
	}
	// 重新分配节点 ID
	for i, cluster := range clusters {
		for j, _ := range cluster {
			// 计算新的节点 ID，从 0 开始递增

			newID := uint64(j)
			// 更新节点的 ID
			clusters[i][j].NodeID = newID
		}
	}
	fmt.Println("Clustered Nodes:")
	for i, cluster := range clusters {
		fmt.Printf("Cluster %d:\n", i)
		for _, node := range cluster {
			fmt.Printf("NodeID: %d, ShardAfter: %d,shardID: %d\n", node.NodeID, node.ShardAfter, node.ShardID)
		}
	}
	//初始化节点的信誉值60.0
	/*	ReputationMap = make(map[uint64]map[uint64]float64)
		for i := uint64(0); i < snm; i++ {
			ReputationMap[i] = make(map[uint64]float64)
			for j := uint64(0); j < nnm; j++ {
				ReputationMap[i][j] = 60.0
			}
		}*/

	//初始化节点的IP地址
	for i := uint64(0); i < snm; i++ {
		// 检查当前分片是否在 IPmap_nodeTable 中已经存在，如果不存在则创建一个新的映射
		if _, ok := params.IPmap_nodeTable[i]; !ok {
			params.IPmap_nodeTable[i] = make(map[uint64]string)

		}
		// 遍历当前分片的节点，为每个节点设置 IP 地址
		for j := uint64(0); j < nnm; j++ {
			params.IPmap_nodeTable[i][clusters[int(i)][j].NodeID] = "127.0.0.1:" + strconv.Itoa(28800+int(i)*100+int(j))

		}
	}
	params.ShardNum = int(snm)
	params.IPmap_nodeTable[params.DeciderShard] = make(map[uint64]string)
	params.IPmap_nodeTable[params.DeciderShard][0] = params.SupervisorAddr
	params.NodesInShard = len(medoids)
	params.ShardNum = len(clusters)

	fmt.Println("IPmap_nodeTable:", params.IPmap_nodeTable)

	pcc := &params.ChainConfig{
		ChainID:        sid,
		NodeID:         nid,
		ShardID:        sid,
		Nodes_perShard: uint64(params.NodesInShard),
		ShardNums:      snm,
		BlockSize:      uint64(params.MaxBlockSize_global),
		BlockInterval:  uint64(params.Block_Interval),
		InjectSpeed:    uint64(params.InjectSpeed),
	}
	return pcc

}

func BuildSupervisor(nnm, snm, mod uint64) {
	methodID := params.ConsensusMethod
	var measureMod []string
	if methodID == 0 {
		measureMod = params.MeasureRelayMod
	}

	lsn := new(supervisor.Supervisor)
	lsn.NewSupervisor(params.SupervisorAddr, InitConfig(123, nnm, 123, snm), params.CommitteeMethod[methodID], measureMod...)
	time.Sleep(10000 * time.Millisecond)
	go lsn.SupervisorTxHandling()
	lsn.TcpListen()
}

func BuildNewPbftNode(nid, nnm, sid, snm, mod uint64, auditNodes map[uint64]bool, consensusNodeCount uint64) {
	methodID := params.ConsensusMethod
	if nid == 0 {
		role = "leader"
	} else if auditNodes[nid] {
		role = "audit"
	} else if nid < consensusNodeCount {
		role = "consensus"
	} else {
		role = "candidate"
	}

	switch role {
	case "leader":
		worker := pbft_all.NewPbftNode(sid, nid, InitConfig(nid, nnm, sid, snm), params.CommitteeMethod[methodID])
		go worker.Propose()
		worker.TcpListen()
	case "consensus":
		worker := pbft_all.NewPbftNode(sid, nid, InitConfig(nid, nnm, sid, snm), params.CommitteeMethod[methodID])
		worker.TcpListen()
	case "audit":
		audit := audit.NewAuditNode(sid, nid, InitConfig(nid, nnm, sid, snm))
		audit.PrintAudMessg()
		audit.TcpListen()
	case "candidate":
		candidate := candidate.NewCandidateNode(sid, nid, InitConfig(nid, nnm, sid, snm))
		candidate.PrintCanMessg()
		candidate.TcpListen()
	}

}
