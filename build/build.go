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
Obtain the interaction frequency of nodes.
*/
var (
	AllNodes map[uint64]map[uint64]*pbft_all.PbftConsensusNode
	role     string
)

func InitConfig(nid, nnm, sid, snm uint64) *params.ChainConfig {
	csvPath := params.FileInput
	dataTotalNum := params.TotalDataSize
	batchDataNum := params.BatchSize

	txs := committee.GetTransactions1(csvPath, uint64(dataTotalNum), uint64(batchDataNum))

	freq := KMedoids.CalculateInteractionFrequency(txs)

	maxNodesPerCluster := nnm
	maxIterations := 550
	nodes := shard.GenerateNodes(snm, nnm, freq)
	//Execute the clustering algorithm.
	medoids, clusters := KMedoids.KMedoids(nodes, int(snm), maxIterations, int(maxNodesPerCluster))
	for i := 0; i < int(snm); i++ {
		if len(clusters[i]) > int(maxNodesPerCluster) {
			// Sort nodes in the current cluster by their distance to the medoid
			sort.SliceStable(clusters[i], func(a, b int) bool {
				return KMedoids.CalculateWeightedDistance(clusters[i][a], medoids[i]) < KMedoids.CalculateWeightedDistance(clusters[i][b], medoids[i])
			})
			// Remove nodes exceeding the quantity limit.
			for j := maxNodesPerCluster; int(j) < len(clusters[i]); j++ {
				nextCluster := (i + 1) % int(snm)
				// Move to the second most similar cluster
				clusters[nextCluster] = append(clusters[nextCluster], clusters[i][j])
			}
			// Keep only the first maxNodesPerCluster nodes in the current cluster
			clusters[i] = clusters[i][:maxNodesPerCluster]
		}
	}

	for i, cluster := range clusters {
		shardID := i
		for j, _ := range cluster {
			clusters[i][j].ShardAfter = uint64(shardID)

		}
	}
	// Reassign node IDs.
	for i, cluster := range clusters {
		for j, _ := range cluster {
			newID := uint64(j)
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

	for i := uint64(0); i < snm; i++ {
		// Check if the current shard already exists in the IPmap_nodeTable. If it does not exist, create a new mapping.
		if _, ok := params.IPmap_nodeTable[i]; !ok {
			params.IPmap_nodeTable[i] = make(map[uint64]string)

		}
		// Iterate through the nodes in the current shard and assign an IP address to each node.
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
