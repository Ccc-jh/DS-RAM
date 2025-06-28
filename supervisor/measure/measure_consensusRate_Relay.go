package measure

import (
	"blockEmulator/message"
	"fmt"
)

type TestModule_SuccessRate struct {
	epochID          int
	totalProposals   []int
	successfulBlocks []int
}

func NewTestModule_SuccessRate() *TestModule_SuccessRate {
	return &TestModule_SuccessRate{
		epochID:          -1,
		totalProposals:   make([]int, 0),
		successfulBlocks: make([]int, 0),
	}
}

func (tmsr *TestModule_SuccessRate) OutputMetricName() string {
	return "Consensus_Success_Rate"
}

func (tmsr *TestModule_SuccessRate) UpdateMeasureRecord(b *message.BlockInfoMsg) {

	epochid := b.Epoch

	// extend slices to match current epochID
	for tmsr.epochID < epochid {
		tmsr.totalProposals = append(tmsr.totalProposals, 0)
		tmsr.successfulBlocks = append(tmsr.successfulBlocks, 0)
		tmsr.epochID++
	}

	tmsr.totalProposals[epochid]++
	fmt.Printf("Epoch %d Total Proposals: %d\n", epochid, tmsr.totalProposals[epochid])
	if b.BlockBodyLength == 0 {
		return
	}
	if b.BlockBodyLength > 0 {
		tmsr.successfulBlocks[epochid]++
		fmt.Printf("Epoch %d Successful Blocks: %d\n", epochid, tmsr.successfulBlocks[epochid])
	} else {
		fmt.Printf("Warning: Empty block in epoch %d\n", epochid)
	}
}

func (tmsr *TestModule_SuccessRate) HandleExtraMessage([]byte) {}

func (tmsr *TestModule_SuccessRate) OutputRecord() (perEpochSuccessRate []float64, totalSuccessRate float64) {
	tmsr.writeToCSV()

	perEpochSuccessRate = make([]float64, 0)
	totalProposals := 0
	totalSuccesses := 0

	for eid, proposals := range tmsr.totalProposals {
		if proposals > 0 {
			successRate := float64(tmsr.successfulBlocks[eid]) / float64(proposals)
			perEpochSuccessRate = append(perEpochSuccessRate, successRate)
			totalProposals += proposals
			totalSuccesses += tmsr.successfulBlocks[eid]
		} else {
			perEpochSuccessRate = append(perEpochSuccessRate, 0.0)
		}
	}

	if totalProposals > 0 {
		totalSuccessRate = float64(totalSuccesses) / float64(totalProposals)
	} else {
		totalSuccessRate = 0.0
	}

	return
}

func (tmsr *TestModule_SuccessRate) writeToCSV() {
	fileName := tmsr.OutputMetricName()
	measureName := []string{"EpochID", "Total Proposals", "Successful Blocks", "Success Rate"}
	measureVals := make([][]string, 0)

	for eid, proposals := range tmsr.totalProposals {
		successRate := float64(tmsr.successfulBlocks[eid]) / float64(proposals)
		csvLine := []string{
			fmt.Sprintf("%d", eid),
			fmt.Sprintf("%d", proposals),
			fmt.Sprintf("%d", tmsr.successfulBlocks[eid]),
			fmt.Sprintf("%.4f", successRate),
		}
		measureVals = append(measureVals, csvLine)
	}
	WriteMetricsToCSV(fileName, measureName, measureVals)
}
