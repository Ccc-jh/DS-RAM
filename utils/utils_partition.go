package utils

import (
	"blockEmulator/params"
	"log"
	"strconv"
)

// the default method将交易地址作为发送到相应分片的依据
func Addr2Shard(addr Address) int {
	last16_addr := addr[len(addr)-8:]
	num, err := strconv.ParseUint(last16_addr, 16, 64)
	if err != nil {
		log.Panic(err)
	}
	return int(num) % params.ShardNum
}
