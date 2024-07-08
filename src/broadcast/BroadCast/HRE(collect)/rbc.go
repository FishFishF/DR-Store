package rbc

import (
	"bytes"
	"log"
	"message"
	"sync"
	"time"
	"utils"

	"github.com/youchainhq/go-bls/bls"
	"go.dedis.ch/kyber/share"
)

type RBCStatus int

const (
	STATUS_IDLE  RBCStatus = 0
	STATUS_SEND  RBCStatus = 1
	STATUS_ECHO  RBCStatus = 2
	STATUS_READY RBCStatus = 3
)

var rstatus utils.IntBoolMap       //broadcast status,only has value when  RBC Deliver
var instancestatus utils.IntIntMap // status for each instance, used in RBC
var cachestatus utils.IntIntMap    // status for each instance
var receivedReq utils.IntByteMap   //req is serialized RawOPS or replica msg
var received utils.IntSet
var elock sync.Mutex
var rlock sync.Mutex
var StartTime time.Time
var EndTime time.Time
var voteEnough bool
var votenum int
var votefailnum int
var Mynode node
var nodes = make([]node, 6)
var MyPayload []byte
var MySecretKey = make([]bls.SecretKey, 6)
var MyNodeSecretKey bls.SecretKey
var MyNodePublicKey bls.PublicKey
var HashSet = make([]uint64, 6)
var myRoot []byte
var mybranches [][]byte
var myidxresult []int64
var receivedFrag utils.IntBytesMap
var receivedRoot utils.IntByteMap //merkle root of all erasure coding frags of instance
var DecodeEnd bool
var resultData []byte

var MyFingerPrint []byte

type node struct {
	privateKey *share.PriShare
	publicKey  *share.PubPoly
}

// check whether the instance has been deliver in RBC
func QueryStatus(instanceid int) bool {
	v, exist := rstatus.Get(instanceid)
	return v && exist
}

func QueryStatusCount() int {
	return rstatus.GetCount()
}

func QueryReq(instanceid int) []byte {
	v, exist := receivedReq.Get(instanceid)
	if !exist {
		return nil
	}
	return v
}

func HandleSend(m message.ReplicaMessage) {
	if DecodeEnd == true {
		return
	}

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}
	//d1 := time.Now()
	if !VerifyMerkleRoot(m.Instance, m.OneFingerPrint, m.MTBranch, m.MTIndex, m.MTRoot) {
		log.Printf("Failed to verify the merkle root of instance %d from %v", m.Instance, m.Source)
		return
	}

	CompareFig := GF8Mod(m.Payload)
	if bytes.Compare(CompareFig, m.OneFingerPrint) != 0 {
		log.Println("验证错误")
		return
	}

	//d2 := time.Now()
	//log.Println("Verify time   ", d2.Sub(d1))

	//log.Printf("[%v] Handling send message from node %v", m.Instance, m.Source)

	//log.Println("Get Message", m.Payload)
	thisRoot := utils.BytesToInt(m.MTRoot)
	receivedFrag.InsertValueAndInt(thisRoot, m.Payload, m.Source)
	ids, _ := receivedFrag.GetAllValue(thisRoot)

	if len(ids) >= 27 {
		rlock.Lock()
		DecodeEnd = true
		log.Println("Enough data", len(ids))
		resultData = ErasureDecoding(thisRoot, 15, 39)
		EndTime = time.Now()
		log.Println("Time   ", EndTime.Sub(StartTime))
		rlock.Unlock()
	}

}
