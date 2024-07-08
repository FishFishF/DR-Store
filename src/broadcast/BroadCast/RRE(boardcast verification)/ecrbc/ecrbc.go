package ecrbc

import (
	"bytes"
	"communication/sender"
	"cryptolib"
	"fmt"
	"log"
	"logging"
	"message"
	"quorum"
	"sync"
	"time"
	"utils"
)

type RBCStatus int

const (
	STATUS_IDLE  RBCStatus = 0
	STATUS_SEND  RBCStatus = 1
	STATUS_ECHO  RBCStatus = 2
	STATUS_READY RBCStatus = 3
	STATUS_Vote  RBCStatus = 4
)

var rstatus utils.IntBoolMap       //broadcast status,only has value when  RBC Deliver
var instancestatus utils.IntIntMap // status for each instance, used in RBC
var cachestatus utils.IntIntMap    // status for each instance
var receivedReq utils.IntByteMap   //req is serialized RawOPS or replica msg
var receivedRoot utils.IntByteMap  //merkle root of all erasure coding frags of instance
var receivedFrag utils.IntBytesMap
var receivedBranch utils.IntBytesMap

var decodedInstance utils.IntBytesMap //decode the erasure for instance upon receive f+1 frags
var decodeStatus utils.Set            //set true if decode
var entireInstance utils.IntByteMap   //set the decoded instance payload
var elock sync.Mutex
var rlock sync.Mutex
var decodeLock sync.Mutex
var votenum int //记录票数
var voteEnough bool
var DecodeEND bool
var votefailnum int //记录错误票数
var StartTime time.Time
var EndTime time.Time
var myRoot []byte
var mybranches [][][]byte
var myidxresult [][]int64
var HaveReady bool
var readynum int
var ReadyEnd bool
var inputHash []byte

// check whether the instance has been deliver in RBC
func QueryStatus(instanceid int) bool {
	v, exist := rstatus.Get(instanceid)
	return v && exist
}

func QueryStatusCount() int {
	return rstatus.GetCount()
}

func QueryReq(instanceid int) []byte {
	v, exist := entireInstance.Get(instanceid)
	if !exist {
		return nil
	}
	return v
}

func QueryInstanceFrag(instanceid int) []byte {
	v, exist := receivedReq.Get(instanceid)
	if !exist {
		return nil
	}
	return v
}

func QueryInstanceRoot(instanceid int) ([]byte, bool) {
	v, exist := receivedRoot.Get(instanceid)
	if !exist {
		return nil, false
	}
	return v, true
}

func QueryInstanceBranch(instanceid int) ([][]byte, []int64, bool) {
	branch, exist := receivedBranch.GetM(instanceid)
	if !exist {
		return nil, nil, false
	}
	index, exi := receivedBranch.GetV(instanceid)
	if !exi {
		return nil, nil, false
	}
	return branch, index, true
}

func HandleSend(m message.ReplicaMessage) {
	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	p := fmt.Sprintf("[%v] Handling ECRBC send message from node %v", m.Instance, m.Source)
	logging.PrintLog(verbose, logging.NormalLog, p)
	instancestatus.Insert(m.Instance, int(STATUS_SEND))

	msg := m
	msg.Source = id
	msg.Mtype = message.RBC_ECHO

	if !VerifyMerkleRoot(m.Instance, m.Payload, m.MTBranch, m.MTIndex, m.MTRoot) {
		log.Printf("Failed to verify the merkle root of instance %d from %v", m.Instance, m.Source)
		return
	}

	//log.Printf("[HandleSend] Success to verify the merkle root of instance %d from %v", m.Instance, m.Source)
	receivedReq.Insert(m.Instance, m.Payload)
	receivedRoot.Insert(m.Instance, m.MTRoot)
	receivedBranch.InsertM(m.Instance, m.MTBranch)
	receivedBranch.InsertV(m.Instance, m.MTIndex)

	msgbyte, err := msg.Serialize()
	if err != nil {
		log.Fatalf("failed to serialize echo message")
	}
	var data [][]byte
	data = append(data, msgbyte)

	sender.MACBroadcastWithErasureCode(data, message.ECRBC, false)

	v, exist := cachestatus.Get(m.Instance)
	if exist && v >= int(STATUS_ECHO) {
		SendReady(m)
	}
	if exist && v == int(STATUS_READY) {
		Deliver(m)
	}
}

func HandleEcho(m message.ReplicaMessage) {
	if DecodeEND == true {
		return
	}

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	//p := fmt.Sprintf("[%v] Handling ECRBC echo message from node %v", m.Instance, m.Source)
	//logging.PrintLog(verbose, logging.NormalLog, p)

	if !VerifyMerkleRoot(m.Instance, m.Payload, m.MTBranch, m.MTIndex, m.MTRoot) {
		log.Printf("[HandleEcho error] Failed to verify the merkle root of instance %d from %v", m.Instance, m.Source)
		return
	}
	//log.Printf("[HandleEcho] Success to verify the merkle root of instance %d from %v", m.Instance, m.Source)
	receivedFrag.InsertValueAndInt(m.Instance, m.Payload, m.Source)

	hash := utils.IntToString(m.Instance)
	quorum.Add(m.Source, hash, nil, quorum.PP)

	// if quorum.CheckSmallQuorum(hash, quorum.PP) {
	// 	decodeLock.Lock()
	// 	ErasureDecoding(m.Instance, quorum.N2fSize(), quorum.NSize())
	// 	decodeLock.Unlock()
	// }
	if quorum.CheckQuorum(hash, quorum.PP) && !HaveReady {
		//Vote(m)
		SendReady(m)
		return
	}

	if quorum.CheckQuorum(hash, quorum.PP) && ReadyEnd && !DecodeEND {
		DecodeEND = true
		DecodeandVerify(m.Instance)
	}
}

func SendReady(m message.ReplicaMessage) {
	elock.Lock()
	HaveReady = true
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_SEND) {
		instancestatus.Insert(m.Instance, int(STATUS_ECHO))
		elock.Unlock()
		p := fmt.Sprintf("Sending ready for instance id %v", m.Instance)
		logging.PrintLog(verbose, logging.NormalLog, p)

		var msgs [][]byte
		//var frag []byte

		msg := m
		msg.Source = id
		msg.Mtype = message.RBC_READY
		msg.Payload = nil

		//selfIndex, _ := utils.Int64ToInt(id)

		// frag = QueryInstanceFrag(m.Instance)
		root, _ := QueryInstanceRoot(m.Instance)
		msg.MTRoot = root
		// branch, index, exi1 := QueryInstanceBranch(m.Instance)

		// if frag == nil || !exi || !exi1 {
		// 	//log.Printf("\n\n\n\n\n\n\nReconstruct frag%v\n\n\n\n\n\n\n\n",m.Instance)
		// 	data, exi := decodedInstance.Get(m.Instance)
		// 	if !exi {
		// 		log.Fatalf("%v has noe been decoded", m.Instance)
		// 	}
		// 	frag = data[selfIndex]
		// 	root = cryptolib.GenMerkleTreeRoot(data)
		// 	branches, idxresult := cryptolib.ObtainMerklePath(data)
		// 	branch, index = branches[selfIndex], idxresult[selfIndex]
		// 	//if m.Instance ==8{
		// 	//	log.Printf("\n\n\n\n[Sendready Reconstruct] Get frag %v \nroot%v \n Branch%v \n, index%v\n",frag,root,branch,index)
		// 	//}
		// }

		// msg.Payload = frag
		// msg.MTRoot = root
		// msg.MTBranch = branch
		// msg.MTIndex = index
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize RBC message")
		}
		msgs = append(msgs, msgbyte)

		sender.MACBroadcastWithErasureCode(msgs, message.ECRBC, false)

	} else {
		v, exist := cachestatus.Get(m.Instance)
		elock.Unlock()
		if exist && v == int(STATUS_READY) {
			instancestatus.Insert(m.Instance, int(STATUS_ECHO))
			SendReady(m)
		} else {
			cachestatus.Insert(m.Instance, int(STATUS_ECHO))
		}
	}
}

func HandleReady(m message.ReplicaMessage) {
	if ReadyEnd {
		return
	}

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	// p := fmt.Sprintf("[%v] Handling ready message from node %v", m.Instance, m.Source)
	// logging.PrintLog(verbose, logging.NormalLog, p)

	// if !VerifyMerkleRoot(m.Instance, m.Payload, m.MTBranch, m.MTIndex, m.MTRoot) {
	// 	log.Printf("[HandleReady error] Failed to verify the merkle root of instance %d from %v", m.Instance, m.Source)
	// 	return
	// }
	// log.Printf("[HandleReady] Success to verify the merkle root of instance %d from %v", m.Instance, m.Source)
	// log.Println(readynum)
	// receivedFrag.InsertValueAndInt(m.Instance, m.Payload, m.Source)
	h, _ := receivedRoot.Get(m.Instance)
	if bytes.Compare(h, m.MTRoot) != 0 {
		return
	}

	readynum++

	if readynum == quorum.FSize()+1 {
		if !HaveReady {
			msg := m
			msg.Source = id
			SendReady(m)
		}
	}

	if readynum >= quorum.NSize()-quorum.FSize() {
		ReadyEnd = true
		ids, _ := receivedFrag.GetAllValue(m.Instance)
		if len(ids) >= quorum.N2fSize() {
			DecodeEND = true
			DecodeandVerify(m.Instance)
		}
		return
	}

}

func Deliver(m message.ReplicaMessage) {
	rlock.Lock()
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_ECHO) {
		instancestatus.Insert(m.Instance, int(STATUS_READY))
		rlock.Unlock()

		p := fmt.Sprintf("[%v] ECRBC Deliver the request epoch %v, curEpoch %v", m.Instance, m.Epoch, epoch.Get())
		logging.PrintLog(verbose, logging.NormalLog, p)

		rstatus.Insert(m.Instance, true)

	} else {
		rlock.Unlock()
		cachestatus.Insert(m.Instance, int(STATUS_READY))
	}
}

func VerifyMerkleRoot(instanceid int, rd []byte, branch [][]byte, index []int64, root []byte) bool {
	h, exi := receivedRoot.Get(instanceid)
	if exi {
		if bytes.Compare(h, root) != 0 {
			return false
		}
	}

	hash := cryptolib.ObtainMerkleNodeHash(rd)
	for i := 0; i < len(index); i++ {
		if index[i]%2 == 0 { //leftnode
			chash := append(branch[i], hash...)
			hash = cryptolib.ObtainMerkleNodeHash(chash)
		} else {
			chash := append(hash, branch[i]...)
			hash = cryptolib.ObtainMerkleNodeHash(chash)
		}
	}

	return bytes.Compare(root, hash) == 0
}

func HandleVote(m message.ReplicaMessage) {
	result, exist := rstatus.Get(m.Instance)
	if voteEnough == true {
		return
	}
	if exist && result {
		return
	}

	if m.Value == 1 {
		votenum++
	} else {
		votefailnum++
	}
	if votenum >= quorum.QuorumSize() {
		voteEnough = true
		log.Println("ACCEPT")
		EndTime = time.Now()

		log.Println("Time   ", EndTime.Sub(StartTime))
	} else if votefailnum >= quorum.QuorumSize() {
		voteEnough = true
		log.Println("REFUSE")
		EndTime = time.Now()
		log.Println("Time   ", EndTime.Sub(StartTime))
	}
}

func DecodeandVerify(instanceid int) {

	ErasureDecoding(instanceid, quorum.N2fSize(), quorum.NSize())
	originData, _ := entireInstance.Get(instanceid)
	decodeLock.Lock()
	VerifyData := cryptolib.GenHash(originData)
	if bytes.Compare(VerifyData, inputHash) != 0 {
		log.Println("verify failed")
		decodeLock.Unlock()
		return
	}
	decodeLock.Unlock()
	log.Println("verify success")
	data, _ := ErasureEncoding(originData, quorum.N2fSize(), quorum.NSize())
	mRoot := cryptolib.GenMerkleTreeRoot(data)
	//log.Println("data: ", data)
	branches, idxresult := cryptolib.ObtainMerklePath(data)
	myRoot = mRoot
	mybranches = branches
	myidxresult = idxresult

	EndTime = time.Now()
	log.Println("Time   ", EndTime.Sub(StartTime))
	log.Println("END FINISH")

	return

}
