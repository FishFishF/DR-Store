package rbc

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
var receivedRoot utils.IntByteMap
var receivedFrag utils.IntBytesMap

var MyNodeSecretKey bls.SecretKey
var MyNodePublicKey bls.PublicKey
var HashSet = make([]uint64, 6)
var EncodeData = make([][]byte, quorum.NSize())
var EncodeFinish bool
var receivedFrag1 utils.IntBytesMap
var receivedFrag2 utils.IntBytesMap
var MyFingerPrint []byte
var MyMtRoot []byte
var MyMTBranch [][]byte
var MyMTIndex []int64
var MyNewFingerprint []byte

// 这里是同态的标签
var fingerprintEnough bool
var EndReady bool
var NewFGNUM int
var ReadyEnd bool
var readynum int

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

func HandleEcho(m message.ReplicaMessage) {
	if id != 7 {
		if EndReady == false {
			result, exist := rstatus.Get(m.Instance)
			if exist && result {
				return
			}
			if !VerifyMerkleRoot(m.Instance, m.OneFingerPrint, m.MTBranch, m.MTIndex, m.MTRoot) {
				log.Printf("Failed to verify the merkle root of instance %d from %v", m.Instance, m.Source)
				return
			}
			receivedFrag.InsertValueAndInt(m.Instance, m.OneFingerPrint, m.Source)

			//验证过后说明这个指纹正确，创建一个组来存指纹，可以用类似data的，满足n-f用一个标签来标记
			//新指纹不用存，直接用计数器，达到n-f的时候就发送ready

			if fingerprintEnough == false {
				ids, _ := receivedFrag.GetAllValue(m.Instance)
				//这个地方的判断本质上是n-2f，但是因为添加了冗余，原本有多少数据块就够验证了
				if len(ids) == 3 {
					fingerprintEnough = true

				}
			}

			if bytes.Compare(m.Payload, MyNewFingerprint) == 0 {

				NewFGNUM++
			} else {
				log.Println("data incorrect", m.Instance, m.Source)

			}
			if NewFGNUM == 5 {
				SendReady(m)
			}
		}

	}

}

func SendReady(m message.ReplicaMessage) {
	elock.Lock()
	EndReady = true
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_SEND) {
		instancestatus.Insert(m.Instance, int(STATUS_ECHO))
		elock.Unlock()

		msg := m
		msg.Payload = MyNewFingerprint
		msg.OneFingerPrint = nil
		msg.Mtype = message.RBC_READY
		msg.MTBranch = nil
		msg.MTRoot = nil
		msg.MTIndex = nil
		msg.Source = id
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize RBC message")
		}
		sender.MACBroadcast(msgbyte, message.RBC)
	}
}

func HandleReady(m message.ReplicaMessage) {
	if id != 7 {
		if ReadyEnd {
			return
		}
		result, exist := rstatus.Get(m.Instance)
		if exist && result {
			return
		}
		log.Printf("[%v] Handling ready message from node %v", m.Instance, m.Source)
		if bytes.Compare(MyNewFingerprint, m.Payload) != 0 {
			return
		}

		readynum++
		if readynum == quorum.FSize()+1 {
			if !ReadyEnd {
				SendReady(m)
			}
		}

		if readynum == quorum.NSize()-quorum.FSize() && fingerprintEnough == true {
			Data := ErasureDecoding(m.Instance, 3, 7)
			NewData, _ := ErasureEncoding(Data, 3, 8)
			if bytes.Compare(NewData[7], m.Payload) == 0 {
				log.Println("------------verify")
				log.Println(NewData[7])
				log.Println(m.Payload)
				log.Println("------------verify success")
			}

			newmRoot := cryptolib.GenMerkleTreeRoot(NewData)
			branches, idxresult := cryptolib.ObtainMerklePath(NewData)
			if len(branches) != len(NewData) || len(branches) != len(idxresult) {
				log.Fatal("Fail to get merkle branch when start ECRBC!")
			}
			log.Println(newmRoot)
			EndTime = time.Now()
			log.Println("All Time ", EndTime.Sub(StartTime))
			log.Println("entire Finish")

			return
		}
	}

}

func Deliver(m message.ReplicaMessage) {
	rlock.Lock()
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_ECHO) {
		if !received.IsTrue(m.Instance) {
			receivedReq.Insert(m.Instance, m.Payload)
			received.AddItem(m.Instance)
		}
		instancestatus.Insert(m.Instance, int(STATUS_READY))
		rlock.Unlock()

		p := fmt.Sprintf("[%v] RBC Deliver the request epoch %v, curEpoch %v", m.Instance, m.Epoch, epoch.Get())
		logging.PrintLog(verbose, logging.NormalLog, p)

		//if epoch.Get() == m.Epoch{
		rstatus.Insert(m.Instance, true)
		//if m.Instance<100{
		//	log.Printf("insert %v rstatus: %v",m.Instance,rstatus.GetAll())
		//}

		//}

	} else {
		rlock.Unlock()
		cachestatus.Insert(m.Instance, int(STATUS_READY))
	}
}

func HandleNewSend(m message.ReplicaMessage) {

	if id != 7 {
		result, exist := rstatus.Get(m.Instance)
		if exist && result {
			return
		}

		log.Printf("[%v] Handling send message from node %v", m.Instance, m.Source)
		instancestatus.Insert(m.Instance, int(STATUS_SEND))
		MyNewFingerprint = m.Payload
		msg := m
		msg.MTBranch = MyMTBranch
		msg.MTRoot = MyMtRoot
		msg.MTIndex = MyMTIndex
		msg.Mtype = message.RBC_ECHO
		msg.Source = id
		msg.OneFingerPrint = MyFingerPrint
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize RBC message")
		}
		sender.MACBroadcast(msgbyte, message.RBC)

	}

}

func Vote(m message.ReplicaMessage) {

	elock.Lock()

	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_SEND) {
		instancestatus.Insert(m.Instance, int(STATUS_ECHO))
		elock.Unlock()

		msg := m
		msg.Value = 1

		msg.Source = id
		msg.Mtype = message.RBC_VOTE
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize ready message")
		}

		//sender.MACBroadcast(msgbyte, message.ECRBC)
		sender.MACBroadcast(msgbyte, message.RBC)
		log.Printf("Sending Vote for instance id %v", m.Instance)

	}

}

func HandleVote(m message.ReplicaMessage) {
	result, exist := rstatus.Get(m.Instance)
	if voteEnough == true {
		return
	}
	if exist && result {
		return
	}

	// p := fmt.Sprintf("[%v] Handling Vote message from node %v", m.Instance, m.Source)
	// logging.PrintLog(verbose, logging.NormalLog, p)
	// log.Println("Handle vote")
	// log.Println("n-f", quorum.QuorumSize())
	log.Printf("[%v] Handling Vote message from node %v", m.Instance, m.Source)

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

func HandleRequire(m message.ReplicaMessage) {
	if voteEnough == true {
		return
	}

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	log.Printf("[%v] Handling Require message from node %v", m.Instance, m.Source)

	votenum++
	if votenum >= 4 {
		voteEnough = true
		log.Println("Finish")
		EndTime = time.Now()
		log.Println("Time   ", EndTime.Sub(StartTime))
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
