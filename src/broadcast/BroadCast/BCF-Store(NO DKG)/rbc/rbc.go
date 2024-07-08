package rbc

import (
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
	"go.dedis.ch/kyber/pairing/bn256"
	"go.dedis.ch/kyber/share"
	"go.dedis.ch/kyber/sign/tbls"
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
var MyPayload []byte

var MyNodeSecretKey bls.SecretKey
var MyNodePublicKey bls.PublicKey
var EncodeData = make([][]byte, quorum.NSize())
var EncodeFinish bool
var receivedFrag1 utils.IntBytesMap
var receivedFrag2 utils.IntBytesMap
var totalData []byte
var pubs = make([]bls.PublicKey, 0, quorum.NSize()-quorum.FSize())
var sigs = make([]bls.Signature, 0, quorum.NSize()-quorum.FSize()) //si
var totalCBC int
var ECHOFinish bool
var SignatureTime time.Time

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
	if ECHOFinish {
		return
	}
	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	//log.Printf("Handling echo message from node %v", m.Source)
	var blsMgr = bls.NewBlsManager()
	// pk, _ := blsMgr.DecPublicKey(m.PublicKey)
	// log.Println(pk)
	//sign, _ := blsMgr.DecSignature(m.SignPayload[id])
	idint := int(id)
	//log.Println(m.PublicKey)
	receivedFrag1.InsertValueAndInt(idint, m.PublicKey, m.Source)
	receivedFrag2.InsertValueAndInt(idint, m.SignPayload[id], m.Source)

	ids1, pk := receivedFrag1.GetAllValue(idint)
	ids2, sign := receivedFrag2.GetAllValue(idint)

	if len(ids1) >= quorum.NSize()-quorum.FSize() && len(ids2) >= quorum.NSize()-quorum.FSize() && EncodeFinish {
		rlock.Lock()
		ECHOFinish = true
		sigs := make([]bls.Signature, 0, len(ids1))
		for index := range ids1 {
			pkv, _ := blsMgr.DecPublicKey(pk[index])
			signv, _ := blsMgr.DecSignature(sign[index])
			err := pkv.Verify(EncodeData[id], signv)
			if err != nil {
				log.Println("verify failed")
				rlock.Unlock()
				return

			}
			sigs = append(sigs, signv)

		}
		rlock.Unlock()
		log.Println("verify success")
		d1 := time.Now()
		_, err := blsMgr.Aggregate(sigs)
		//time.Sleep(2 * 100 * time.Millisecond)
		if err != nil {
			log.Println("agg failed")
		}
		d2 := time.Now()
		log.Println("agg time", d2.Sub(d1))
		// EndTime = time.Now()
		// log.Println("Time", EndTime.Sub(StartTime))
		SignatureTime = time.Now()
		log.Println("signature time", SignatureTime.Sub(StartTime))

		FinishPayload := cryptolib.GenHash(totalData)
		FinishSign := MyNodeSecretKey.Sign(FinishPayload)
		FinishSignByte := FinishSign.Compress().Bytes()

		msg := m
		msg.Payload = FinishPayload
		msg.OneSign = FinishSignByte
		msg.SignPayload = nil
		msg.Source = id
		msg.OnePublicKey = MyNodePublicKey.Compress().Bytes()
		msg.Mtype = message.RBC_READY

		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize echo message")
		}

		sender.SendToNode(msgbyte, 39, message.RBC)

	}

	// hash := utils.BytesToString(m.Hash)
	// quorum.Add(m.Source, hash, nil, quorum.PP)

	// if quorum.CheckQuorum(hash, quorum.PP) {
	// 	if !received.IsTrue(m.Instance) {
	// 		receivedReq.Insert(m.Instance, m.Payload)
	// 		received.AddItem(m.Instance)
	// 	}
	// 	SendReady(m)
	// }
}

func SendReady(m message.ReplicaMessage) {
	elock.Lock()
	stat, _ := instancestatus.Get(m.Instance)

	if stat == int(STATUS_SEND) {
		instancestatus.Insert(m.Instance, int(STATUS_ECHO))
		elock.Unlock()
		p := fmt.Sprintf("Sending ready for instance id %v", m.Instance)
		logging.PrintLog(verbose, logging.NormalLog, p)
		log.Printf("Sending ready for instance id %v", m.Instance)

		msg := m
		msg.Source = id
		msg.Mtype = message.RBC_READY
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize ready message")
		}
		sender.MACBroadcast(msgbyte, message.RBC)
	} else {
		v, exist := cachestatus.Get(m.Instance)
		elock.Unlock()
		if exist && v == int(STATUS_READY) {
			instancestatus.Insert(m.Instance, int(STATUS_ECHO))
			Deliver(m)
		} else {
			cachestatus.Insert(m.Instance, int(STATUS_ECHO))
		}
	}
}

func HandleReady(m message.ReplicaMessage) {
	//log.Printf("Handle Ready from%v", m.Source)

	if totalCBC >= quorum.NSize()-quorum.FSize() {
		return
	}

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}
	var blsMgr = bls.NewBlsManager()
	// pk, _ := blsMgr.DecPublicKey(m.PublicKey)
	// log.Println(pk)
	//sign, _ := blsMgr.DecSignature(m.SignPayload[id])
	//log.Println(m.PublicKey)
	pkv, _ := blsMgr.DecPublicKey(m.OnePublicKey)
	signv, _ := blsMgr.DecSignature(m.OneSign)
	messageH := m.Payload
	err := pkv.Verify(messageH, signv)
	if err != nil {
		log.Println("verify failed")
	}
	pubs = append(pubs, pkv)
	sigs = append(sigs, signv)
	totalCBC++
	if totalCBC == quorum.NSize()-quorum.FSize() {
		asig, _ := blsMgr.Aggregate(sigs)
		apub, _ := blsMgr.AggregatePublic(pubs)
		asigByte := asig.Compress().Bytes()
		apubByte := apub.Compress().Bytes()
		msg := m
		msg.OnePublicKey = apubByte
		msg.OneSign = asigByte
		msg.Source = id
		msg.Mtype = message.RBC_CBC
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize echo message")
		}
		sender.MACBroadcast(msgbyte, message.RBC)
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

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	// p := fmt.Sprintf("[%v] Handling send message from node %v", m.Instance, m.Source)
	// logging.PrintLog(verbose, logging.NormalLog, p)
	log.Printf("[%v] Handling send message from node %v", m.Instance, m.Source)
	instancestatus.Insert(m.Instance, int(STATUS_SEND))
	d1 := time.Now()
	var blsMgr = bls.NewBlsManager()
	MyNodeSecretKey, MyNodePublicKey = blsMgr.GenerateKey()
	d2 := time.Now()
	log.Println("Generate Time", d2.Sub(d1))
	totalData = m.Payload
	data, _ := ErasureEncoding(m.Payload, quorum.N2fSize(), quorum.NSize())
	EncodeData = data
	EncodeFinish = true
	SignResult := make([]bls.Signature, len(data))
	d3 := time.Now()
	for i := 0; i < len(data); i++ {
		SignResult[i] = MyNodeSecretKey.Sign(data[i])
	}
	d4 := time.Now()
	log.Println("Sign Time", d4.Sub(d3))
	SignByte := make([][]byte, len(SignResult))
	for i := 0; i < len(SignResult); i++ {
		SignByte[i] = SignResult[i].Compress().Bytes()
	}
	//log.Println(SignByte)

	msg := m
	msg.Payload = nil
	msg.SignPayload = SignByte
	msg.Source = id
	msg.PublicKey = MyNodePublicKey.Compress().Bytes()
	msg.Mtype = message.RBC_ECHO

	msgbyte, err := msg.Serialize()
	if err != nil {
		log.Fatalf("failed to serialize echo message")
	}
	sender.MACBroadcast(msgbyte, message.RBC)

	//log.Println("Get Message", m.Payload)

	//log.Println("This data", id, data[id])

	// hash := rabin.New()
	// hash.Write(m.Payload)
	// sum := hash.Sum64()
	// EndTime = time.Now()
	// log.Println(EndTime.Sub(StartTime))

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

func MakePrivateKey(nodes []node, n, f, threshold int, suite *bn256.Suite) []node {
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	for i, x := range priPoly.Shares(n) {
		nodes[i].privateKey = x
		nodes[i].publicKey = pubPoly
	}
	return nodes
}

func signMessage(Messages [][]byte, node node, threshold int, n int) [][]byte {
	suite := bn256.NewSuite()
	sigShares := make([][]byte, 0)
	for i := 0; i < len(Messages); i++ {
		sig, _ := tbls.Recover(suite, node.publicKey, Messages[i], sigShares, threshold, n)
		sigShares = append(sigShares, sig)
	}
	return sigShares
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
		log.Println("finish")
		EndTime = time.Now()
		log.Println("Time   ", EndTime.Sub(StartTime))
	}

}

func HandlePKBACK(m message.ReplicaMessage) {

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}

	log.Println(MyNodeSecretKey)
	log.Println(MyNodePublicKey)

	log.Println("Source", m.Source)

	//signature all
	_, suc := ErasureEncoding(MyPayload, quorum.N2fSize(), quorum.NSize())
	if !suc {
		log.Fatal("Handle Send encode fail")
		return
	}

	EndTime = time.Now()
	log.Println("Time      ", EndTime.Sub(StartTime))

}

func HandleCBC(m message.ReplicaMessage) {

	result, exist := rstatus.Get(m.Instance)
	if exist && result {
		return
	}
	var blsMgr = bls.NewBlsManager()
	// pk, _ := blsMgr.DecPublicKey(m.PublicKey)
	// log.Println(pk)
	//sign, _ := blsMgr.DecSignature(m.SignPayload[id])
	//log.Println(m.PublicKey)
	pkv, _ := blsMgr.DecPublicKey(m.OnePublicKey)
	signv, _ := blsMgr.DecSignature(m.OneSign)
	err := pkv.Verify(cryptolib.GenHash(totalData), signv)
	if err != nil {
		log.Println("verify failed")
	}
	log.Println("CBC success")
	EndTime := time.Now()
	log.Println("CBC END Time", EndTime.Sub(StartTime))

}
