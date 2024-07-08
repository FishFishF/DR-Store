package rbc

import (
	"communication/sender"
	"cryptolib"
	"log"
	"message"
	"quorum"
	"time"
	"utils"

	"github.com/klauspost/reedsolomon"
	"github.com/youchainhq/go-bls/bls"
)

var id int64
var n int
var verbose bool
var epoch utils.IntValue

func StartRBC(instanceid int, input []byte) {
	//log.Printf("Starting RBC %v for epoch %v\n", instanceid, epoch.Get())
	//p := fmt.Sprintf("[%v] Starting RBC for epoch %v", instanceid, epoch.Get())
	//logging.PrintLog(verbose, logging.NormalLog, p)
	voteEnough = false
	votenum = 0
	votefailnum = 0
	voteEnough = false
	DecodeEnd = false

	arrayLength := 1024 * 1024 * 30
	array := make([]byte, arrayLength)

	for i := 0; i < arrayLength; i++ {
		array[i] = byte(i)
	}

	log.Println(instanceid)
	log.Println("id", id)

	data, _ := ErasureEncoding(array, 15, 39)
	var blsMgr = bls.NewBlsManager()
	MyNodeSecretKey, MyNodePublicKey = blsMgr.GenerateKey()

	if instanceid != 119 {
		sign := MyNodeSecretKey.Sign(data[id])
		signBytes := sign.Compress().Bytes()
		publickeyBytes := MyNodePublicKey.Compress().Bytes()
		msg := message.ReplicaMessage{
			Mtype:        message.RBC_SEND,
			Instance:     instanceid,
			Source:       id,
			TS:           utils.MakeTimestamp(),
			Payload:      data[id],
			Epoch:        epoch.Get(),
			OneSign:      signBytes,
			OnePublicKey: publickeyBytes,
		}
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize RBC message")
		}

		sender.SendToNode(msgbyte, 39, message.RBC)

	}
	StartTime = time.Now()
}

func HandleRBCMsg(inputMsg []byte) {

	tmp := message.DeserializeMessageWithSignature(inputMsg)
	input := tmp.Msg
	content := message.DeserializeReplicaMessage(input)
	mtype := content.Mtype

	if !cryptolib.VerifyMAC(content.Source, tmp.Msg, tmp.Sig) {
		log.Printf("[Authentication Error] The signature of rbc message has not been verified.")
		return
	}

	//log.Printf("handling message from %v, type %v", source, mtype)
	switch mtype {
	case message.RBC_SEND:
		HandleSend(content)
	case message.RBC_ECHO:
		HandleEcho(content)
	case message.RBC_READY:
		HandleReady(content)
	case message.RBC_VOTE:
		HandleVote(content)
	case message.RBC_PKREQUIRE:
		HandleRequire(content)
	case message.RBC_PKBACK:
		HandlePKBACK(content)
	default:
		log.Printf("not supported")
	}

}

func SetEpoch(e int) {
	epoch.Set(e)
}

func InitRBC(thisid int64, numNodes int, ver bool) {
	id = thisid
	n = numNodes
	verbose = ver
	quorum.StartQuorum(n)
	//log.Printf("ini rstatus %v",rstatus.GetAll())
	rstatus.Init()
	instancestatus.Init()
	cachestatus.Init()
	receivedReq.Init()
	received.Init()
	epoch.Init()
	receivedRoot.Init()
	receivedFrag.Init()
}

func ClearRBCStatus(instanceid int) {
	rstatus.Delete(instanceid)
	instancestatus.Delete(instanceid)
	cachestatus.Delete(instanceid)
	receivedReq.Delete(instanceid)
}

/*
The function will encode input to erasure code. input is the data that to be encoded; dataShards is the minimize number that decoding;
totalShards is the total number that encoding
*/
func ErasureEncoding(input []byte, dataShards int, totalShards int) ([][]byte, bool) {
	if dataShards == 0 {
		return [][]byte{}, false
	}
	//log.Println("len of input: ", len(input))
	enc, err := reedsolomon.New(dataShards, totalShards-dataShards)
	if err != nil {
		log.Println("Fail to execute New() in reed-solomon: ", err)
		return [][]byte{}, false
	}

	PaddingInput(&input, dataShards)
	log.Println("len of input: ", cap(input))

	data := make([][]byte, totalShards)
	paritySize := len(input) / dataShards
	// log.Println("dataSize: ", dataShards)
	// log.Println("parityShards: ", totalShards-dataShards)
	// log.Println("paritySize: ", paritySize)

	for i := 0; i < totalShards; i++ {
		data[i] = make([]byte, paritySize)
		if i < dataShards {
			data[i] = input[i*paritySize : (i+1)*paritySize]
		}

	}
	//log.Println("len of data: ",len(data),data)

	err = enc.Encode(data)

	if err != nil {
		log.Println("Fail to encode the input to erasure conde: ", err)
		return nil, false
	}
	ok, err1 := enc.Verify(data)
	if err1 != nil || !ok {
		log.Println("Fail verify the erasure code: ", err)
		return nil, false
	}
	//log.Println("len of data: ",len(data),data)
	return data, true
}

/*
if the length of input is not an integer multiple of size, padding "0" in the end
*/
func PaddingInput(input *[]byte, size int) {
	if size == 0 {
		return
	}
	initLen := len(*input)
	remainder := initLen % size
	if remainder == 0 {
		return
	} else {
		ending := make([]byte, size-remainder)
		*input = append(*input, ending[:]...)
	}
}

func ErasureDecoding(RootID int, dataShards int, totalShards int) []byte {
	ids, frags := receivedFrag.GetAllValue(RootID)
	//log.Println(ids)
	data := make([][]byte, totalShards)

	for index, ID := range ids {
		data[ID] = frags[index]
	}

	entireIns := DecodeData(data, dataShards, totalShards)
	return entireIns

}

func DecodeData(data [][]byte, dataShards int, totalShards int) []byte {
	enc, err := reedsolomon.New(dataShards, totalShards-dataShards)
	if err != nil {
		log.Println("Fail to execute New() in reed-solomon: ", err)
		return nil
	}
	//t1 := time.Now()
	err = enc.Reconstruct(data)
	//t2 := time.Now()
	//d1 := t2.Sub(t1)
	//log.Println(d1)
	if err != nil {
		//log.Println("Fail to decode the erasure conde: ",err)
		return nil
	}
	//log.Printf("*******Decode erasure: %s",data)

	var entireIns []byte

	for i := 0; i < quorum.N2fSize(); i++ {
		entireIns = append(entireIns, data[i]...)
	}
	return entireIns
}
