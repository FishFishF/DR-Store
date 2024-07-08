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
	StartTime = time.Now()
	if id != 39 {

		arrayLength := 1024 * 1024 * 15
		array := make([]byte, arrayLength)

		for i := 0; i < arrayLength; i++ {
			array[i] = byte(i)
		}

		data, _ := ErasureEncoding(array, 15, 39)
		log.Println(instanceid)
		log.Println("id", id)

		AllfingerPrint := make([][]byte, 39)
		for i := 0; i < 39; i++ {
			AllfingerPrint[i] = GF8Mod(data[i])
		}

		mRoot := cryptolib.GenMerkleTreeRoot(AllfingerPrint)
		branches, idxresult := cryptolib.ObtainMerklePath(AllfingerPrint)
		if len(branches) != len(AllfingerPrint) || len(branches) != len(idxresult) {
			log.Fatal("Fail to get merkle branch when start ECRBC!")
		}

		myRoot = mRoot
		mybranches = branches[id]
		myidxresult = idxresult[id]
		MyFingerPrint = AllfingerPrint[id]

		msg := message.ReplicaMessage{
			Mtype:          message.RBC_SEND,
			Instance:       instanceid,
			Source:         id,
			TS:             utils.MakeTimestamp(),
			Payload:        data[id],
			Epoch:          epoch.Get(),
			MTRoot:         myRoot,
			MTBranch:       mybranches,
			MTIndex:        myidxresult,
			OneFingerPrint: MyFingerPrint,
		}
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize RBC message")
		}
		EndTime = time.Now()
		log.Println(EndTime.Sub(StartTime))
		sender.SendToNode(msgbyte, 39, message.RBC)

	}

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

func GF8Mod(origin []byte) []byte {
	end := false
	//8阶多项式,这里需要修改成拿一个参数来生成10阶GF(256)的不可约多项式
	ModP := []byte{3, 0, 5, 16, 11, 250, 12, 0, 1, 230}
	d1 := time.Now()
	for end == false {
		ModPnew := make([]byte, len(ModP))
		copy(ModPnew, ModP)
		MulNum := reedsolomon.GalDivide(origin[0], ModPnew[0])
		for i := 0; i < len(ModPnew); i++ {
			ModPnew[i] = reedsolomon.GalMultiply(ModPnew[i], MulNum)
		}
		for i := 0; i < len(ModPnew); i++ {
			origin[i] = reedsolomon.GalAdd(origin[i], ModPnew[i])
		}
		for len(origin) > 0 && origin[0] == 0 {
			origin = origin[1:]
		}

		if len(origin) < len(ModP) {
			end = true
		}
	}

	if len(origin) != 9 {
		log.Println("---------------长度错误")
	}
	d2 := time.Now()
	log.Println(d2.Sub(d1))
	return origin
}
