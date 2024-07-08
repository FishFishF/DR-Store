package ecrbc

import (
	"communication/sender"
	"cryptolib"
	"fmt"
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

func StartECRBC(instanceid int, input []byte) {
	//log.Printf("Starting ECRBC %v for INPUT %v\n", instanceid, input)
	//log.Printf("Starting ECRBC %v for epoch %v\n", instanceid, epoch.Get())
	//p := fmt.Sprintf("[%v] Starting ECRBC for epoch %v", instanceid, epoch.Get())
	//logging.PrintLog(verbose, logging.NormalLog, p)

	votenum = 0
	votefailnum = 0
	readynum = 0
	DecodeEND = false
	voteEnough = false
	HaveReady = false
	ReadyEnd = false

	arrayLength := 1024 * 1024 * 4
	array := make([]byte, arrayLength)

	for i := 0; i < arrayLength; i++ {
		array[i] = byte(i)
	}

	inputHash = cryptolib.GenHash(array)
	//PaddingInput(&input, quorum.N2fSize())

	//log.Println(array)

	//log.Println("input1", input)
	log.Println(instanceid)

	if instanceid != 29 {
		StartTime = time.Now()
		//log.Println("Right data", data)

	} else if instanceid == 29 {
		StartTime = time.Now()
		//log.Println("SQSZIE", quorum.N2fSize())
		data, suc := ErasureEncoding(array, quorum.N2fSize(), quorum.NSize())
		fmt.Println(quorum.N2fSize())
		fmt.Println(quorum.NSize())
		if !suc {
			log.Fatal("Fail to erasure coding the input when start ECRBC!")
		}
		wrongData := make([][]byte, len(data))
		copy(wrongData, data)
		//wrongData[4] = []byte{123, 34, 79, 80, 83, 34, 58, 91, 123, 34, 109, 115, 103, 34, 58, 34, 101, 121, 74, 78, 99, 50, 99, 105, 79, 105, 74, 108, 101, 85, 112, 86, 90, 86, 104, 67, 98, 69, 108, 113, 98, 51, 108, 77, 81, 48}
		//log.Println("origin Data", wrongData)

		mRoot := cryptolib.GenMerkleTreeRoot(wrongData)
		//log.Println("data: ", data)
		branches, idxresult := cryptolib.ObtainMerklePath(wrongData)
		if len(branches) != len(wrongData) || len(branches) != len(idxresult) {
			log.Fatal("Fail to get merkle branch when start ECRBC!")
		}
		var msgs [][]byte
		for findex, frag := range wrongData {

			msg := message.ReplicaMessage{
				Mtype:    message.RBC_SEND,
				Instance: instanceid,
				Source:   id,
				TS:       utils.MakeTimestamp(),
				Payload:  frag,
				Epoch:    epoch.Get(),
				MTRoot:   mRoot,
				MTBranch: branches[findex],
				MTIndex:  idxresult[findex],
			}

			msgbyte, err := msg.Serialize()
			if err != nil {
				log.Fatalf("failed to serialize RBC message")
			}
			msgs = append(msgs, msgbyte)
		}
		sender.MACBroadcastWithErasureCode(msgs, message.ECRBC, true)
		//log.Println("Hash", TestHash)

	}

}

func HandleECRBCMsg(inputMsg []byte) {

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
	default:
		log.Printf("not supported")
	}

}

func SetEpoch(e int) {
	epoch.Set(e)
}

func InitECRBC(thisid int64, numNodes int, ver bool) {
	id = thisid
	n = numNodes
	verbose = ver
	quorum.StartQuorum(n)
	//log.Printf("ini rstatus %v",rstatus.GetAll())
	rstatus.Init()
	instancestatus.Init()
	cachestatus.Init()
	receivedReq.Init()
	receivedRoot.Init()
	receivedFrag.Init()
	receivedBranch.Init()
	decodedInstance.Init()
	decodeStatus = *utils.NewSet()
	entireInstance.Init()
	epoch.Init()

}

func ClearECRBCStatus(instanceid int) {
	rstatus.Delete(instanceid)
	instancestatus.Delete(instanceid)
	cachestatus.Delete(instanceid)
	receivedReq.Delete(instanceid)
	receivedRoot.Delete(instanceid)
	receivedFrag.Delete(instanceid)
	decodedInstance.Delete(instanceid)
	entireInstance.Delete(instanceid)
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
	log.Println("len of input: ", cap(input)/(1024*1024))

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

func ErasureDecoding(instanceID int, dataShards int, totalShards int) {
	if decodeStatus.HasItem(int64(instanceID)) {
		return
	}
	ids, frags := receivedFrag.GetAllValue(instanceID)
	log.Println(ids)
	data := make([][]byte, totalShards)

	for index, ID := range ids {
		data[ID] = frags[index]
	}

	entireIns := DecodeData(data, dataShards, totalShards)
	decodeStatus.AddItem(int64(instanceID))
	decodedInstance.SetValue(instanceID, data)
	//log.Printf("[%v] Decode the erasure code to : %v",instanceID,entireIns)
	entireInstance.Insert(instanceID, entireIns)
	//log.Println("result", data)

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

	//这里在做零填充的回溯，所以最后解码的东西经过处理变成了输入的内容
	for {
		if entireIns == nil || len(entireIns) == 0 {
			return nil
		}
		if entireIns[len(entireIns)-1] == 0 {
			entireIns = entireIns[0 : len(entireIns)-1]
		} else {
			break
		}
	}
	//log.Println("decode Success")
	return entireIns
}
