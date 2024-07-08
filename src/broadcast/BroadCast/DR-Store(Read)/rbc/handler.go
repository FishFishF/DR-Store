package rbc

import (
	"bytes"
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
	if instanceid != 23 {
		StartTime = time.Now()
		arrayLength := 1024 * 1024 * 4 // 数组长度
		array := make([]byte, arrayLength)

		for i := 0; i < arrayLength; i++ {
			array[i] = byte(i)
		}

		log.Println(instanceid)
		log.Println("id", id)

		//reconstruct
		Newdata := make([][]byte, 8)
		data := make([][]byte, 8)
		paritySize := len(array) / 4
		// log.Println("dataSize: ", dataShards)
		// log.Println("parityShards: ", totalShards-dataShards)
		// log.Println("paritySize: ", paritySize)
		for i := 0; i < 8; i++ {
			Newdata[i] = make([]byte, paritySize)
			if i < 4 {
				Newdata[i] = array[i*paritySize : (i+1)*paritySize]
			}
		}
		//log.Println(Newdata)
		if len(Newdata[0])%4 != 0 {
			for i := 0; i < 4; i++ {
				Newdata[i], _ = PaddingInputNew(Newdata[i], 8)
			}
		}

		//log.Println(Newdata)
		OnePartSize := len(Newdata[0]) / 4
		// log.Println("partsize", OnePartSize)

		for i := 0; i < 8; i++ {
			if i < 4 {
				for j := 0; j < 4; j++ {
					data[i] = BytesCombine1(data[i], Newdata[j][i*OnePartSize:(i+1)*OnePartSize])
				}
			} else {
				data[i] = make([]byte, len(Newdata[0]))

			}

		}
		data, _ = ErasureEncodingKnowData(data, 4, 8)
		// log.Println(data)

		msg := message.ReplicaMessage{
			Mtype:    message.RBC_SEND,
			Instance: instanceid,
			Source:   id,
			TS:       utils.MakeTimestamp(),
			Payload:  data[id][0 : 1*OnePartSize],
			Epoch:    epoch.Get(),
		}
		msgbyte, err := msg.Serialize()
		if err != nil {
			log.Fatalf("failed to serialize RBC message")
		}

		EndTime = time.Now()
		log.Println(EndTime.Sub(StartTime))
		sender.SendToNode(msgbyte, 7, message.RBC)

	} else {
		StartTime = time.Now()
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

func PaddingInputNew(input []byte, size int) ([]byte, int) {
	if size == 0 {
		return nil, 999
	}
	initLen := len(input)
	remainder := initLen % size
	result := make([]byte, initLen)
	copy(result, input)
	if remainder == 0 {
		return result, 0
	} else {
		ending := make([]byte, size-remainder)
		result = append(result, ending[:]...)
	}
	return result, size - remainder

}

func BytesCombine1(pBytes ...[]byte) []byte {
	length := len(pBytes)
	s := make([][]byte, length)
	for index := 0; index < length; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

func ErasureEncodingKnowData(data [][]byte, dataShards int, totalShards int) ([][]byte, bool) {
	if dataShards == 0 {
		return [][]byte{}, false
	}
	//log.Println("len of input: ", len(input))
	enc, err := reedsolomon.New(dataShards, totalShards-dataShards)
	if err != nil {
		log.Println("Fail to execute New() in reed-solomon: ", err)
		return [][]byte{}, false
	}

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
