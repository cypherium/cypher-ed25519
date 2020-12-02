package reconfig

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/math"
	"github.com/cypherium/cypherBFT/crypto/sha3"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/onet"
	"github.com/cypherium/cypherBFT/onet/network"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
	"github.com/cypherium/cypherBFT/rlp"
)

type serviceCallback interface {
	networkMsgAck(si *network.ServerIdentity, msg *networkMsg)
}

const Gossip_MSG = 8

type retryMsg struct {
	Address string
	Msg     *networkMsg
}

type msgHeadInfo struct {
	blockN    uint64
	keyblockN uint64
}

type netService struct {
	*onet.ServiceProcessor // We need to embed the ServiceProcessor, so that incoming messages are correctly handled.
	server                 *onet.Server
	serverAddress          string
	serverID               string
	heartBeat              *heartBeat
	gossipMsg              map[common.Hash]msgHeadInfo
	muGossip               sync.Mutex

	goMap        map[string]*int32 //atomic int
	idDataMap    map[string]*common.Queue
	backend      serviceCallback
	curBlockN    uint64
	curKeyBlockN uint64
}

func newNetService(sName string, conf *Reconfig, callback serviceCallback) *netService {
	registerService := func(c *onet.Context) (onet.Service, error) {
		s := &netService{ServiceProcessor: onet.NewServiceProcessor(c)}
		s.RegisterProcessorFunc(network.RegisterMessage(&networkMsg{}), s.handleNetworkMsgAck)
		return s, nil
	}
	onet.RegisterNewService(sName, registerService)
	address := conf.cph.ExtIP().String() + ":" + conf.config.OnetPort
	server := onet.NewKcpServer(address)
	s := server.Service(sName).(*netService)
	s.server = server
	s.serverID = address
	s.serverAddress = address
	s.heartBeat = Heartbeat_New(conf.config.HeartbeatPort)
	s.gossipMsg = make(map[common.Hash]msgHeadInfo)
	s.goMap = make(map[string]*int32)
	s.idDataMap = make(map[string]*common.Queue)
	s.backend = callback

	return s
}

func (s *netService) StartStop(isStart bool) {
	if isStart {
		s.server.Start()
		s.heartBeat.Start()
	} else { //stop
		//..............................
		s.heartBeat.Stop()
	}
}

func (s *netService) AdjustConnect(mb *bftview.Committee) {
	//
}

func (s *netService) procBlockDone(blockN, keyblockN uint64) {

	atomic.StoreUint64(&s.curBlockN, blockN)
	atomic.StoreUint64(&s.curKeyBlockN, keyblockN)

	//clear old cache of gossipMsg
	s.muGossip.Lock()
	for k, h := range s.gossipMsg {
		if (h.blockN > 0 && h.blockN < blockN) || (h.keyblockN > 0 && h.keyblockN < keyblockN) {
			delete(s.gossipMsg, k)
		}
	}
	s.muGossip.Unlock()
}

func (s *netService) handleNetworkMsgAck(env *network.Envelope) {
	msg, ok := env.Msg.(*networkMsg)
	if !ok {
		log.Error("handleNetworkMsgReq failed to cast to ")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	log.Info("handleNetworkMsgReq Recv", "from address", address, "msg number", msg.Number, "curBlockN", atomic.LoadUint64(&s.curBlockN), "keyblockN", atomic.LoadUint64(&s.curKeyBlockN))

	if msg.Cmsg != nil {
		if msg.Number < atomic.LoadUint64(&s.curKeyBlockN) {
			return
		}
	} else {
		if msg.Number < atomic.LoadUint64(&s.curBlockN) {
			return
		}
	}

	if (msg.MsgFlag & Gossip_MSG) > 0 {
		s.muGossip.Lock()
		_, ok := s.gossipMsg[msg.Hash]
		s.muGossip.Unlock()
		if !ok {
			s.broadcast(msg)
		} else {
			return
		}
	}
	s.backend.networkMsgAck(si, msg)
}

func (s *netService) broadcast(msg *networkMsg) {
	n := bftview.GetServerCommitteeLen()
	msg.MsgFlag = Gossip_MSG
	seedIndexs := math.GetRandIntArray(n, (n*4/10)+1)
	mb := bftview.GetCurrentMember()
	if mb == nil {
		log.Error("broadcast", "error", "can't find current committee")
		return
	}
	mblist := mb.List
	for i, _ := range seedIndexs {
		if mblist[i].IsSelf() {
			continue
		}
		s.SendRawData(mblist[i].Address, msg)
	}
}

func (s *netService) SendRawData(address string, msg *networkMsg) error {
	//	log.Info("SendRawData", "to address", address)
	if address == s.serverAddress {
		return nil
	}
	if msg.Hash == common.Empty_Hash {
		if msg.Hmsg != nil {
			msg.Number = atomic.LoadUint64(&s.curBlockN) + 1
		} else if msg.Cmsg != nil {
			msg.Number = msg.Cmsg.KeyNumber
		} else if msg.Bmsg != nil {
			msg.Number = msg.Bmsg.KeyNumber
		} else {
			log.Warn("SendRawData msg=nil", "to address", address)
		}
		msg.Hash = rlpHash([]interface{}{msg.Number, msg.Hmsg, msg.Cmsg, msg.Bmsg})
		/*
			s.muGossip.Lock()
			if msg.Cmsg != nil {
				s.gossipMsg[msg.Hash] = msgHeadInfo{keyblockN: msg.Number}
			} else {
				s.gossipMsg[msg.Hash] = msgHeadInfo{blockN: msg.Number}
			}
			s.muGossip.Unlock()
		*/
	}

	s.setIsRunning(address, true)
	q, _ := s.idDataMap[address]
	q.PushBack(msg)
	//	log.Info("SendRawData", "to address", address, "msg", msg)
	return nil
}

func (s *netService) loop_iddata(address string, q *common.Queue) {
	log.Debug("loop_iddata start", "address", address)
	si := network.NewServerIdentity(address)
	isRunning, _ := s.goMap[address]
	for atomic.LoadInt32(isRunning) == 1 {
		msg := q.PopFront()
		if msg != nil {
			m := msg.(*networkMsg)
			curN := atomic.LoadUint64(&s.curBlockN)
			log.Info("loop_iddata", "m.Number", m.Number, "curN", curN)
			if m.Number < curN {
				continue
			}

			err := s.SendRaw(si, msg, false)
			if err != nil {
				log.Warn("SendRawData", "couldn't send to", address, "error", err)
			}
		}
		time.Sleep(10)
	}
	atomic.StoreInt32(isRunning, 0)

	log.Debug("loop_iddata exit", "id", address)
}

//------------------------------------------------------------------------------------------
func (s *netService) isRunning(id string) int32 {
	isRunning, ok := s.goMap[id]
	if ok {
		return atomic.LoadInt32(isRunning)
	}
	return 0
}

func (s *netService) setIsRunning(id string, isStart bool) {
	isRunning, ok := s.goMap[id]
	if !ok {
		isRunning = new(int32)
		s.goMap[id] = isRunning
	}
	i := atomic.LoadInt32(isRunning)
	if isStart {
		atomic.StoreInt32(isRunning, 1)
		if i == 0 {
			q, ok := s.idDataMap[id]
			if !ok {
				q = common.QueueNew()
				s.idDataMap[id] = q
			}
			go s.loop_iddata(id, q)
		}
	} else {
		if i == 1 {
			atomic.StoreInt32(isRunning, 2)
		}
	}
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
