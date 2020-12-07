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
	"github.com/cypherium/cypherBFT/params"
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

type heartBeatMsg struct {
	blockN uint64
}
type ackInfo struct {
	tm        time.Time
	isSending *int32 //atomic int
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
	gossipMsg              map[common.Hash]*msgHeadInfo
	muGossip               sync.Mutex

	goMap     map[string]*int32 //atomic int
	idDataMap map[string]*common.Queue
	ackMap    map[string]*ackInfo
	muIdMap   sync.Mutex

	backend      serviceCallback
	curBlockN    uint64
	curKeyBlockN uint64
	isStoping    bool
}

func newNetService(sName string, conf *Reconfig, callback serviceCallback) *netService {
	registerService := func(c *onet.Context) (onet.Service, error) {
		s := &netService{ServiceProcessor: onet.NewServiceProcessor(c)}
		s.RegisterProcessorFunc(network.RegisterMessage(&networkMsg{}), s.handleNetworkMsgAck)
		s.RegisterProcessorFunc(network.RegisterMessage(&heartBeatMsg{}), s.handleHeartBeatMsgAck)
		return s, nil
	}
	onet.RegisterNewService(sName, registerService)
	address := conf.cph.ExtIP().String() + ":" + conf.config.OnetPort
	server := onet.NewKcpServer(address)
	s := server.Service(sName).(*netService)
	s.server = server
	s.serverID = address
	s.serverAddress = address

	s.gossipMsg = make(map[common.Hash]*msgHeadInfo)
	s.goMap = make(map[string]*int32)
	s.idDataMap = make(map[string]*common.Queue)
	s.ackMap = make(map[string]*ackInfo)
	s.backend = callback

	return s
}

func (s *netService) StartStop(isStart bool) {
	if isStart {
		s.server.Start()
		go s.heartBeat_Loop()
	} else { //stop
		s.isStoping = true
		//..............................
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
	log.Info("handleNetworkMsgReq Recv", "from address", address)
	if s.IgnoreMsg(msg) {
		return
	}

	if (msg.MsgFlag & Gossip_MSG) > 0 {
		hash := rlpHash(msg)
		s.muGossip.Lock()
		m, ok := s.gossipMsg[hash]
		s.muGossip.Unlock()
		if !ok {
			s.broadcast(msg)
		} else {
			log.Info("Gossip_MSG Recv Same", "hash", hash, "keyblockN", m.keyblockN, "blockN", m.blockN)
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

	hash := rlpHash(msg)
	hInfo := s.getMsgHeadInfo(msg)
	log.Info("Gossip_MSG broadcast", "hash", hash, "keyblockN", hInfo.keyblockN, "blockN", hInfo.blockN)

	s.muGossip.Lock()
	s.gossipMsg[hash] = hInfo
	s.muGossip.Unlock()

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

	s.setIsRunning(address, true)
	s.muIdMap.Lock()
	q, _ := s.idDataMap[address]
	s.muIdMap.Unlock()
	q.PushBack(msg)
	//	log.Info("SendRawData", "to address", address, "msg", msg)
	return nil
}

func (s *netService) loop_iddata(address string, q *common.Queue) {
	log.Debug("loop_iddata start", "address", address)
	si := network.NewServerIdentity(address)
	s.muIdMap.Lock()
	isRunning, _ := s.goMap[address]
	s.muIdMap.Unlock()
	for atomic.LoadInt32(isRunning) == 1 {
		if s.GetNetBlocks(si) > 1 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		msg := q.PopFront()
		if msg != nil {
			m, ok := msg.(*networkMsg)
			if ok && s.IgnoreMsg(m) {
				continue
			}
			err := s.SendRaw(si, msg, false)
			if err != nil {
				//if err == SendOverFlowErr {}
				log.Warn("SendRawData", "couldn't send to", address, "error", err)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	atomic.StoreInt32(isRunning, 0)

	log.Debug("loop_iddata exit", "id", address)
}

func (s *netService) getMsgHeadInfo(msg *networkMsg) *msgHeadInfo {
	hInfo := new(msgHeadInfo)
	if msg.Cmsg != nil {
		hInfo.keyblockN = msg.Cmsg.KeyNumber
		hInfo.blockN = 0
	} else if msg.Bmsg != nil {
		hInfo.keyblockN = msg.Bmsg.KeyNumber
		hInfo.blockN = 0
	} else if msg.Hmsg != nil {
		hInfo.keyblockN = 0
		hInfo.blockN = msg.Hmsg.Number
	}
	return hInfo
}

func (s *netService) IgnoreMsg(m *networkMsg) bool {
	if m.Cmsg != nil {
		if m.Cmsg.KeyNumber < atomic.LoadUint64(&s.curKeyBlockN) {
			return true
		}
	} else if m.Bmsg != nil {
		if m.Bmsg.KeyNumber < atomic.LoadUint64(&s.curKeyBlockN) {
			return true
		}
	} else if m.Hmsg != nil {
		if m.Hmsg.Number < atomic.LoadUint64(&s.curBlockN) {
			return true
		}
	}
	return false
}

//------------------------------------------------------------------------------------------
func (s *netService) isRunning(id string) int32 {
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	s.muIdMap.Unlock()
	if ok {
		return atomic.LoadInt32(isRunning)
	}
	return 0
}

func (s *netService) setIsRunning(id string, isStart bool) {
	s.muIdMap.Lock()
	isRunning, ok := s.goMap[id]
	if !ok {
		isRunning = new(int32)
		s.goMap[id] = isRunning
	}
	s.muIdMap.Unlock()
	i := atomic.LoadInt32(isRunning)
	if isStart {
		atomic.StoreInt32(isRunning, 1)
		if i == 0 {
			s.muIdMap.Lock()
			q, ok := s.idDataMap[id]
			if !ok {
				q = common.QueueNew()
				s.idDataMap[id] = q
			}
			s.muIdMap.Unlock()
			go s.loop_iddata(id, q)
		}
	} else {
		if i == 1 {
			atomic.StoreInt32(isRunning, 2)
		}
	}
}

//-------------------------------------------------------------------------------------------------------------------------------------------
func (s *netService) handleHeartBeatMsgAck(env *network.Envelope) {
	msg, ok := env.Msg.(*heartBeatMsg)
	if !ok {
		log.Error("handleNetworkMsgReq failed to cast to ")
		return
	}
	si := env.ServerIdentity
	address := si.Address.String()
	log.Info("handleHeartBeatMsgAck Recv", "from address", address, "blockN", msg.blockN)
	a := s.getAckInfo(address)
	a.tm = time.Now()
}

func (s *netService) getAckInfo(addr string) *ackInfo {
	s.muIdMap.Lock()
	a := s.ackMap[addr]
	if a == nil {
		a = new(ackInfo)
		a.isSending = new(int32)
		s.ackMap[addr] = a
	}
	s.muIdMap.Unlock()
	return a
}

func (s *netService) heartBeat_Loop() {
	heatBeatTimeout := params.HeatBeatTimeout
	for !s.isStoping {
		mb := bftview.GetCurrentMember()
		if mb == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		now := time.Now()
		msg := &heartBeatMsg{blockN: atomic.LoadUint64(&s.curBlockN)}
		for _, node := range mb.List {
			if node.IsSelf() {
				continue
			}
			addr := node.Address
			a := s.getAckInfo(addr)
			if a != nil && now.Sub(a.tm) > heatBeatTimeout {
				if atomic.LoadInt32(a.isSending) == 0 {
					si := network.NewServerIdentity(addr)
					if s.GetNetBlocks(si) == 0 {
						go func(si *network.ServerIdentity, msg interface{}, isRunning *int32) {
							atomic.StoreInt32(isRunning, 1)
							err := s.SendRaw(si, msg, false)
							log.Debug("sendHeartBeatMsg", "address", si.Address, "tm", time.Now(), "error", err)
							atomic.StoreInt32(isRunning, 0)
						}(si, msg, a.isSending)
					}
				}
				continue
			}
			time.Sleep(200 * time.Millisecond)
		}
	} //end for  !s.isStoping
}

//--------------------------------------------------------------------------------------------------------------------------
func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
