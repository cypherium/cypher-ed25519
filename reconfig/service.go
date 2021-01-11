package reconfig

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/crypto/bls"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/onet/network"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
	"github.com/cypherium/cypherBFT/reconfig/hotstuff"
)

type committeeInfo struct {
	Committee *bftview.Committee
	KeyHash   common.Hash
	KeyNumber uint64
}
type bestCandidateInfo struct {
	Node      *common.Cnode
	KeyHash   common.Hash
	KeyNumber uint64
}
type cachedCommitteeInfo struct {
	keyHash   common.Hash
	keyNumber uint64
	committee *bftview.Committee
	node      *common.Cnode
}
type committeeMsg struct {
	sid   *network.ServerIdentity
	cinfo *committeeInfo
	best  *bestCandidateInfo
}
type hotstuffMsg struct {
	sid   *network.ServerIdentity
	lastN uint64
	hMsg  *hotstuff.HotstuffMessage
}

type networkMsg struct {
	MsgFlag uint32
	Hmsg    *hotstuff.HotstuffMessage
	Cmsg    *committeeInfo
	Bmsg    *bestCandidateInfo
}

func (msg *networkMsg) GetCommittee() *bftview.Committee {
	var mb *bftview.Committee
	if msg.Cmsg != nil {
		mb = bftview.LoadMember(msg.Cmsg.KeyNumber, msg.Cmsg.KeyHash, true)
	} else if msg.Bmsg != nil {
		mb = bftview.LoadMember(msg.Bmsg.KeyNumber, msg.Bmsg.KeyHash, true)
	} else if msg.Hmsg != nil {
		mb = bftview.GetCurrentMember()
	}
	return mb
}

//Service work for protcol
type Service struct {
	netService *netService
	bc         *core.BlockChain
	txService  *txService
	kbc        *core.KeyBlockChain
	keyService *keyService

	protocolMng *hotstuff.HotstuffProtocolManager

	lastCmInfoMap   map[common.Hash]*cachedCommitteeInfo
	muCommitteeInfo sync.Mutex
	currentView     bftview.View
	waittingView    bftview.View
	lastReqCmNumber uint64
	muCurrentView   sync.Mutex

	replicaView     *bftview.View
	runningState    int32
	lastProposeTime time.Time
	pacetMakerTimer *paceMakerTimer

	hotstuffMsgQ *common.Queue
	feed1        event.Feed
	msgCh1       chan committeeMsg
	msgSub1      event.Subscription // Subscription for msg event
}

func newService(sName string, conf *Reconfig) *Service {
	s := new(Service)
	s.netService = newNetService(sName, conf, s)

	s.txService = newTxService(s, conf.cph, conf.config)
	s.keyService = newKeyService(s, conf.cph, conf.config)

	s.bc = conf.cph.BlockChain()
	s.kbc = conf.cph.KeyBlockChain()
	s.lastCmInfoMap = make(map[common.Hash]*cachedCommitteeInfo)

	s.msgCh1 = make(chan committeeMsg, 10)
	s.msgSub1 = s.feed1.Subscribe(s.msgCh1)
	s.hotstuffMsgQ = common.QueueNew()

	s.protocolMng = hotstuff.NewHotstuffProtocolManager(s, nil, nil)

	go s.handleHotStuffMsg()
	go s.handleCommitteeMsg()
	return s
}

//OnNewView --------------------------------------------------------------------------
func (s *Service) OnNewView(data []byte, extraes [][]byte) error { //buf is snapshot, //verify repla' block before newview
	view := bftview.DecodeToView(data)
	log.Info("OnNewView..", "txNumber", view.TxNumber, "keyNumber", view.KeyNumber)

	s.muCurrentView.Lock()
	s.replicaView = view
	if view.EqualNoIndex(&s.currentView) {
		s.currentView.LeaderIndex = view.LeaderIndex
		s.currentView.ReconfigType = view.ReconfigType
	}
	s.muCurrentView.Unlock()

	var bestCandidates []*types.Candidate
	for _, extraD := range extraes {
		if extraD == nil {
			continue
		}
		cand := types.DecodeToCandidate(extraD)
		if cand == nil {
			continue
		}
		bestCandidates = append(bestCandidates, cand)
	}
	s.keyService.setBestCandidateAndBadAddress(bestCandidates, nil)

	return nil
}

//CurrentState call by hotstuff
func (s *Service) CurrentState() ([]byte, string, uint64) { //recv by onnewview
	curView := s.GetCurrentView()
	leaderID := ""
	mb := bftview.GetCurrentMember()
	if mb != nil {
		leader := mb.List[curView.LeaderIndex]
		//leader := mb.List[0]
		log.Info("CurrentState.NextLeader", "index", curView.LeaderIndex, "ip", leader.Address)
		leaderID = bftview.GetNodeID(leader.Address, leader.Public)
	} else {
		log.Error("CurrentState.NextLeader: can't get current committee!")
		s.Committee_Request(curView.KeyNumber, curView.KeyHash)
	}

	log.Info("CurrentState", "TxNumber", curView.TxNumber, "KeyNumber", curView.KeyNumber, "LeaderIndex", curView.LeaderIndex, "ReconfigType", curView.ReconfigType)

	return curView.EncodeToBytes(), leaderID, curView.TxNumber + 1
}

//GetExtra call by hotstuff
func (s *Service) GetExtra() []byte {
	best := s.keyService.getBestCandidate(true)
	if best == nil {
		return nil
	}
	return best.EncodeToBytes()
}

//GetPublicKey call by hotstuff
func (s *Service) GetPublicKey() []*bls.PublicKey {
	keyblock := s.kbc.CurrentBlock()
	keyNumber := keyblock.NumberU64()
	c := bftview.LoadMember(keyNumber, keyblock.Hash(), false)
	if c == nil {
		return nil
	}
	return c.ToBlsPublicKeys(keyblock.Hash())
}

//Self call by hotstuff
func (s *Service) Self() string {
	return s.netService.serverID
}

//CheckView call by hotstuff
func (s *Service) CheckView(data []byte) error {
	if !s.isRunning(0) {
		return types.ErrNotRunning
	}
	view := bftview.DecodeToView(data)
	knumber := s.kbc.CurrentBlockN()
	txnumber := s.bc.CurrentBlockN()
	log.Debug("CheckView..", "txNumber", view.TxNumber, "keyNumber", view.KeyNumber, "local key number", knumber, "tx number", txnumber)
	if view.KeyNumber < knumber {
		return hotstuff.ErrOldState
	} else if view.KeyNumber > knumber {
		return hotstuff.ErrFutureState
	}
	if view.TxNumber < txnumber {
		return hotstuff.ErrOldState
	} else if view.TxNumber > txnumber {
		return hotstuff.ErrFutureState
	}

	return nil
}

//OnPropose call by hotstuff
func (s *Service) OnPropose(isKeyBlock bool, state []byte, extra []byte) error { //verify new block
	log.Debug("OnPropose..")
	if !s.isRunning(0) {
		return types.ErrNotRunning
	}

	if isKeyBlock {
		var kblock *types.KeyBlock
		if kState != nil {
			kblock = types.DecodeToKeyBlock(kState)
			log.Info("OnPropose", "keyNumber", kblock.NumberU64())
		}
		if kblock != nil {
			err := s.keyService.verifyKeyBlock(kblock, types.DecodeToCandidate(extra), nil)
			if err != nil {
				log.Error("verify keyblock", "number", kblock.NumberU64(), "err", err)
				return err
			}
		} else {
			err := fmt.Errorf("DecodeToKeyBlock(state) error")
			log.Error("Propose", "error", err)
			return err
		}
	} else {
		var block *types.Block
		if tState != nil {
			block = types.DecodeToBlock(tState)
			log.Info("OnPropose", "txNumber", block.NumberU64())
		}
		if block != nil {
			err := s.txService.verifyTxBlock(block)
			if err != nil {
				log.Error("verify txblock", "number", block.NumberU64(), "err", err)
				return err
			}
		} else {
			err := fmt.Errorf("DecodeToBlock(state) error")
			log.Error("Propose", "error", err)
			return err
		}
	}
	s.pacetMakerTimer.start()
	return nil
}

//Propose call by hotstuff
func (s *Service) Propose() (e error, kState []byte, tState []byte, extra []byte) { //buf recv by onpropose, onviewdown
	log.Debug("Propose..")

	proposeOK := false
	defer func() {
		if !proposeOK {
			go func() {
				time.Sleep(2 * time.Second)
				curView := s.GetCurrentView()
				if bftview.IamLeader(curView.LeaderIndex) {
					s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, lastN: s.bc.CurrentBlockN(), hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgTryPropose}})
				}
			}()
		} else {
			s.lastProposeTime = time.Now()
		}
	}()

	if !s.isRunning(0) {
		err := fmt.Errorf("not running for propose")
		return err, nil, nil, nil
	}

	s.muCurrentView.Lock()
	leaderIndex := s.currentView.LeaderIndex
	reconfigType := s.currentView.ReconfigType
	if !s.replicaView.EqualAll(&s.currentView) {
		log.Error("Propose", "replica view not equal to local current view txNumber", s.currentView.TxNumber, "keyNumber", s.currentView.KeyNumber, "LeaderIndex", leaderIndex, "ReconfigType",
			reconfigType, "replica txNumber", s.replicaView.TxNumber, "keyNumber", s.replicaView.KeyNumber, "LeaderIndex", s.replicaView.LeaderIndex, "ReconfigType", s.replicaView.ReconfigType)
		s.muCurrentView.Unlock()
		return fmt.Errorf("replica view not equal to local current view"), nil, nil, nil
	}
	if !bftview.IamLeader(leaderIndex) {
		//proposeOK = true
		err := fmt.Errorf("not leader for propose")
		log.Error("Propose", "error", err)
		s.muCurrentView.Unlock()
		return err, nil, nil, nil
	}
	s.muCurrentView.Unlock()

	if reconfigType > 0 {
		keyblock, mb, bestCandi, _, err := s.keyService.tryProposalChangeCommittee(reconfigType, leaderIndex)
		if err == nil && keyblock != nil && mb != nil {
			kbuf := keyblock.EncodeToBytes()
			if bestCandi != nil {
				extra = bestCandi.EncodeToBytes()
			}
			proposeOK = true
			return nil, kbuf, nil, extra
		} else {
			log.Error("tryProposalChangeCommittee failed", "error", err)
			return fmt.Errorf("tryProposalChangeCommittee failed"), nil, nil, nil
		}
	}
	data, err := s.txService.tryProposalNewBlock(types.IsTxBlockType)
	if err != nil {
		log.Error("tryProposalNewBlock", "error", err)
		return err, nil, nil, nil
	}
	proposeOK = true
	return nil, nil, data, nil
}

//OnViewDone call by hotstuff
func (s *Service) OnViewDone(kSign *hotstuff.SignedState, tSign *hotstuff.SignedState) error {
	if !s.isRunning(0) {
		return types.ErrNotRunning
	}
	if tSign != nil {
		block := types.DecodeToBlock(tSign.State)
		err := s.txService.decideNewBlock(block, tSign.Sign, tSign.Mask)
		if err != nil {
			return err
		}
	}
	if kSign != nil {
		block := types.DecodeToKeyBlock(kSign.State)
		err := s.keyService.decideNewKeyBlock(block, kSign.Sign, kSign.Mask)
		if err != nil {
			return err
		}
	}

	return nil
}

//Write call by hotstuff------------------------------------------------------------------------------------------------
func (s *Service) Write(id string, data *hotstuff.HotstuffMessage) error {
	log.Info("Write", "to id", id, "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)

	if id == s.Self() {
		s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, hMsg: data})
		return nil
	}

	mb := bftview.GetCurrentMember()
	if mb == nil {
		return fmt.Errorf("can't find current committee,id %s", id)
	}
	node, _ := mb.Get(id, bftview.ID)
	if node == nil || len(node.Address) < 7 { //1.1.1.1
		err := fmt.Errorf("can't find id %s in current committee", id)
		log.Error("Couldn't send", "err", err)
		return err
	}

	s.netService.SendRawData(node.Address, &networkMsg{Hmsg: data})
	return nil
}

//Broadcast call by hotstuff
func (s *Service) Broadcast(data *hotstuff.HotstuffMessage) []error {
	log.Debug("Broadcast", "code", hotstuff.ReadableMsgType(data.Code), "ViewId", data.ViewId)
	s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, hMsg: data})
	/*
		mb := bftview.GetCurrentMember()
		if mb == nil {
			return []error{fmt.Errorf("can't find current committee")}
		}
		for _, node := range mb.List {
			if node.IsSelf() {
				continue
			}
			s.netService.SendRawData(node.Address, &networkMsg{Hmsg: data})
		}
	*/
	s.netService.broadcast("", &networkMsg{Hmsg: data})
	return nil //return arr
}

func (s *Service) networkMsgAck(si *network.ServerIdentity, msg *networkMsg) {
	if msg.Hmsg != nil {
		s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: si, hMsg: msg.Hmsg})
		return
	}
	s.feed1.Send(committeeMsg{sid: si, cinfo: msg.Cmsg, best: msg.Bmsg})
}

func (s *Service) handleHotStuffMsg() {
	for {
		data := s.hotstuffMsgQ.PopFront()
		if data == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		msg := data.(*hotstuffMsg)
		msgCode := msg.hMsg.Code
		log.Debug("handleHotStuffMsg", "id", msg.hMsg.Id, "code", hotstuff.ReadableMsgType(msgCode), "ViewId", msg.hMsg.ViewId)

		var curN uint64
		if msgCode == hotstuff.MsgTryPropose || msgCode == hotstuff.MsgStartNewView {
			curN = s.bc.CurrentBlockN()
			if msg.lastN < curN {
				log.Debug("handleHotStuffMsg", "code", hotstuff.ReadableMsgType(msgCode), "lastN", msg.lastN, "curN", curN)
				continue
			}
		} else if msgCode == hotstuff.MsgPrepare && msg.sid != nil {
			curBlock := s.kbc.CurrentBlock()
			keyNumber := curBlock.NumberU64()
			keyHash := curBlock.Hash()
			msgAddress := msg.sid.Address.String()
			if bftview.LoadMember(keyNumber, keyHash, true) == nil && msgAddress != s.netService.serverAddress {
				log.Debug("request committee", "keynumber", keyNumber, "send to address", msgAddress)
				s.netService.SendRawData(msgAddress, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: keyHash, KeyNumber: keyNumber}})
			}
		}

		err := s.protocolMng.HandleMessage(msg.hMsg)
		if err != nil && msgCode == hotstuff.MsgStartNewView {
			go func(curN uint64) {
				time.Sleep(2 * time.Second)
				s.sendNewViewMsg(curN)
			}(curN)
		}
	}
}

//-------------------------------------------------------------------------------------------------------------------------
func (s *Service) syncCommittee(mb *bftview.Committee, keyblock *types.KeyBlock) {
	if !keyblock.HasNewNode() {
		return
	}

	in := mb.In()
	s.netService.SendRawData(in.Address, &networkMsg{Cmsg: &committeeInfo{Committee: mb, KeyHash: keyblock.Hash(), KeyNumber: keyblock.NumberU64()}})

	msg := &bestCandidateInfo{Node: in, KeyHash: keyblock.Hash(), KeyNumber: keyblock.NumberU64()}
	//s.netService.broadcast("", &networkMsg{Bmsg: msg})
	for i, r := range mb.List {
		if i == 0 || r.IsSelf() {
			continue
		}
		log.Debug("syncBestCandidate", "send to", r.Address)
		s.netService.SendRawData(r.Address, &networkMsg{Bmsg: msg})
	}
}

func (s *Service) storeCommitteeInCache(cmInfo *committeeInfo, best *bestCandidateInfo) {
	s.muCommitteeInfo.Lock()
	defer s.muCommitteeInfo.Unlock()
	var (
		keyHash   common.Hash
		keyNumber uint64
		committee *bftview.Committee
		node      *common.Cnode
	)
	if cmInfo != nil {
		keyHash = cmInfo.KeyHash
		keyNumber = cmInfo.KeyNumber
		committee = cmInfo.Committee
	} else if best != nil {
		keyHash = best.KeyHash
		keyNumber = best.KeyNumber
		node = best.Node
	}

	ac, ok := s.lastCmInfoMap[keyHash]
	if ok {
		if cmInfo != nil {
			ac.committee = cmInfo.Committee
		}
		if best != nil {
			ac.node = best.Node
		}
		return
	}
	//clear prev map
	maxNumber := s.kbc.CurrentBlockN()
	for hash, ac := range s.lastCmInfoMap {
		if ac.keyNumber < maxNumber-9 {
			delete(s.lastCmInfoMap, hash)
		}
	}
	log.Info("@@storeCommitteeInCache", "key number", keyNumber)

	s.lastCmInfoMap[keyHash] = &cachedCommitteeInfo{keyHash: keyHash, keyNumber: keyNumber, committee: committee, node: node}
}

// handle committee sync message
func (s *Service) handleCommitteeMsg() {
	for {
		select {
		case msg := <-s.msgCh1:
			if msg.best != nil {
				if bftview.LoadMember(msg.best.KeyNumber, msg.best.KeyHash, true) != nil {
					continue
				}
				log.Info("bestCandidate", "best KeyNumber", msg.best.KeyNumber)
				s.storeCommitteeInCache(nil, msg.best)
				continue
			}
			cInfo := msg.cinfo
			if cInfo == nil {
				continue
			}
			if cInfo.Committee == nil {
				mb := bftview.LoadMember(cInfo.KeyNumber, cInfo.KeyHash, true)
				if mb == nil {
					continue
				}
				msgAddress := msg.sid.Address.String()
				log.Debug("committeeInfo answer", "number", cInfo.KeyNumber, "adddress", msgAddress)
				r, _ := mb.Get(msgAddress, bftview.Address)
				if r != nil {
					log.Debug("committeeInfo answer..ok", "number", cInfo.KeyNumber)
					s.netService.SendRawData(msgAddress, &networkMsg{Cmsg: &committeeInfo{Committee: mb, KeyHash: cInfo.KeyHash, KeyNumber: cInfo.KeyNumber}})
				}
				continue
			}

			if bftview.LoadMember(cInfo.KeyNumber, cInfo.KeyHash, true) != nil {
				continue
			}
			log.Debug("committeeInfo", "number", cInfo.KeyNumber, "adddress", msg.sid.Address)
			keyblock := s.kbc.GetBlock(cInfo.KeyHash, cInfo.KeyNumber)
			if keyblock != nil {
				cInfo.Committee.Store(keyblock)
			} else {
				s.storeCommitteeInCache(cInfo, nil)
			}

		case <-s.msgSub1.Err():
			log.Error("handleHotStuffMsg Feed error")
			return
		}
	}
}

// Update committee by keyblock
func (s *Service) updateCommittee(keyBlock *types.KeyBlock) bool {
	bStore := false
	curKeyBlock := keyBlock
	if bftview.IamMember() < 0 {
		return false
	}
	if curKeyBlock == nil {
		curKeyBlock = s.kbc.CurrentBlock()
	}
	mb := bftview.LoadMember(curKeyBlock.NumberU64(), curKeyBlock.Hash(), true)
	if mb != nil {
		return bStore
	}

	s.muCommitteeInfo.Lock()
	ac, ok := s.lastCmInfoMap[curKeyBlock.Hash()]
	if ok {
		if ac.committee != nil {
			mb = ac.committee
		} else if ac.node != nil {
			mb, _ = bftview.GetCommittee(ac.node, curKeyBlock, true)
		}
	}
	s.muCommitteeInfo.Unlock()

	if mb == nil && !curKeyBlock.HasNewNode() {
		mb, _ = bftview.GetCommittee(nil, curKeyBlock, true)
	}

	if mb != nil {
		bStore = mb.Store(curKeyBlock)
	} else {
		log.Info("updateCommittee can't found committee", "txNumber", s.bc.CurrentBlockN(), "keyNumber", curKeyBlock.NumberU64())
	}
	return bStore
}

func (s *Service) Committee_OnStored(keyblock *types.KeyBlock, mb *bftview.Committee) {
	log.Debug("store committee", "keyNumber", keyblock.NumberU64(), "ip0", mb.List[0].Address, "ipn", mb.List[len(mb.List)-1].Address)
	if keyblock.HasNewNode() && keyblock.NumberU64() == s.kbc.CurrentBlockN() {
		s.netService.AdjustConnect(keyblock.OutAddress())
	}
}

// Request committee for keyblock
func (s *Service) Committee_Request(kNumber uint64, hash common.Hash) {
	if kNumber <= s.lastReqCmNumber || !bftview.IamMemberByNumber(kNumber, hash) {
		return
	}

	log.Debug("Committee_Request", "keynumber", kNumber)

	var parentMb *bftview.Committee
	for i := 1; i < 10; i++ {
		keyblock := s.kbc.GetBlockByNumber(kNumber - uint64(i))
		if keyblock == nil {
			return
		}
		mb := bftview.LoadMember(keyblock.NumberU64(), keyblock.Hash(), true)
		if mb != nil {
			parentMb = mb
			break
		}
	}
	if parentMb == nil {
		return
	}

	for _, node := range parentMb.List {
		if node.IsSelf() {
			continue
		}
		s.netService.SendRawData(node.Address, &networkMsg{Cmsg: &committeeInfo{Committee: nil, KeyHash: hash, KeyNumber: kNumber}})
	}
	s.lastReqCmNumber = kNumber
}

// Update current view data
func (s *Service) updateCurrentView(fromKeyBlock bool) { //call by keyblock done
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	curBlock := s.bc.CurrentBlock()
	curKeyBlock := s.kbc.CurrentBlock()

	s.currentView.TxNumber = curBlock.NumberU64()
	s.currentView.TxHash = curBlock.Hash()
	s.currentView.KeyNumber = curKeyBlock.NumberU64()
	s.currentView.KeyHash = curKeyBlock.Hash()
	s.currentView.CommitteeHash = curKeyBlock.CommitteeHash()

	if fromKeyBlock || curBlock.NumberU64() > curKeyBlock.T_Number() {
		s.currentView.LeaderIndex = 0
		s.currentView.ReconfigType = 0
	}
	log.Trace("updateCurrentView", "TxNumber", s.currentView.TxNumber, "KeyNumber", s.currentView.KeyNumber, "LeaderIndex", s.currentView.LeaderIndex, "ReconfigType", s.currentView.ReconfigType)
	if fromKeyBlock || (s.currentView.TxNumber >= s.waittingView.TxNumber && s.currentView.KeyNumber >= s.waittingView.KeyNumber) || curBlock.BlockType() == types.IsKeyBlockSkipType {
		s.sendNewViewMsg(s.currentView.TxNumber)
		s.waittingView.KeyNumber = s.currentView.KeyNumber
		s.waittingView.TxNumber = s.currentView.TxNumber
	}
}

func (s *Service) GetCurrentView() *bftview.View {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()
	v := &s.currentView
	return v
}

func (s *Service) getBestCandidate(refresh bool) *types.Candidate {
	return s.keyService.getBestCandidate(refresh)
}

// Send new view when new block done
func (s *Service) sendNewViewMsg(curN uint64) {
	if bftview.IamMember() >= 0 && curN >= s.bc.CurrentBlockN() {
		s.hotstuffMsgQ.PushBack(&hotstuffMsg{sid: nil, lastN: curN, hMsg: &hotstuff.HotstuffMessage{Code: hotstuff.MsgStartNewView}})
	}
}

// Set next leader by prescribed rules
func (s *Service) setNextLeader(reconfigType uint8) {
	s.muCurrentView.Lock()
	defer s.muCurrentView.Unlock()

	if reconfigType == types.PowReconfig {
		s.currentView.LeaderIndex = s.kbc.GetNextLeaderIndex(0, nil)
	} else {
		s.currentView.LeaderIndex = s.kbc.GetNextLeaderIndex(s.currentView.LeaderIndex, nil)
	}
	s.currentView.ReconfigType = reconfigType
	log.Info("setNextLeader", "type", reconfigType, "index", s.currentView.LeaderIndex)

	s.waittingView.TxNumber = s.currentView.TxNumber + 1
	s.waittingView.KeyNumber = s.currentView.KeyNumber + 1
}

func (s *Service) procBlockDone(txBlock *types.Block, keyblock *types.KeyBlock) {
	if keyblock == nil {
		keyblock = s.kbc.CurrentBlock()
	}
	s.pacetMakerTimer.procBlockDone(txBlock, keyblock)
	keyblockN := keyblock.NumberU64()
	var blockN uint64
	if txBlock == nil {
		blockN = s.bc.CurrentBlockN()
	} else {
		blockN = txBlock.NumberU64()
	}
	s.netService.procBlockDone(blockN, keyblockN)
}

// call by miner.start
func (s *Service) start(config *common.NodeConfig) {
	if !s.isRunning(0) {
		s.protocolMng.UpdateKeyPair(bftview.StrToBlsPrivKey(config.Private))
		bftview.SetServerInfo(s.netService.serverAddress, config.Public)
		s.netService.StartStop(true)
		if bftview.IamMember() >= 0 {
			s.updateCommittee(nil)
			s.pacetMakerTimer.start()
		}
		s.updateCurrentView(false)
		s.setRunState(1)
	}
}

func (s *Service) stop() {
	if s.isRunning(0) {
		s.netService.StartStop(false)
		s.pacetMakerTimer.stop()
		s.setRunState(0)
	}
}

func (s *Service) isRunning(flag int) bool {
	//log all status
	if flag == 1 {
		go s.printAllStatus()
	}
	return atomic.LoadInt32(&s.runningState) == 1
}

func (s *Service) printAllStatus() {
	s.netService.GetNetBlocks(nil)
	for addr, a := range s.netService.ackMap {
		si := network.NewServerIdentity(addr)
		log.Info("ackInfo", "addr", addr, "id", si.ID)
		if a != nil {
			log.Info("ackInfo", "ackTm", a.ackTm, "sendTm", a.sendTm, "isSending", *a.isSending)
		}
	}
}

func (s *Service) setRunState(state int32) {
	atomic.StoreInt32(&s.runningState, state)
}

func (s *Service) LeaderAckTime() time.Time {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		curView := s.GetCurrentView()
		leader := mb.List[curView.LeaderIndex]
		return s.netService.GetAckTime(leader.Address)
	}
	return time.Now()
}

func (s *Service) ResetLeaderAckTime() {
	mb := bftview.GetCurrentMember()
	if mb != nil {
		curView := s.GetCurrentView()
		leader := mb.List[curView.LeaderIndex]
		s.netService.ResetAckTime(leader.Address)
	}
}

/*
func (s *Service) MakeupData(data *hotstuff.StateSign) []byte {
	if data.Type == hotstuff.TxState {
		block := types.DecodeToBlock(data.State)
		block.SetSignature(data.Sign, data.Mask)
		return block.EncodeToBytes()
	} else if data.Type == hotstuff.KeyState {
		block := types.DecodeToKeyBlock(data.State)
		block.SetSignature(data.Sign, data.Mask)
		return block.EncodeToBytes()
	}
	return nil
}
*/
