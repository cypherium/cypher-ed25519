package miner

import (
	"sync/atomic"

	"golang.org/x/crypto/ed25519"

	"net"

	"github.com/cypherium/cypherBFT/accounts"
	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/ethdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/pow"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
)

// Backend wraps all methods required for mining.
type Backend interface {
	AccountManager() *accounts.Manager
	BlockChain() *core.BlockChain
	KeyBlockChain() *core.KeyBlockChain
	CandidatePool() *core.CandidatePool
	TxPool() *core.TxPool
	ChainDb() ethdb.Database
}

// Miner creates candidate from current head keyblock and searches for proof-of-work values.
type Miner struct {
	mux         *event.TypeMux
	worker      *worker
	pubKey      ed25519.PublicKey
	coinBase    common.Address
	eth         Backend
	engine      pow.Engine
	keyHeadSub  *event.TypeMuxSubscription
	fullSyncing int32 // can start indicates whether we can start the mining operation
	shouldStart int32 // should start indicates whether we should start after sync
	isMember    bool
}

func New(eth Backend, config *params.ChainConfig, mux *event.TypeMux, engine pow.Engine, extIP net.IP) *Miner {
	miner := &Miner{
		eth:         eth,
		mux:         mux,
		engine:      engine,
		worker:      newWorker(config, engine, eth, mux, eth.CandidatePool(), extIP),
		fullSyncing: 0,
		shouldStart: 0,
		isMember:    false,
	}
	miner.Register(NewCpuAgent(eth.BlockChain(), engine))
	go miner.update() //monitor self role change carefully，prevent role change something wrong
	return miner
}

// updateIdentityEvents keeps track of member identity change events
func (self *Miner) update() {
	events := self.mux.Subscribe(core.SelfRoleChangeEvent{}, core.KeyChainHeadEvent{})
	defer events.Unsubscribe()
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		case core.KeyChainHeadEvent:
			log.Info("Miner.update  core.KeyChainHeadEvent")
			self.worker.stop()
			self.MinerDoWork()

		}
	}
	log.Warn("Stop tracking key block head events")
}

func (self *Miner) Start(pubKey ed25519.PublicKey, eb common.Address) {

	self.SetPubKey(pubKey)
	self.SetCoinbase(eb)
	log.Info("Miner) Start", "coinBase", eb, "pubKey", pubKey)
	atomic.StoreInt32(&self.shouldStart, 1)

	log.Info("Ready to start pow work")
	self.worker.start()
}

func (self *Miner) SuspendMiner() {
	if self.Mining() {
		self.worker.stop() //now action
	}
}

func (self *Miner) MinerDoWork() {
	//log.Info("MinerDoWork")
	if bftview.IamMember() >= 0 {
		return
	}
	shouldStart := atomic.LoadInt32(&self.shouldStart) == 1

	if shouldStart {
		if !self.Mining() {
			log.Info("Restore,Ready to start pow work")
			self.worker.start() //now action
		}

	} else {
		if !shouldStart {
			log.Info("User has not permitted  to start")
		}
	}
}

func (self *Miner) Stop() {
	self.worker.stop()
	atomic.StoreInt32(&self.shouldStart, 0)
}

func (self *Miner) Quit() {
	self.worker.stop()
}

func (self *Miner) Register(agent Agent) {
	self.worker.register(agent)
}

func (self *Miner) Unregister(agent Agent) {
	self.worker.unregister(agent)
}

func (self *Miner) Mining() bool {
	return self.worker.isRunning()
}

func (self *Miner) HashRate() uint64 {
	if pow, ok := self.engine.(pow.PoW); ok {
		return uint64(pow.Hashrate())
	}
	return 0
}

func (self *Miner) GetPubKey() ed25519.PublicKey {
	return self.pubKey
}

func (self *Miner) SetPubKey(pubKey ed25519.PublicKey) {
	self.pubKey = pubKey
	self.worker.SetPubKey(pubKey)
}

func (self *Miner) SetCoinbase(eb common.Address) {
	self.coinBase = eb
	self.worker.SetCoinbase(eb)
}

func (self *Miner) GetCoinbase() common.Address {
	return self.coinBase
}
