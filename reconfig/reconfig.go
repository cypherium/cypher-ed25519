// Copyright 2017 The cypherBFT Authors
// This file is part of the cypherBFT library.
//
// The cypherBFT library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The cypherBFT library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the cypherBFT library. If not, see <http://www.gnu.org/licenses/>.

package reconfig

import (
	"net"
	"sync"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/cphdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/pow"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
)

// Reconfig reconfiguration.
type Reconfig struct {
	config  *params.ChainConfig
	engine  pow.Engine
	db      cphdb.Database // Low level persistent database to store final content in
	cph     Backend
	service *Service
	//	service *Service1

	mux *event.TypeMux
	mu  sync.Mutex

	//	reconfigSub *event.TypeMuxSubscription
	txsCh  chan core.NewTxsEvent
	txsSub event.Subscription
}

// Backend wraps all methods required for mining.
type Backend interface {
	BlockChain() *core.BlockChain
	KeyBlockChain() *core.KeyBlockChain
	CandidatePool() *core.CandidatePool
	Engine() pow.Engine
	ExtIP() net.IP
	TxPool() *core.TxPool
}

// Public interface of service class
type serviceI interface {
	updateCommittee(keyBlock *types.KeyBlock) bool
	updateCurrentView(fromKeyBlock bool)
	procBlockDone(txBlock *types.Block, keyblock *types.KeyBlock)
	GetCurrentView() *bftview.View
	getBestCandidate(refresh bool) *types.Candidate
	syncCommittee(mb *bftview.Committee, keyblock *types.KeyBlock)
	setNextLeader(reconfigType uint8)
	sendNewViewMsg(curN uint64)
	LeaderAckTime() time.Time
	ResetLeaderAckTime()
	SwitchOK() bool
}

//NewReconfig call by backend
func NewReconfig(db cphdb.Database, cph Backend, config *params.ChainConfig, mux *event.TypeMux, engine pow.Engine, extIP net.IP) *Reconfig {
	reconfig := &Reconfig{mux: mux, cph: cph, config: config, engine: engine, db: db}

	reconfig.service = newService("cypherBFTService", reconfig)
	bftview.SetCommitteeConfig(db, cph.KeyBlockChain(), reconfig.service)
	reconfig.service.pacetMakerTimer = newPaceMakerTimer(config, reconfig.service, cph)
	go reconfig.service.pacetMakerTimer.loopTimer()

	reconfig.txsCh = make(chan core.NewTxsEvent, 1024)
	reconfig.txsSub = cph.TxPool().SubscribeNewTxsEvent(reconfig.txsCh)
	go reconfig.txsEventLoop()

	return reconfig
}

// Monitoring new txs Event
func (reconf *Reconfig) txsEventLoop() {
	for {
		select {
		case <-reconf.txsCh:
			//log.Debug("core.NewTxsEvent")
			reconf.service.pacetMakerTimer.onNewTx()

		case <-reconf.txsSub.Err():
			log.Info("txsEventLoop stopped")
			return
		}
	}
}

//Start call by miner
func (reconf *Reconfig) Start(config *common.NodeConfig) {
	reconf.service.start(config)
	log.Info("reconfig start")
}

//Stop call by miner
func (reconf *Reconfig) Stop() {
	defer log.Info("reconfig stop")
	reconf.service.stop()
}

//ReconfigIsRunning call by backend
func (reconf *Reconfig) ReconfigIsRunning() bool {
	return reconf.service.isRunning(1)
}

func (reconf *Reconfig) Exceptions(blockNumber int64) []string {
	return reconf.service.Exceptions(blockNumber)
}

func (reconf *Reconfig) TakePartInNumberList(address common.Address, backCheckNumber int64) []string {
	return reconf.service.TakePartInNumberList(address, backCheckNumber)
}

func (reconf *Reconfig) CheckMinerPort(addr string, blockN uint64, keyblockN uint64) {
	reconf.service.netService.CheckMinerPort(addr, blockN, keyblockN, 111)
}
