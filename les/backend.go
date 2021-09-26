// Copyright 2015 The go-ethereum Authors
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

// Package les implements the Light Cypherium Subprotocol.
package les

import (
	"fmt"
	"sync"
	"time"

	"github.com/cypherium/cypherBFT/accounts"
	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/hexutil"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/bloombits"
	"github.com/cypherium/cypherBFT/core/rawdb"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/eth"
	"github.com/cypherium/cypherBFT/eth/downloader"
	"github.com/cypherium/cypherBFT/eth/filters"
	"github.com/cypherium/cypherBFT/eth/gasprice"
	"github.com/cypherium/cypherBFT/ethdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/internal/ethapi"
	"github.com/cypherium/cypherBFT/light"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/node"
	"github.com/cypherium/cypherBFT/p2p"
	"github.com/cypherium/cypherBFT/p2p/discv5"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/pow"
	rpc "github.com/cypherium/cypherBFT/rpc"
)

type LightCphereum struct {
	config *eth.Config

	odr         *LesOdr
	relay       *LesTxRelay
	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	shutdownChan chan bool
	// Handlers
	peers           *peerSet
	txPool          *light.TxPool
	blockchain      *light.LightChain
	protocolManager *ProtocolManager
	serverPool      *serverPool
	reqDist         *requestDistributor
	retriever       *retrieveManager
	// DB interfaces
	chainDb ethdb.Database // Block chain database

	bloomRequests                              chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer, chtIndexer, bloomTrieIndexer *core.ChainIndexer

	ApiBackend *LesApiBackend

	eventMux       *event.TypeMux
	engine         pow.Engine
	accountManager *accounts.Manager

	networkId     uint64
	netRPCService *ethapi.PublicNetAPI

	wg sync.WaitGroup
}

func New(ctx *node.ServiceContext, config *eth.Config) (*LightCphereum, error) {
	chainDb, err := eth.CreateDB(ctx, config, "lightchaindata")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisKeyBlock(chainDb, config.GenesisKey)
	if _, isCompat := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !isCompat {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	peers := newPeerSet()
	quitSync := make(chan struct{})

	leth := &LightCphereum{
		config:           config,
		chainConfig:      chainConfig,
		chainDb:          chainDb,
		eventMux:         ctx.EventMux,
		peers:            peers,
		reqDist:          newRequestDistributor(peers, quitSync),
		accountManager:   ctx.AccountManager,
		shutdownChan:     make(chan bool),
		networkId:        config.NetworkId,
		bloomRequests:    make(chan chan *bloombits.Retrieval),
		bloomIndexer:     eth.NewBloomIndexer(chainDb, light.BloomTrieFrequency),
		chtIndexer:       light.NewChtIndexer(chainDb, true),
		bloomTrieIndexer: light.NewBloomTrieIndexer(chainDb, true),
	}

	leth.relay = NewLesTxRelay(peers, leth.reqDist)
	leth.serverPool = newServerPool(chainDb, quitSync, &leth.wg)
	leth.retriever = newRetrieveManager(peers, leth.reqDist, leth.serverPool)
	leth.odr = NewLesOdr(chainDb, leth.chtIndexer, leth.bloomTrieIndexer, leth.bloomIndexer, leth.retriever)
	if leth.blockchain, err = light.NewLightChain(leth.odr, leth.chainConfig, leth.engine); err != nil {
		return nil, err
	}
	leth.bloomIndexer.Start(leth.blockchain)
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		leth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}

	leth.txPool = light.NewTxPool(leth.chainConfig, leth.blockchain, leth.relay)
	if leth.protocolManager, err = NewProtocolManager(leth.chainConfig, true, ClientProtocolVersions, config.NetworkId, leth.eventMux, leth.engine, leth.peers, leth.blockchain, nil, chainDb, leth.odr, leth.relay, leth.serverPool, quitSync, &leth.wg); err != nil {
		return nil, err
	}
	leth.ApiBackend = &LesApiBackend{leth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	leth.ApiBackend.gpo = gasprice.NewOracle(leth.ApiBackend, gpoParams)
	return leth, nil
}

func lesTopic(genesisHash common.Hash, protocolVersion uint) discv5.Topic {
	var name string
	switch protocolVersion {
	case lpv1:
		name = "LES"
	case lpv2:
		name = "LES2"
	default:
		panic(nil)
	}
	return discv5.Topic(name + "@" + common.Bytes2Hex(genesisHash.Bytes()[0:8]))
}

type LightDummyAPI struct{}

// Coinbase is the address that mining rewards will be send to
func (s *LightDummyAPI) Coinbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Hashrate returns the POW hashrate
func (s *LightDummyAPI) Hashrate() hexutil.Uint {
	return 0
}

// Mining returns an indication if this node is currently mining.
func (s *LightDummyAPI) Mining() bool {
	return false
}

// APIs returns the collection of RPC services the cypherium package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *LightCphereum) APIs() []rpc.API {
	return append(ethapi.GetAPIs(s.ApiBackend), []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &LightDummyAPI{},
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, true),
			Public:    true,
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *LightCphereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *LightCphereum) BlockChain() *light.LightChain      { return s.blockchain }
func (s *LightCphereum) TxPool() *light.TxPool              { return s.txPool }
func (s *LightCphereum) Engine() pow.Engine                 { return s.engine }
func (s *LightCphereum) LesVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *LightCphereum) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *LightCphereum) EventMux() *event.TypeMux           { return s.eventMux }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *LightCphereum) Protocols() []p2p.Protocol {
	return s.protocolManager.SubProtocols
}

// Start implements node.Service, starting all internal goroutines needed by the
// Cypherium protocol implementation.
func (s *LightCphereum) Start(srvr *p2p.Server) error {
	s.startBloomHandlers()
	log.Warn("Light client mode is an experimental feature")
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.networkId)
	// clients are searching for the first advertised protocol in the list
	protocolVersion := AdvertiseProtocolVersions[0]
	s.serverPool.start(srvr, lesTopic(s.blockchain.Genesis().Hash(), protocolVersion))
	s.protocolManager.Start(s.config.LightPeers)
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Cypherium protocol.
func (s *LightCphereum) Stop() error {
	s.odr.Stop()
	if s.bloomIndexer != nil {
		s.bloomIndexer.Close()
	}
	if s.chtIndexer != nil {
		s.chtIndexer.Close()
	}
	if s.bloomTrieIndexer != nil {
		s.bloomTrieIndexer.Close()
	}
	s.blockchain.Stop()
	s.protocolManager.Stop()
	s.txPool.Stop()

	s.eventMux.Stop()

	time.Sleep(time.Millisecond * 200)
	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
