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

// Package eth implements the Cypherium protocol.
package eth

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypherBFT/accounts"
	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/hexutil"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/bloombits"
	"github.com/cypherium/cypherBFT/core/rawdb"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/core/vm"
	"github.com/cypherium/cypherBFT/eth/downloader"
	"github.com/cypherium/cypherBFT/eth/filters"
	"github.com/cypherium/cypherBFT/eth/gasprice"
	"github.com/cypherium/cypherBFT/ethdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/internal/ethapi"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/miner"
	"github.com/cypherium/cypherBFT/node"
	"github.com/cypherium/cypherBFT/p2p"
	"golang.org/x/crypto/ed25519"

	//"github.com/cypherium/cypherBFT/p2p/nat"
	"github.com/cypherium/cypherBFT/p2p/nat"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/pow"
	"github.com/cypherium/cypherBFT/pow/ethash"
	"github.com/cypherium/cypherBFT/reconfig"
	"github.com/cypherium/cypherBFT/rlp"
	"github.com/cypherium/cypherBFT/rpc"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
}

// Cypherium implements the Cypherium full node service.
type Cypherium struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan chan bool // Channel for shutting down the Cypherium

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	keyBlockChain   *core.KeyBlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	candidatePool *core.CandidatePool

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         pow.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *EthAPIBackend

	miner    *miner.Miner
	reconfig *reconfig.Reconfig
	gasPrice *big.Int

	networkID     uint64
	netRPCService *ethapi.PublicNetAPI

	extIP net.IP

	scope   event.SubscriptionScope
	tpsFeed event.Feed
}

func (s *Cypherium) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// New creates a new Cypherium object (including the
// initialisation of the common Cypherium object)
func New(ctx *node.Node, config *Config) (*Cypherium, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Cypherium in light sync mode, use les.LightCphereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisKeyBlock(chainDb, config.GenesisKey)
	chainConfig.RnetPort = config.RnetPort
	//??	chainConfig.EnabledTPS = config.TxPool.EnableTPS
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}

	_, _, genesisErr = core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config id", chainConfig.ChainID)
	var extIP net.IP
	extIP = net.ParseIP(config.ExternalIp).To4()
	if extIP == nil {
		extIP = net.ParseIP(config.LocalTestConfig.LocalTestIP).To4()
		if extIP == nil {
			extIP = net.ParseIP(nat.GetExternalIp())
		} else {
			extIP = net.ParseIP(config.LocalTestConfig.LocalTestIP)
		}
	}

	log.Info("extIP address", "IP", extIP.String())
	eth := &Cypherium{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux(),
		accountManager: ctx.AccountManager(),
		engine:         CreateConsensusEngine(ctx, &config.Ethash, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		networkID:      config.NetworkId,
		gasPrice:       config.GasPrice,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks),
		extIP:          extIP,
	}

	log.Info("Initialising Cypherium protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	if !config.SkipBcVersionCheck {
		bcVersion := rawdb.ReadDatabaseVersion(chainDb)
		if *bcVersion != core.BlockChainVersion && *bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run cypher upgradedb.\n", *bcVersion, core.BlockChainVersion)
		}
		rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
	}
	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
		}
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanJournal:    ctx.ResolvePath(config.TrieCleanCacheJournal),
			TrieCleanRejournal:  config.TrieCleanCacheRejournal,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
			SnapshotLimit:       config.SnapshotCache,
		}
	)
	/*
		var (
			vmConfig = vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
			//cacheConfig = &core.CacheConfig{Disabled: config.NoPruning, TrieNodeLimit: config.TrieCache, TrieTimeLimit: config.TrieTimeout}
			cacheConfig = &core.CacheConfig{Disabled: true, TrieNodeLimit: config.TrieCache, TrieTimeLimit: config.TrieTimeout}
		)
	*/
	eth.keyBlockChain, err = core.NewKeyBlockChain(eth, chainDb, cacheConfig, eth.chainConfig, eth.engine, eth.EventMux())
	if err != nil {
		return nil, err
	}
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, eth.chainConfig, vmConfig, nil, &config.TxLookupLimit, eth.keyBlockChain)
	if err != nil {
		return nil, err
	}
	eth.candidatePool = core.NewCandidatePool(eth, eth.EventMux(), chainDb)

	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	config.TxPool.PriceLimit = config.GasPrice.Uint64()
	eth.txPool = core.NewTxPool(config.TxPool, eth.chainConfig, eth.blockchain)
	eth.blockchain.TxPool = eth.txPool
	eth.reconfig = reconfig.NewReconfig(chainDb, eth, eth.chainConfig, eth.EventMux(), eth.engine, extIP)

	eth.miner = miner.New(eth, eth.chainConfig, eth.EventMux(), eth.engine, extIP)
	if eth.protocolManager, err = NewProtocolManager(eth.chainConfig, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, eth.keyBlockChain, eth.reconfig, chainDb, eth.candidatePool); err != nil {
		return nil, err
	}
	eth.candidatePool.CheckMinerPort = eth.reconfig.CheckMinerPort
	eth.blockchain.AddNewMinedBlock = eth.protocolManager.AddNewMinedBlock
	// eth.miner.SetExtra(makeExtraData(config.ExtraData))
	eth.APIBackend = &EthAPIBackend{ctx.Config().ExtRPCEnabled(), eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)

	//go eth.LatestTPSMeter()

	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"cypher",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.Node, config *Config, name string) (ethdb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles, "eth/db/chaindata/")
	if err != nil {
		return nil, err
	}
	//if db, ok := db.(*ethdb.LDBDatabase); ok {
	//	db.Meter("eth/db/chaindata/")
	//}
	return db, nil
}

// CreateConsensusEngine creates the required type of pow engine instance for an Cypherium service
func CreateConsensusEngine(ctx *node.Node, config *ethash.Config, chainConfig *params.ChainConfig, db ethdb.Database) pow.Engine {
	// If proof-of-authority is requested, set it up
	//if chainConfig.Clique != nil {
	//	return clique.New(chainConfig.Clique, db)
	//}
	// Otherwise assume proof-of-work
	log.Info("pow engine ", "mode", config.PowMode)
	switch config.PowMode {
	case ethash.ModeFake:
		log.Warn("Ethash used in fake mode")
		return ethash.NewFaker()
	case ethash.ModeTest:
		log.Warn("Ethash used in test mode")
		return ethash.NewTester()
	case ethash.ModeShared:
		log.Warn("Ethash used in shared mode")
		return ethash.NewShared()
	default:
		engine := ethash.New(ethash.Config{
			CacheDir:       ctx.ResolvePath(config.CacheDir),
			CachesInMem:    config.CachesInMem,
			CachesOnDisk:   config.CachesOnDisk,
			DatasetDir:     config.DatasetDir,
			DatasetsInMem:  config.DatasetsInMem,
			DatasetsOnDisk: config.DatasetsOnDisk,
		})
		engine.SetThreads(-1) // Disable CPU mining
		return engine
	}
}

// APIs return the collection of RPC services the cypherium package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Cypherium) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the pow engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		},
		//{
		//	Namespace: "eth",
		//	Version:   "1.0",
		//	Service:   NewPublicMinerAPI(s),
		//	Public:    true,
		//},
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "reconfig",
			Version:   "1.0",
			Service:   NewPrivateReconfigAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Cypherium) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Cypherium) Coinbase() (eb common.Address, err error) {
	if s.miner.Mining() {
		return s.miner.GetCoinbase(), nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			coinbase := accounts[0].Address

			log.Info("Coinbase automatically configured", "address", coinbase)
			return coinbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("Coinbase must be explicitly specified")
}

func (s *Cypherium) StartMining(local bool, eb common.Address, pubKey ed25519.PublicKey) error {

	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so none will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)
	}
	go s.miner.Start(pubKey, eb)
	return nil
}

func (s *Cypherium) StopMining() {
	s.miner.Stop()
}

func (s *Cypherium) IsMining() bool                        { return s.miner.Mining() }
func (s *Cypherium) reconfigIsRunning() bool               { return s.reconfig.ReconfigIsRunning() }
func (s *Cypherium) Exceptions(blockNumber int64) []string { return s.reconfig.Exceptions(blockNumber) }
func (s *Cypherium) TakePartInNumberList(address common.Address, backCheckNumber rpc.BlockNumber) []string {
	return s.reconfig.TakePartInNumberList(address, int64(backCheckNumber))
}

func (s *Cypherium) Miner() *miner.Miner                { return s.miner }
func (s *Cypherium) Reconfig() *reconfig.Reconfig       { return s.reconfig }
func (s *Cypherium) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Cypherium) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Cypherium) KeyBlockChain() *core.KeyBlockChain { return s.keyBlockChain }
func (s *Cypherium) TxPool() *core.TxPool               { return s.txPool }
func (s *Cypherium) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Cypherium) Engine() pow.Engine                 { return s.engine }
func (s *Cypherium) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Cypherium) IsListening() bool                  { return true } // Always listening
func (s *Cypherium) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *Cypherium) NetVersion() uint64                 { return s.networkID }
func (s *Cypherium) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *Cypherium) CandidatePool() *core.CandidatePool { return s.candidatePool }
func (s *Cypherium) ExtIP() net.IP                      { return s.extIP }
func (s *Cypherium) PublicKey() ed25519.PublicKey {
	return s.miner.GetPubKey()
}

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *Cypherium) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}

func (s *Cypherium) LatestTPSMeter() {
	oldTxHeight := s.BlockChain().CurrentBlockN()
	for {
		time.Sleep(time.Second)

		select {
		case <-s.shutdownChan:
			return
		default:
		}

		currentTxHeight := s.BlockChain().CurrentBlockN()
		//log.Info("TPS Meter", "old", oldTxHeight, "current", currentTxHeight)
		txN := 0
		for old := oldTxHeight + 1; old <= currentTxHeight; old += 1 {
			txN += len(s.BlockChain().GetBlockByNumber(old).Transactions())
		}

		s.tpsFeed.Send(uint64(txN))

		oldTxHeight = currentTxHeight
	}
}

func (s *Cypherium) SubscribeLatestTPSEvent(ch chan<- uint64) event.Subscription {
	return s.scope.Track(s.tpsFeed.Subscribe(ch))
}

// Start implements node.Service, starting all internal goroutines needed by the
// Cypherium protocol implementation.
func (s *Cypherium) Start(srvr *p2p.Server) error {
	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Cypherium protocol.
func (s *Cypherium) Stop() error {
	s.bloomIndexer.Close()
	s.scope.Close()
	s.blockchain.Stop()
	s.keyBlockChain.Stop()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.miner.Quit()
	s.reconfig.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
