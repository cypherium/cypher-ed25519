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

package cph

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/cph/downloader"
	"github.com/cypherium/cypherBFT/cph/fetcher"
	"github.com/cypherium/cypherBFT/cphdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/p2p"
	"github.com/cypherium/cypherBFT/p2p/discover"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/pow"
	"github.com/cypherium/cypherBFT/reconfig"
	"github.com/cypherium/cypherBFT/rlp"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
)

var (
	daoChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	networkID uint64

	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool        txPool
	blockchain    *core.BlockChain
	keyBlockChain *core.KeyBlockChain
	reconfig      *reconfig.Reconfig
	chainconfig   *params.ChainConfig
	maxPeers      int

	downloader *downloader.Downloader
	fetcher    *fetcher.Fetcher
	peers      *peerSet

	SubProtocols []p2p.Protocol

	eventMux       *event.TypeMux
	txsCh          chan core.NewTxsEvent
	txsSub         event.Subscription
	newKeyBlockSub *event.TypeMuxSubscription
	epochPriKeySub *event.TypeMuxSubscription
	candidatePool  *core.CandidatePool
	candidateCh    chan *types.Candidate
	candidateSub   event.Subscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
	//??minedBlockSub  *event.TypeMuxSubscription
	newBlocks   []*types.Block
	muNewBlocks sync.Mutex
}

// NewProtocolManager returns a new Cypherium sub protocol manager. The Cypherium sub protocol manages peers capable
// with the Cypherium network.
func NewProtocolManager(config *params.ChainConfig, mode downloader.SyncMode, networkID uint64, mux *event.TypeMux, txpool txPool, engine pow.Engine, blockchain *core.BlockChain, keyBlockChain *core.KeyBlockChain, reconfg *reconfig.Reconfig, chaindb cphdb.Database, candidatePool *core.CandidatePool) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkID:     networkID,
		eventMux:      mux,
		txpool:        txpool,
		candidatePool: candidatePool,
		blockchain:    blockchain,
		keyBlockChain: keyBlockChain,
		reconfig:      reconfg,
		chainconfig:   config,
		peers:         newPeerSet(),
		newPeerCh:     make(chan *peer),
		noMorePeers:   make(chan struct{}),
		txsyncCh:      make(chan *txsync),
		quitSync:      make(chan struct{}),
	}
	// Figure out whether to allow fast sync or not
	if mode == downloader.FastSync && blockchain.CurrentBlockN() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.fastSync = uint32(1)
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		if mode == downloader.FastSync && version < cph63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}

				log.Trace("Try to get info of unknown peer")
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(mode, chaindb, manager.eventMux, blockchain, nil, keyBlockChain, manager.removePeer)

	validator := func(block *types.Block) error {
		if nil == keyBlockChain.GetBlockByHash(block.GetKeyHash()) {
			keyBlockChain.AddFutureTxBlock(block)
			return types.ErrFutureBlock
		}

		err := blockchain.Validator.VerifyHeader(block.Header())
		if err != nil {
			log.Info("handler.VerifyHeader", "err", err)
			return err
		}
		err = blockchain.Validator.VerifySignature(block)
		if err != nil {
			return err
		}
		return nil
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlockN()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		// If fast sync is running, deny importing weird blocks
		//if atomic.LoadUint32(&manager.fastSync) == 1 {
		//	log.Warn("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
		//	return 0, nil
		//}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import
		for _, block := range blocks {
			if nil == keyBlockChain.GetBlockByHash(block.GetKeyHash()) {
				keyBlockChain.AddFutureTxBlock(block)
			} else {
				fail, err := manager.blockchain.InsertChain([]*types.Block{block})
				if err != nil {
					return fail, err
				}
			}
		}

		return 0, nil
	}

	keyHeighter := func() uint64 {
		return keyBlockChain.CurrentBlockN()
	}

	keyBlockInserter := func(blocks types.KeyBlocks) (int, error) {
		return manager.keyBlockChain.InsertChain(blocks)
	}

	keyBlockValidator := func(block *types.KeyBlock) error {
		// todo....
		return nil
	}

	manager.fetcher = fetcher.New(blockchain.GetBlockByHash, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer, keyHeighter, keyBlockInserter, keyBlockChain.GetBlockByHash, keyBlockValidator, manager.BroadcastKeyBlock)

	return manager, nil
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	log.Trace("Removing Cypherium peer", "peer", id)

	// Unregister the peer from the downloader and Cypherium peer set
	pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		log.Error("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers

	// broadcast transactions
	pm.txsCh = make(chan core.NewTxsEvent, txChanSize)
	pm.txsSub = pm.txpool.SubscribeNewTxsEvent(pm.txsCh)
	go pm.txBroadcastLoop()

	// broadcast mined blocks
	//??pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	go pm.minedBroadcastLoop()

	pm.newKeyBlockSub = pm.eventMux.Subscribe(core.KeyChainHeadEvent{})
	go pm.newKeyBlockBroadcastLoop()

	// start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()

	pm.candidateCh = make(chan *types.Candidate, 1)
	pm.candidateSub = pm.candidatePool.SubscribeNewCandidatePoolEvent(pm.candidateCh)
	go pm.candidateBroadcastLoop()

}

func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Cypherium protocol")

	pm.txsSub.Unsubscribe() // quits txBroadcastLoop
	//??pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop
	pm.newKeyBlockSub.Unsubscribe()

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	log.Info("Cypherium protocol stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of an cph peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	// Ignore maxPeers if this is a trusted peer
	if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		return p2p.DiscTooManyPeers
	}
	p.Log().Trace("Cypherium peer connected", "name", p.Name())

	// Execute the Cypherium handshake
	var (
		genesis     = pm.keyBlockChain.Genesis()
		keyHead     = pm.keyBlockChain.CurrentHeader()
		keyHeadHash = keyHead.Hash()
		keyHeight   = keyHead.Number
		txHead      = pm.blockchain.CurrentHeader()
		txHeight    = txHead.Number
		txHeadHash  = txHead.Hash()
	)
	if err := p.Handshake(pm.networkID, keyHeight, keyHeadHash, genesis.Hash(), txHeight, txHeadHash); err != nil {
		p.Log().Trace("Cypherium handshake failed", "err", err)
		return err
	}
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		p.Log().Error("Cypherium peer registration failed", "err", err)
		return err
	}
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p); err != nil {
		return err
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.chainconfig.DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
			p.Log().Debug("Timed out DAO fork-check, dropping")
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			p.Log().Trace("Cypherium message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
	if err != nil {
		p.Log().Trace("Read message failed", "err", err)
		return err
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

	// Block header query, collect the requested headers and reply
	case msg.Code == GetBlockHeadersMsg:
		// Decode the complex header query
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		hashMode := query.Origin.Hash != (common.Hash{})
		first := true
		maxNonCanonical := uint64(100)

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			unknown bool
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				if first {
					first = false
					origin = pm.blockchain.GetHeaderByHash(query.Origin.Hash)
					if origin != nil {
						query.Origin.Number = origin.Number.Uint64()
					}
				} else {
					origin = pm.blockchain.GetHeader(query.Origin.Hash, query.Origin.Number)
				}
			} else {
				origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}
			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case hashMode && query.Reverse:
				// Hash based traversal towards the genesis block
				ancestor := query.Skip + 1
				if ancestor == 0 {
					unknown = true
				} else {
					query.Origin.Hash, query.Origin.Number = pm.blockchain.GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
					unknown = (query.Origin.Hash == common.Hash{})
				}
			case hashMode && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
					p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
					unknown = true
				} else {
					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
						nextHash := header.Hash()
						expOldHash, _ := pm.blockchain.GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
						if expOldHash == query.Origin.Hash {
							query.Origin.Hash, query.Origin.Number = nextHash, next
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= query.Skip + 1
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		return p.SendBlockHeaders(headers)

	case msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers []*types.Header
		if err := msg.Decode(&headers); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// If no headers were received, but we're expending a DAO fork check, maybe it's that
		if len(headers) == 0 && p.forkDrop != nil {
			// Possibly an empty reply to the fork header checks, sanity check TDs
			verifyDAO := true

			// If we already have a DAO header, we can check the peer's TD against it. If
			// the peer's ahead of this, it too must have a reply to the DAO check
			if daoHeader := pm.blockchain.GetHeaderByNumber(pm.chainconfig.DAOForkBlock.Uint64()); daoHeader != nil {
				if _, _, _, td := p.Head(); td.Cmp(pm.blockchain.GetTd(daoHeader.Hash(), daoHeader.Number.Uint64())) >= 0 {
					verifyDAO = false
				}
			}
			// If we're seemingly on the same chain, disable the drop timer
			if verifyDAO {
				p.Log().Debug("Seems to be on the same side of the DAO fork")
				p.forkDrop.Stop()
				p.forkDrop = nil
				return nil
			}
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader
		filter := len(headers) == 1
		if filter {
			// Irrelevant of the fork checks, send the header to the fetcher just in case
			headers = pm.fetcher.FilterHeaders(p.id, headers, time.Now())
		}
		if len(headers) > 0 || !filter {
			err := pm.downloader.DeliverHeaders(p.id, headers)
			if err != nil {
				log.Debug("Failed to deliver headers", "err", err)
			}
		}

	case msg.Code == GetBlockBodiesMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block body, stopping if enough was found
			if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
				bodies = append(bodies, data)
				bytes += len(data)
			}
		}
		return p.SendBlockBodiesRLP(bodies)

	case msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		var request blockBodiesData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver them all to the downloader for queuing
		transactions := make([][]*types.Transaction, len(request))

		for i, body := range request {
			transactions[i] = body.Transactions
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(transactions) > 0
		if filter {
			transactions = pm.fetcher.FilterBodies(p.id, transactions, time.Now())
		}
		if len(transactions) > 0 || !filter {
			err := pm.downloader.DeliverBodies(p.id, transactions)
			if err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}

	case msg.Code == KeyBlocksMsg:
		// A batch of key blocks arrived to one of our previous requests
		var blocks []*types.KeyBlock
		if err := msg.Decode(&blocks); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(blocks) > 0
		if filter {
			blocks = pm.fetcher.FilterKeyBlock(p.id, blocks, time.Now())
		}

		err := pm.downloader.DeliverKeyBlocks(p.id, blocks)
		if err != nil {
			log.Debug("Failed to deliver key blocks", "err", err)
		}

	case msg.Code == GetKeyBlocksMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}

		log.Trace("Receive GetKeyBlocksMsg")

		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			blocks []rlp.RawValue
		)
		for bytes < softResponseLimit && len(blocks) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}

			log.Trace("Get key block", "hash", hash.Hex())

			// Retrieve the requested key block , stopping if enough was found
			if data := pm.keyBlockChain.GetBlockRLPByHash(hash); len(data) != 0 {
				blocks = append(blocks, data)
				bytes += len(data)
			}
		}

		log.Trace("Response to GetKeyBlocksMsg", "len", len(blocks))

		return p.SendKeyBlockRLP(blocks)

	case msg.Code == GetContinuousKeyBlocksMsg:
		// Decode the complex header query
		var query getKeyBlocksData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		first := true

		// Gather key blocks until the fetch or network limits is reached
		var (
			blocks []rlp.RawValue
			data   rlp.RawValue
			next   uint64
			bytes  int
		)
		for len(blocks) < int(query.Amount) && bytes < softResponseLimit && len(blocks) < downloader.MaxHeaderFetch {
			// Retrieve the next key block satisfying the query
			if first {
				first = false

				block := pm.keyBlockChain.GetBlockByNumber(query.Origin)
				if block == nil {
					log.Trace("Failed to query key block", "number", query.Origin)
					break
				}
				data = pm.keyBlockChain.EncodeBlockToBytes(block.Hash(), block)
				if len(data) == 0 {
					log.Trace("Failed to encode key block to bytes", "hash", block.Hash(), "number", query.Origin)
					break
				}

				next = block.NumberU64() + 1
			} else {
				log.Trace("Get key Block RLP ", "number", next)
				data = pm.keyBlockChain.GetBlockRLPByNumber(next)
				next = next + 1
			}

			if data == nil {
				break
			}

			blocks = append(blocks, data)
			bytes += len(data)
		}

		log.Trace("Respond to continuous key block request", "number", query.Origin, "response", len(blocks))
		return p.SendKeyBlockRLP(blocks)

	case p.version >= cph63 && msg.Code == GetNodeDataMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash  common.Hash
			bytes int
			data  [][]byte
		)
		for bytes < softResponseLimit && len(data) < downloader.MaxStateFetch {
			// Retrieve the hash of the next state entry
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested state entry, stopping if enough was found
			if entry, err := pm.blockchain.TrieNode(hash); err == nil {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		return p.SendNodeData(data)

	case p.version >= cph63 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data [][]byte
		if err := msg.Decode(&data); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverNodeData(p.id, data); err != nil {
			log.Debug("Failed to deliver node state data", "err", err)
		}

	case p.version >= cph63 && msg.Code == GetReceiptsMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash     common.Hash
			bytes    int
			receipts []rlp.RawValue
		)
		for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := pm.blockchain.GetReceiptsByHash(hash)
			if results == nil {
				if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				log.Error("Failed to encode receipt", "err", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		return p.SendReceiptsRLP(receipts)

	case p.version >= cph63 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts [][]*types.Receipt
		if err := msg.Decode(&receipts); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
			log.Debug("Failed to deliver receipts", "err", err)
		}

	case msg.Code == NewBlockHashesMsg:
		var announces newBlockHashesData
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Mark the hashes as present at the remote node
		for _, block := range announces {
			p.MarkBlock(block.Hash)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make(newBlockHashesData, 0, len(announces))
		for _, block := range announces {
			if !pm.blockchain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}
		for _, block := range unknown {
			pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBodies)
		}
	case msg.Code == NewKeyBlockHashesMsg:
		var announces newBlockHashesData
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		// Mark the hashes as present at the remote node
		for _, block := range announces {
			p.MarkKeyBlock(block.Hash)
		}

		// Schedule all the unknown hashes for retrieval
		unknown := make(newBlockHashesData, 0, len(announces))
		for _, block := range announces {
			if !pm.keyBlockChain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}

		for _, block := range unknown {
			pm.fetcher.NotifyKeyBlock(p.id, block.Hash, block.Number, time.Now(), p.RequestKeyBlock)
		}

	case msg.Code == NewKeyBlockMsg:
		// Retrieve and decode the propagated key block
		var request newKeyBlockData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		request.Block.ReceivedAt = msg.ReceivedAt
		request.Block.ReceivedFrom = p

		// Mark the peer as owning the block and schedule it for import
		p.MarkBlock(request.Block.Hash())
		pm.fetcher.EnqueueKeyBlock(p.id, request.Block)

		// Assuming the key block is importable by the peer, but possibly not yet done so,
		// calculate the key head hash and height that the peer truly must have.
		var (
			trueKeyHead   = request.Block.ParentHash()
			trueKeyHeight = request.Block.Number()
		)
		// Update the peers height if better than the previous
		if _, keyHeight, _, _ := p.Head(); trueKeyHeight.Cmp(keyHeight) > 0 {
			p.SetKeyHead(trueKeyHead, trueKeyHeight)

			// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
			// a singe block , however this scenario should easily be covered by the fetcher.
			currentKeyBlock := pm.keyBlockChain.CurrentBlock()
			if trueKeyHeight.Cmp(currentKeyBlock.Number()) > 1 {
				go pm.synchronise(p)
			}
		}

	case msg.Code == NewBlockMsg:
		// Retrieve and decode the propagated block
		var request newBlockData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		request.Block.ReceivedAt = msg.ReceivedAt
		request.Block.ReceivedFrom = p

		// Mark the peer as owning the block and schedule it for import
		p.MarkBlock(request.Block.Hash())

		// Assuming the block is importable by the peer, but possibly not yet done so,
		// calculate the head hash and height that the peer truly must have.
		var (
			trueHead   = request.Block.ParentHash()
			trueHeight = request.Block.Number()
		)

		// Update the peers height if better than the previous
		if _, _, _, txHeight := p.Head(); trueHeight.Cmp(txHeight) > 0 {
			p.SetHead(trueHead, trueHeight)
		}

		if !pm.blockchain.HasBlock(request.Block.Hash(), request.Block.NumberU64()) {
			pm.fetcher.Enqueue(p.id, request.Block)

			// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
			// a singe block , however this scenario should easily be covered by the fetcher.
			currentBlock := pm.blockchain.CurrentBlock()
			if trueHeight.Uint64()-currentBlock.NumberU64() > 1 {
				go pm.synchronise(p)
			}
		}

	case msg.Code == TxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		// if atomic.LoadUint32(&pm.acceptTxs) == 0 {
		// 	break
		// }
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			p.MarkTransaction(tx.Hash())
		}
		pm.txpool.AddRemotes(txs)

	case msg.Code == CandidateMsg:
		var candidate types.Candidate
		if err := msg.Decode(&candidate); err != nil {
			log.Trace("fail to decode candidate message")
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if !pm.candidatePool.FoundCandidate(candidate.KeyCandidate.Number, candidate.PubKey) {
			log.Debug("CandidateMsg", "new candidate coinbase", candidate.Coinbase)
			p.MarkCandidate(candidate.Hash())
			pm.eventMux.Post(core.RemoteCandidateEvent{Candidate: &candidate})
		}
	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)
	sig, _ := block.GetSignature()
	if len(sig) < 32 {
		panic("BroadcastBlock sig is null")
	}
	// If propagation is requested, send to a subset of the peer
	if propagate {

		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			peer.AsyncSendNewBlock(block)
		}
		log.Trace("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if pm.blockchain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			peer.AsyncSendNewBlockHash(block)
		}
		//log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

// BroadcastKeyBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastKeyBlock(block *types.KeyBlock, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			peer.AsyncSendNewKeyBlock(block)
		}
		log.Info("Propagated key block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)), "type", block.BlockType())
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if pm.keyBlockChain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			peer.AsyncSendNewKeyBlockHash(block)
		}
		//??log.Info("Announced key block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

// BroadcastTxs will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTxs(txs types.Transactions) {
	var txset = make(map[*peer]types.Transactions)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		peers := pm.peers.PeersWithoutTx(tx.Hash())
		for _, peer := range peers {
			txset[peer] = append(txset[peer], tx)
		}
		//log.Trace("Broadcast transaction", "hash", tx.Hash(), "recipients", len(peers))
	}
	// FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for peer, txs := range txset {
		peer.AsyncSendTransactions(txs)
	}
}

func (pm *ProtocolManager) getNewMinedBlock() *types.Block {
	pm.muNewBlocks.Lock()
	defer pm.muNewBlocks.Unlock()
	if len(pm.newBlocks) > 0 {
		block := pm.newBlocks[0]
		pm.newBlocks = pm.newBlocks[1:]
		return block
	}
	return nil
}
func (pm *ProtocolManager) AddNewMinedBlock(block *types.Block) {
	pm.muNewBlocks.Lock()
	defer pm.muNewBlocks.Unlock()
	pm.newBlocks = append(pm.newBlocks, block)
}

// Mined broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {
	for {
		block := pm.getNewMinedBlock()
		if block != nil {
			pm.BroadcastBlock(block, true)  // First propagate block to peers
			pm.BroadcastBlock(block, false) // Only then announce to the rest
		}
		time.Sleep(20 * time.Millisecond)
	}
	/*
		// automatically stops if unsubscribe
		for obj := range pm.minedBlockSub.Chan() {
			switch ev := obj.Data.(type) {
			case core.NewMinedBlockEvent:
				pm.BroadcastBlock(ev.Block, true)  // First propagate block to peers
				pm.BroadcastBlock(ev.Block, false) // Only then announce to the rest
			}
		}
	*/
}

func (pm *ProtocolManager) txBroadcastLoop() {
	for {
		select {
		case event := <-pm.txsCh:
			pm.BroadcastTxs(event.Txs)

		// Err() channel will be closed when unsubscribing.
		case <-pm.txsSub.Err():
			log.Info("txBroadcastLoop stopped")
			return
		}
	}
}

// Mined broadcast loop
func (pm *ProtocolManager) newKeyBlockBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range pm.newKeyBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.KeyChainHeadEvent:
			//log.Info("Got Key Chain Head event")
			pm.candidatePool.ClearObsolete(ev.KeyBlock.Number())
			pm.BroadcastKeyBlock(ev.KeyBlock, true)  // First propagate block to peers
			pm.BroadcastKeyBlock(ev.KeyBlock, false) // Only then announce to the rest
		}
	}
}

func (pm *ProtocolManager) BroadcastCandidate(candidate *types.Candidate) {
	// Broadcast pow candidate to a batch of peers not knowing about it
	peers := pm.peers.PeersWithoutCandidate(candidate.Hash())
	for _, peer := range peers {
		peer.AsyncSendCandidate(candidate)
	}
	/*
		log.Info("Broadcast candidate",
			"peer count", len(peers),
			"peer all", pm.peers.Len(),
			"candidate.number", candidate.KeyCandidate.Number.Uint64(),
			"candidate.hash", candidate.Hash(), "candidate.ip", candidate.IP)
	*/
}

func (pm *ProtocolManager) candidateBroadcastLoop() {
	log.Info("Start broadcast pow loop")

	for {
		select {
		case candidate := <-pm.candidateCh:

			pm.BroadcastCandidate(candidate)

			// Err() channel will be closed when unsubscribing.
		case <-pm.candidateSub.Err():
			return
		}
	}
}

// NodeInfo represents a short summary of the Cypherium sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network         uint64              `json:"network"`         // Cypherium network ID (1=Frontier, 2=Morden, Ropsten=3, Rinkeby=4)
	KeyBlockTd      *big.Int            `json:"keyBlockTd"`      // Total difficulty of the host's key blockchain
	KeyBlockGenesis common.Hash         `json:"keyBlockGenesis"` // SHA3 hash of the host's genesis key block
	Config          *params.ChainConfig `json:"config"`          // Chain configuration for the fork rules
	KeyBlockHead    common.Hash         `json:"keyBlockHead"`    // SHA3 hash of the host's best owned key block
	TxBlockHead     common.Hash         `json:"txBlockHead"`     // SHA3 hash of the host's best owned tx block
	TxBlockHeight   *big.Int            `json:"txBlockHeight"`   // Height of tx block chain
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (pm *ProtocolManager) NodeInfo() *NodeInfo {
	var (
		genesis     = pm.keyBlockChain.Genesis()
		keyHead     = pm.keyBlockChain.CurrentHeader()
		keyHeadHash = keyHead.Hash()
		keyNumber   = keyHead.Number.Uint64()
		keyTd       = pm.keyBlockChain.GetTd(keyHeadHash, keyNumber)
		txHead      = pm.blockchain.CurrentHeader()
		txHeight    = txHead.Number
		txHeadHash  = txHead.Hash()
	)

	return &NodeInfo{
		Network:         pm.networkID,
		KeyBlockTd:      keyTd,
		KeyBlockGenesis: genesis.Hash(),
		Config:          pm.blockchain.Config(),
		KeyBlockHead:    keyHeadHash,
		TxBlockHead:     txHeadHash,
		TxBlockHeight:   txHeight,
	}
}
