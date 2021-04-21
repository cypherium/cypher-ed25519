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

// Package fetcher contains the block announcement based synchronisation.
package fetcher

import (
	"errors"
	"math/rand"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/log"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

const (
	arriveTimeout = 500 * time.Millisecond // Time allowance before an announced block is explicitly requested
	gatherSlack   = 100 * time.Millisecond // Interval used to collate almost-expired announces with fetches
	fetchTimeout  = 10 * time.Second       // Maximum allotted time to return an explicitly requested block
	maxQueueDist  = 32                     // Maximum allowed distance from the chain head to queue
	hashLimit     = 256                    // Maximum number of unique blocks a peer may have announced
	blockLimit    = 64                     // Maximum number of unique blocks a peer may have delivered
)

var (
	errTerminated = errors.New("terminated")
)

// blockRetrievalFn is a callback type for retrieving a block from the local chain.
type blockRetrievalFn func(common.Hash) *types.Block

// headerRequesterFn is a callback type for sending a header retrieval request.
type headerRequesterFn func(common.Hash) error

// bodyRequesterFn is a callback type for sending a body retrieval request.
type bodyRequesterFn func([]common.Hash) error

// headerVerifierFn is a callback type to verify a block's header for fast propagation.
type headerVerifierFn func(header *types.Block) error

// blockBroadcasterFn is a callback type for broadcasting a block to connected peers.
type blockBroadcasterFn func(block *types.Block, propagate bool)

// chainHeightFn is a callback type to retrieve the current chain height.
type chainHeightFn func() uint64

// chainInsertFn is a callback type to insert a batch of blocks into the local chain.
type chainInsertFn func(types.Blocks) (int, error)

// peerDropFn is a callback type for dropping a peer detected as malicious.
type peerDropFn func(id string)

// keyBlockRequestFn is a callback type for sending a key block retrieval request.
type keyBlockRequestFn func([]common.Hash) error

// keyChainHeightFn is a callback type to retrieve the current key chain height.
type keyChainHeightFn func() uint64

// keyChainInsertFn is a callback type to insert a batch of key blocks into the local chain.
type keyChainInsertFn func(types.KeyBlocks) (int, error)

// keyBlockBroadcasterFn is a callback type for broadcasting a block to connected peers.
type keyBlockBroadcasterFn func(block *types.KeyBlock, propagate bool)

// keyBlockRetrievalFn is a callback type for retrieving a key block from the local chain.
type keyBlockRetrievalFn func(common.Hash) *types.KeyBlock

// keyBlockVerifierFn is a callback type to verify a key block for fast propagation.
type keyBlockVerifierFn func(block *types.KeyBlock) error

// announce is the hash notification of the availability of a new block in the
// network.
type announce struct {
	isKeyBlock bool
	hash       common.Hash   // Hash of the block being announced
	number     uint64        // Number of the block being announced (0 = unknown | old protocol)
	header     *types.Header // Header of the block partially reassembled (new protocol)
	time       time.Time     // Timestamp of the announcement

	origin string // Identifier of the peer originating the notification

	fetchHeader     headerRequesterFn // Fetcher function to retrieve the header of an announced block
	fetchBodies     bodyRequesterFn   // Fetcher function to retrieve the body of an announced block
	keyBlockFetcher keyBlockRequestFn // Fetcher function to retrieve the body of an announced block
}

// headerFilterTask represents a batch of headers needing fetcher filtering.
type headerFilterTask struct {
	peer    string          // The source peer of block headers
	headers []*types.Header // Collection of headers to filter
	time    time.Time       // Arrival time of the headers
}

// bodyFilterTask represents a batch of block bodies (transactions and uncles)
// needing fetcher filtering.
type bodyFilterTask struct {
	peer         string                 // The source peer of block bodies
	transactions [][]*types.Transaction // Collection of transactions per block bodies
	time         time.Time              // Arrival time of the blocks' contents
}

// keyBlockFilterTask represents a batch of key blocks needing fetcher filtering.
type keyBlockFilterTask struct {
	peer   string            // The source peer of block headers
	blocks []*types.KeyBlock // Collection of key blocks to filter
	time   time.Time         // Arrival time of the headers
}

// inject represents a schedules import operation.
type inject struct {
	isKeyBlock bool
	origin     string
	block      *types.Block
	keyBlock   *types.KeyBlock
}

// Fetcher is responsible for accumulating block announcements from various peers
// and scheduling them for retrieval.
type Fetcher struct {
	// Various event channels
	notify chan *announce
	inject chan *inject

	blockFilter  chan chan []*types.Block
	headerFilter chan chan *headerFilterTask
	bodyFilter   chan chan *bodyFilterTask

	keyBlockFilter chan chan *keyBlockFilterTask

	done chan common.Hash
	quit chan struct{}

	// Announce states
	announces  map[string]int              // Per peer announce counts to prevent memory exhaustion
	announced  map[common.Hash][]*announce // Announced blocks, scheduled for fetching
	fetching   map[common.Hash]*announce   // Announced blocks, currently fetching
	fetched    map[common.Hash][]*announce // Blocks with headers fetched, scheduled for body retrieval
	completing map[common.Hash]*announce   // Blocks with headers, currently body-completing

	// Block cache
	queue  *prque.Prque            // Queue containing the import operations (block number sorted)
	queues map[string]int          // Per peer block counts to prevent memory exhaustion
	queued map[common.Hash]*inject // Set of already queued blocks (to dedupe imports)

	// Callbacks
	getBlock       blockRetrievalFn   // Retrieves a block from the local chain
	verifyHeader   headerVerifierFn   // Checks if a block's headers have a valid proof of work
	broadcastBlock blockBroadcasterFn // Broadcasts a block to connected peers
	chainHeight    chainHeightFn      // Retrieves the current chain's height
	insertChain    chainInsertFn      // Injects a batch of blocks into the chain
	dropPeer       peerDropFn         // Drops a peer for misbehaving

	verifyKeyBlock    keyBlockVerifierFn    // Checks if a key block have a valid proof of work
	getKeyBlock       keyBlockRetrievalFn   // Retrieves a key block from the local chain
	broadcastKeyBlock keyBlockBroadcasterFn // Broadcasts a key block to connected peers
	keyChainHeight    keyChainHeightFn      // Retrieves the current key chain's height
	insertKeyChain    keyChainInsertFn      // Injects a batch of key blocks into the key chain

	// Testing hooks
	announceChangeHook   func(common.Hash, bool) // Method to call upon adding or deleting a hash from the announce list
	queueChangeHook      func(common.Hash, bool) // Method to call upon adding or deleting a block from the import queue
	fetchingHook         func([]common.Hash)     // Method to call upon starting a block (cph/61) or header (cph/62) fetch
	completingHook       func([]common.Hash)     // Method to call upon starting a block body fetch (cph/62)
	importedHook         func(*types.Block)      // Method to call upon successful block import (both cph/61 and cph/62)
	importedKeyBlockHook func(*types.KeyBlock)   // Method to call upon successful key block import (both cph/61 and cph/62)
}

// New creates a block fetcher to retrieve blocks based on hash announcements.
func New(
	getBlock blockRetrievalFn, verifyHeader headerVerifierFn, broadcastBlock blockBroadcasterFn, chainHeight chainHeightFn,
	insertChain chainInsertFn, dropPeer peerDropFn, keyChainHeight keyChainHeightFn, insertKeyChain keyChainInsertFn,
	getKeyBlock keyBlockRetrievalFn, verifyKeyBlock keyBlockVerifierFn, broadcastKeyBlock keyBlockBroadcasterFn) *Fetcher {
	return &Fetcher{
		notify:            make(chan *announce),
		inject:            make(chan *inject),
		blockFilter:       make(chan chan []*types.Block),
		headerFilter:      make(chan chan *headerFilterTask),
		bodyFilter:        make(chan chan *bodyFilterTask),
		keyBlockFilter:    make(chan chan *keyBlockFilterTask),
		done:              make(chan common.Hash),
		quit:              make(chan struct{}),
		announces:         make(map[string]int),
		announced:         make(map[common.Hash][]*announce),
		fetching:          make(map[common.Hash]*announce),
		fetched:           make(map[common.Hash][]*announce),
		completing:        make(map[common.Hash]*announce),
		queue:             prque.New(),
		queues:            make(map[string]int),
		queued:            make(map[common.Hash]*inject),
		getBlock:          getBlock,
		verifyHeader:      verifyHeader,
		broadcastBlock:    broadcastBlock,
		chainHeight:       chainHeight,
		insertChain:       insertChain,
		dropPeer:          dropPeer,
		keyChainHeight:    keyChainHeight,
		insertKeyChain:    insertKeyChain,
		verifyKeyBlock:    verifyKeyBlock,
		getKeyBlock:       getKeyBlock,
		broadcastKeyBlock: broadcastKeyBlock,
	}
}

// Start boots up the announcement based synchroniser, accepting and processing
// hash notifications and block fetches until termination requested.
func (f *Fetcher) Start() {
	go f.loop()
}

// Stop terminates the announcement based synchroniser, canceling all pending
// operations.
func (f *Fetcher) Stop() {
	close(f.quit)
}

// Notify announces the fetcher of the potential availability of a new block in
// the network.
func (f *Fetcher) Notify(peer string, hash common.Hash, number uint64, time time.Time,
	headerFetcher headerRequesterFn, bodyFetcher bodyRequesterFn) error {
	block := &announce{
		isKeyBlock:  false,
		hash:        hash,
		number:      number,
		time:        time,
		origin:      peer,
		fetchHeader: headerFetcher,
		fetchBodies: bodyFetcher,
	}
	select {
	case f.notify <- block:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// NotifyKeyBlock announces the fetcher of the potential availability of a new block in
// the network.
func (f *Fetcher) NotifyKeyBlock(peer string, hash common.Hash, number uint64, time time.Time,
	keyBlockFetcher keyBlockRequestFn) error {
	block := &announce{
		isKeyBlock:      true,
		hash:            hash,
		number:          number,
		time:            time,
		origin:          peer,
		keyBlockFetcher: keyBlockFetcher,
	}
	select {
	case f.notify <- block:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// Enqueue tries to fill gaps the the fetcher's future import queue.
func (f *Fetcher) Enqueue(peer string, block *types.Block) error {
	op := &inject{
		origin: peer,
		block:  block,
	}
	select {
	case f.inject <- op:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// EnqueueKeyBlock tries to fill gaps the the fetcher's future import queue.
func (f *Fetcher) EnqueueKeyBlock(peer string, block *types.KeyBlock) error {
	op := &inject{
		isKeyBlock: true,
		origin:     peer,
		keyBlock:   block,
	}
	select {
	case f.inject <- op:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// FilterHeaders extracts all the headers that were explicitly requested by the fetcher,
// returning those that should be handled differently.
func (f *Fetcher) FilterHeaders(peer string, headers []*types.Header, time time.Time) []*types.Header {
	log.Trace("Filtering headers", "peer", peer, "headers", len(headers))

	// Send the filter channel to the fetcher
	filter := make(chan *headerFilterTask)

	select {
	case f.headerFilter <- filter:
	case <-f.quit:
		return nil
	}
	// Request the filtering of the header list
	select {
	case filter <- &headerFilterTask{peer: peer, headers: headers, time: time}:
	case <-f.quit:
		return nil
	}
	// Retrieve the headers remaining after filtering
	select {
	case task := <-filter:
		return task.headers
	case <-f.quit:
		return nil
	}
}

// FilterBodies extracts all the block bodies that were explicitly requested by
// the fetcher, returning those that should be handled differently.
func (f *Fetcher) FilterBodies(peer string, transactions [][]*types.Transaction, time time.Time) [][]*types.Transaction {
	log.Trace("Filtering bodies", "peer", peer, "txs", len(transactions))

	// Send the filter channel to the fetcher
	filter := make(chan *bodyFilterTask)

	select {
	case f.bodyFilter <- filter:
	case <-f.quit:
		return nil
	}
	// Request the filtering of the body list
	select {
	case filter <- &bodyFilterTask{peer: peer, transactions: transactions, time: time}:
	case <-f.quit:
		return nil
	}
	// Retrieve the bodies remaining after filtering
	select {
	case task := <-filter:
		return task.transactions
	case <-f.quit:
		return nil
	}
}

// FilterHeaders extracts all the headers that were explicitly requested by the fetcher,
// returning those that should be handled differently.
func (f *Fetcher) FilterKeyBlock(peer string, blocks []*types.KeyBlock, time time.Time) []*types.KeyBlock {
	log.Trace("Filtering key block", "peer", peer, "blocks", len(blocks))

	// Send the filter channel to the fetcher
	filter := make(chan *keyBlockFilterTask)

	select {
	case f.keyBlockFilter <- filter:
	case <-f.quit:
		return nil
	}
	// Request the filtering of the keyblock list
	select {
	case filter <- &keyBlockFilterTask{peer: peer, blocks: blocks, time: time}:
	case <-f.quit:
		return nil
	}
	// Retrieve the headers remaining after filtering
	select {
	case task := <-filter:
		return task.blocks
	case <-f.quit:
		return nil
	}
}

func (f *Fetcher) hasBlock(hash common.Hash, isKeyBlock bool) bool {
	if isKeyBlock {
		return f.getKeyBlock(hash) != nil
	} else {
		return f.getBlock(hash) != nil
	}
}

func (op *inject) Info() (common.Hash, uint64) {
	var (
		hash   common.Hash
		height uint64
	)

	if op.isKeyBlock {
		hash = op.keyBlock.Hash()
		height = op.keyBlock.NumberU64()
	} else {
		hash = op.block.Hash()
		height = op.block.NumberU64()
	}

	return hash, height
}

func (f *Fetcher) getChainHeight(keyChain bool) uint64 {
	if keyChain {
		return f.keyChainHeight()
	} else {
		return f.chainHeight()
	}
}

// Loop is the main fetcher loop, checking and processing various notification
// events.
func (f *Fetcher) loop() {
	// Iterate the block fetching until a quit is requested
	fetchTimer := time.NewTimer(0)
	completeTimer := time.NewTimer(0)

	for {
		// Clean up any expired block fetches
		for hash, announce := range f.fetching {
			if time.Since(announce.time) > fetchTimeout {
				f.forgetHash(hash)
			}
		}
		// Import any queued blocks that could potentially fit

		for !f.queue.Empty() {
			op := f.queue.PopItem().(*inject)

			height := f.getChainHeight(op.isKeyBlock)
			hash, number := op.Info()

			if f.queueChangeHook != nil {
				f.queueChangeHook(hash, false)
			}

			// If too high up the chain or phase, continue later
			if number > height+1 {
				f.queue.Push(op, -float32(number))
				if f.queueChangeHook != nil {
					f.queueChangeHook(hash, true)
				}
				break
			}
			// Otherwise if fresh and still unknown, try and import
			if number <= height || f.hasBlock(hash, op.isKeyBlock) {
				f.forgetBlock(hash)
				continue
			}

			if op.isKeyBlock {
				log.Trace("Insert enqueued key block", "hash", op.keyBlock.Hash().Hex())
				f.insertKeyBlock(op.origin, op.keyBlock)
			} else {
				log.Trace("Insert enqueued  block", "hash", op.block.Hash().Hex())
				f.insertBlock(op.origin, op.block)
			}

		}
		// Wait for an outside event to occur
		select {
		case <-f.quit:
			// Fetcher terminating, abort all operations
			return

		case notification := <-f.notify:
			// A block was announced, make sure the peer isn't DOSing us
			propAnnounceInMeter.Mark(1)

			count := f.announces[notification.origin] + 1
			if count > hashLimit {
				log.Debug("Peer exceeded outstanding announces", "peer", notification.origin, "limit", hashLimit)
				propAnnounceDOSMeter.Mark(1)
				break
			}

			chainHeight := f.getChainHeight(notification.isKeyBlock)
			// If we have a valid block number, check that it's potentially useful
			if notification.number > 0 {
				if dist := int64(notification.number) - int64(chainHeight); dist < 1 || dist > maxQueueDist {
					log.Debug("Peer discarded announcement", "peer", notification.origin, "number", notification.number, "hash", notification.hash, "distance", dist)
					propAnnounceDropMeter.Mark(1)
					break
				}
			}
			// All is well, schedule the announce if block's not yet downloading
			if _, ok := f.fetching[notification.hash]; ok {
				break
			}
			if _, ok := f.completing[notification.hash]; ok {
				break
			}
			f.announces[notification.origin] = count
			f.announced[notification.hash] = append(f.announced[notification.hash], notification)
			if f.announceChangeHook != nil && len(f.announced[notification.hash]) == 1 {
				f.announceChangeHook(notification.hash, true)
			}
			if len(f.announced) == 1 {
				f.rescheduleFetch(fetchTimer)
			}

		case op := <-f.inject:
			// A direct block insertion was requested, try and fill any pending gaps
			propBroadcastInMeter.Mark(1)
			if op.isKeyBlock {
				f.enqueueKeyBlock(op.origin, op.keyBlock)
			} else {
				f.enqueue(op.origin, op.block)
			}
		case hash := <-f.done:
			// A pending import finished, remove all traces of the notification
			f.forgetHash(hash)
			f.forgetBlock(hash)

		case <-fetchTimer.C:
			// At least one block's timer ran out, check for needing retrieval
			request := make(map[string][]common.Hash)

			for hash, announces := range f.announced {
				if time.Since(announces[0].time) > arriveTimeout-gatherSlack {
					// Pick a random peer to retrieve from, reset all others
					announce := announces[rand.Intn(len(announces))]
					f.forgetHash(hash)

					// If the block still didn't arrive, queue for fetching
					if !f.hasBlock(hash, announce.isKeyBlock) {
						request[announce.origin] = append(request[announce.origin], hash)
						f.fetching[hash] = announce
					}
				}
			}
			// Send out all block header and key block requests
			for peer, hashes := range request {
				announce := f.fetching[hashes[0]]

				if announce.isKeyBlock {
					log.Trace("Fetching key block", "peer", peer, "list", hashes)
					fetchKeyBlock := f.fetching[hashes[0]].keyBlockFetcher
					go func() {
						if f.fetchingHook != nil {
							f.fetchingHook(hashes)
						}
						fetchKeyBlock(hashes)
					}()
				} else {
					log.Trace("Fetching scheduled headers", "peer", peer, "list", hashes)
					// Create a closure of the fetch and schedule in on a new thread
					fetchHeader, hashes := f.fetching[hashes[0]].fetchHeader, hashes
					go func() {
						if f.fetchingHook != nil {
							f.fetchingHook(hashes)
						}
						for _, hash := range hashes {
							headerFetchMeter.Mark(1)
							fetchHeader(hash) // Suboptimal, but protocol doesn't allow batch header retrievals
						}
					}()
				}

			}
			// Schedule the next fetch if blocks are still pending
			f.rescheduleFetch(fetchTimer)

		case <-completeTimer.C:
			// At least one header's timer ran out, retrieve everything
			request := make(map[string][]common.Hash)

			for hash, announces := range f.fetched {
				// Pick a random peer to retrieve from, reset all others
				announce := announces[rand.Intn(len(announces))]
				f.forgetHash(hash)

				// If the block still didn't arrive, queue for completion
				if !f.hasBlock(hash, announce.isKeyBlock) {
					request[announce.origin] = append(request[announce.origin], hash)
					f.completing[hash] = announce
				}
			}
			// Send out all block body requests
			for peer, hashes := range request {
				log.Trace("Fetching scheduled bodies", "peer", peer, "list", hashes)

				// Create a closure of the fetch and schedule in on a new thread
				if f.completingHook != nil {
					f.completingHook(hashes)
				}
				bodyFetchMeter.Mark(int64(len(hashes)))
				go f.completing[hashes[0]].fetchBodies(hashes)
			}
			// Schedule the next fetch if blocks are still pending
			f.rescheduleComplete(completeTimer)

		case filter := <-f.headerFilter:
			// Headers arrived from a remote peer. Extract those that were explicitly
			// requested by the fetcher, and return everything else so it's delivered
			// to other parts of the system.
			var task *headerFilterTask
			select {
			case task = <-filter:
			case <-f.quit:
				return
			}
			headerFilterInMeter.Mark(int64(len(task.headers)))

			// Split the batch of headers into unknown ones (to return to the caller),
			// known incomplete ones (requiring body retrievals) and completed blocks.
			unknown, incomplete, complete := make([]*types.Header, 0), make([]*announce, 0), make([]*types.Block, 0)
			for _, header := range task.headers {
				hash := header.Hash()

				// Filter fetcher-requested headers from other synchronisation algorithms
				if announce := f.fetching[hash]; announce != nil && announce.origin == task.peer && f.fetched[hash] == nil && f.completing[hash] == nil && f.queued[hash] == nil {
					// If the delivered header does not match the promised number, drop the announcer
					if header.Number.Uint64() != announce.number {
						log.Trace("Invalid block number fetched", "peer", announce.origin, "hash", header.Hash(), "announced", announce.number, "provided", header.Number)
						f.dropPeer(announce.origin)
						f.forgetHash(hash)
						continue
					}
					// Only keep if not imported by other means
					if f.getBlock(hash) == nil {
						announce.header = header
						announce.time = task.time

						// If the block is empty (header only), short circuit into the final import queue
						if header.TxHash == types.DeriveSha(types.Transactions{}) {
							log.Trace("Block empty, skipping body retrieval", "peer", announce.origin, "number", header.Number, "hash", header.Hash())

							block := types.NewBlockWithHeader(header)
							block.ReceivedAt = task.time

							complete = append(complete, block)
							f.completing[hash] = announce
							continue
						}
						// Otherwise add to the list of blocks needing completion
						incomplete = append(incomplete, announce)
					} else {
						log.Trace("Block already imported, discarding header", "peer", announce.origin, "number", header.Number, "hash", header.Hash())
						f.forgetHash(hash)
					}
				} else {
					// Fetcher doesn't know about it, add to the return list
					unknown = append(unknown, header)
				}
			}
			headerFilterOutMeter.Mark(int64(len(unknown)))
			select {
			case filter <- &headerFilterTask{headers: unknown, time: task.time}:
			case <-f.quit:
				return
			}
			// Schedule the retrieved headers for body completion
			for _, announce := range incomplete {
				hash := announce.header.Hash()
				if _, ok := f.completing[hash]; ok {
					continue
				}
				f.fetched[hash] = append(f.fetched[hash], announce)
				if len(f.fetched) == 1 {
					f.rescheduleComplete(completeTimer)
				}
			}
			// Schedule the header-only blocks for import
			for _, block := range complete {
				if announce := f.completing[block.Hash()]; announce != nil {
					f.enqueue(announce.origin, block)
				}
			}

		case filter := <-f.bodyFilter:
			// Block bodies arrived, extract any explicitly requested blocks, return the rest
			var task *bodyFilterTask
			select {
			case task = <-filter:
			case <-f.quit:
				return
			}
			bodyFilterInMeter.Mark(int64(len(task.transactions)))

			blocks := make([]*types.Block, 0)
			for i := 0; i < len(task.transactions); i++ {
				// Match up a body to any possible completion request
				matched := false

				for hash, announce := range f.completing {
					if f.queued[hash] == nil {
						txnHash := types.DeriveSha(types.Transactions(task.transactions[i]))

						if txnHash == announce.header.TxHash && announce.origin == task.peer {
							// Mark the body matched, reassemble if still unknown
							matched = true

							if f.getBlock(hash) == nil {
								block := types.NewBlockWithHeader(announce.header).WithBody(task.transactions[i])
								block.ReceivedAt = task.time

								blocks = append(blocks, block)
							} else {
								f.forgetHash(hash)
							}
						}
					}
				}
				if matched {
					task.transactions = append(task.transactions[:i], task.transactions[i+1:]...)
					i--
					continue
				}
			}

			bodyFilterOutMeter.Mark(int64(len(task.transactions)))
			select {
			case filter <- task:
			case <-f.quit:
				return
			}
			// Schedule the retrieved blocks for ordered import
			for _, block := range blocks {
				if announce := f.completing[block.Hash()]; announce != nil {
					f.enqueue(announce.origin, block)
				}
			}

		case filter := <-f.keyBlockFilter:
			// key blocks arrived from a remote peer. Extract those that were explicitly
			// requested by the fetcher, and return everything else so it's delivered
			// to other parts of the system.
			var task *keyBlockFilterTask
			select {
			case task = <-filter:
			case <-f.quit:
				return
			}

			// Split the batch of key blocks into unknown ones (to return to the caller),completed blocks.
			unknown := make([]*types.KeyBlock, 0)
			for _, block := range task.blocks {
				hash := block.Hash()

				// Filter fetcher-requested headers from other synchronisation algorithms
				if announce := f.fetching[hash]; announce != nil && announce.origin == task.peer && f.fetched[hash] == nil && f.queued[hash] == nil {
					// If the delivered header does not match the promised number, drop the announcer
					if block.NumberU64() != announce.number {
						log.Trace("Invalid block number fetched", "peer", announce.origin, "hash", block.Hash(), "announced", announce.number, "provided", block.NumberU64())
						f.dropPeer(announce.origin)
						f.forgetHash(hash)
						continue
					}
					// Only keep if not imported by other means
					if !f.hasBlock(hash, true) {
						log.Trace("Enqueue key block", "hash", block.Hash().Hex())
						f.enqueueKeyBlock(announce.origin, block)
					} else {
						log.Trace("Block already imported, discarding header", "peer", announce.origin, "number", block.NumberU64(), "hash", block.Hash())
						f.forgetHash(hash)
					}
				} else {
					//log.Trace("Filtering unknown key block", "hash", block.Hash().Hex())
					// Fetcher doesn't know about it, add to the return list
					unknown = append(unknown, block)
				}
			}

			select {
			case filter <- &keyBlockFilterTask{blocks: unknown, time: task.time}:
			case <-f.quit:
				return
			}
		}

	}
}

// rescheduleFetch resets the specified fetch timer to the next announce timeout.
func (f *Fetcher) rescheduleFetch(fetch *time.Timer) {
	// Short circuit if no blocks are announced
	if len(f.announced) == 0 {
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.announced {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	fetch.Reset(arriveTimeout - time.Since(earliest))
}

// rescheduleComplete resets the specified completion timer to the next fetch timeout.
func (f *Fetcher) rescheduleComplete(complete *time.Timer) {
	// Short circuit if no headers are fetched
	if len(f.fetched) == 0 {
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.fetched {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	complete.Reset(gatherSlack - time.Since(earliest))
}

// enqueue schedules a new future import operation, if the block to be imported
// has not yet been seen.
func (f *Fetcher) enqueue(peer string, block *types.Block) {
	hash := block.Hash()

	// Ensure the peer isn't DOSing us
	count := f.queues[peer] + 1
	if count > blockLimit {
		log.Debug("Discarded propagated block, exceeded allowance", "peer", peer, "number", block.Number(), "hash", hash, "limit", blockLimit)
		propBroadcastDOSMeter.Mark(1)
		f.forgetHash(hash)
		return
	}
	// Discard any past or too distant blocks
	if dist := int64(block.NumberU64()) - int64(f.chainHeight()); dist < 1 || dist > maxQueueDist {
		log.Debug("Discarded propagated block, too far away", "peer", peer, "number", block.Number(), "hash", hash, "distance", dist)
		propBroadcastDropMeter.Mark(1)
		f.forgetHash(hash)
		return
	}
	// Schedule the block for future importing
	if _, ok := f.queued[hash]; !ok {
		op := &inject{
			origin: peer,
			block:  block,
		}
		f.queues[peer] = count
		f.queued[hash] = op
		f.queue.Push(op, -float32(block.NumberU64()))
		if f.queueChangeHook != nil {
			f.queueChangeHook(op.block.Hash(), true)
		}
		log.Debug("Queued propagated block", "peer", peer, "number", block.Number(), "hash", hash, "queued", f.queue.Size())
	}
}

// enqueue schedules a new future import operation, if the block to be imported
// has not yet been seen.
func (f *Fetcher) enqueueKeyBlock(peer string, block *types.KeyBlock) {
	hash := block.Hash()

	// Ensure the peer isn't DOSing us
	count := f.queues[peer] + 1
	if count > blockLimit {
		log.Debug("Discarded propagated block, exceeded allowance", "peer", peer, "number", block.Number(), "hash", hash, "limit", blockLimit)
		propBroadcastDOSMeter.Mark(1)
		f.forgetHash(hash)
		return
	}
	// Discard any past or too distant blocks
	if dist := int64(block.NumberU64()) - int64(f.keyChainHeight()); dist < 1 || dist > maxQueueDist {
		//log.Debug("Discarded propagated key block, too far away", "peer", peer, "number", block.Number(), "hash", hash, "distance", dist)
		propBroadcastDropMeter.Mark(1)
		f.forgetHash(hash)
		return
	}
	// Schedule the block for future importing
	if _, ok := f.queued[hash]; !ok {
		op := &inject{
			origin:     peer,
			keyBlock:   block,
			isKeyBlock: true,
		}
		f.queues[peer] = count
		f.queued[hash] = op
		f.queue.Push(op, -float32(block.NumberU64()))
		if f.queueChangeHook != nil {
			f.queueChangeHook(op.block.Hash(), true)
		}
		log.Debug("Queued propagated key block", "peer", peer, "number", block.Number(), "hash", hash, "queued", f.queue.Size())
	}
}

// insertBlock spawns a new goroutine to run a block insertion into the chain. If the
// block's number is at the same height as the current import phase, it updates
// the phase states accordingly.
func (f *Fetcher) insertBlock(peer string, block *types.Block) {
	hash := block.Hash()

	// Run the import on a new thread
	log.Debug("Importing propagated block", "peer", peer, "number", block.Number(), "hash", hash)
	go func() {
		defer func() { f.done <- hash }()

		// If the parent's unknown, abort insertion
		parent := f.getBlock(block.ParentHash())
		if parent == nil {
			log.Debug("Unknown parent of propagated block", "peer", peer, "number", block.Number(), "hash", hash, "parent", block.ParentHash())
			return
		}
		// Quickly validate the header and propagate the block if it passes
		switch err := f.verifyHeader(block); err {
		case nil:
			// All ok, quickly propagate to our peers
			propBroadcastOutTimer.UpdateSince(block.ReceivedAt)
			go f.broadcastBlock(block, true)

		case types.ErrFutureBlock:
			log.Debug("Propagated future tx block", "peer", peer, "number", block.Number(), "hash", hash)
			return
			// Weird future block, don't fail, but neither propagate

		default:
			// Something went very wrong, drop the peer
			log.Debug("Propagated block verification failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			f.dropPeer(peer)
			return
		}
		// Run the actual import and log any issues
		if _, err := f.insertChain(types.Blocks{block}); err != nil {
			log.Debug("Propagated block import failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			return
		}
		// If import succeeded, broadcast the block
		propAnnounceOutTimer.UpdateSince(block.ReceivedAt)
		go f.broadcastBlock(block, false)

		// Invoke the testing hook if needed
		if f.importedHook != nil {
			f.importedHook(block)
		}
	}()
}

// insertKeyBlock spawns a new goroutine to run a block insertion into the chain. If the
// block's number is at the same height as the current import phase, it updates
// the phase states accordingly.
func (f *Fetcher) insertKeyBlock(peer string, block *types.KeyBlock) {
	hash := block.Hash()

	// Run the import on a new thread
	log.Debug("Importing propagated key block", "peer", peer, "number", block.Number(), "hash", hash)
	go func() {
		defer func() { f.done <- hash }()

		// If the parent's unknown, abort insertion
		parent := f.getKeyBlock(block.ParentHash())
		if parent == nil {
			log.Debug("Unknown parent of propagated key block", "peer", peer, "number", block.Number(), "hash", hash, "parent", block.ParentHash())
			return
		}
		// Quickly validate the header and propagate the block if it passes
		switch err := f.verifyKeyBlock(block); err {
		case nil:
			// All ok, quickly propagate to our peers
			propBroadcastOutTimer.UpdateSince(block.ReceivedAt)
			//go f.broadcastKeyBlock(block, true)

		case types.ErrFutureBlock:
			// Weird future block, don't fail, but neither propagate

		default:
			// Something went very wrong, drop the peer
			//??log.Debug("Propagated key block verification failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			f.dropPeer(peer)
			return
		}
		// Run the actual import and log any issues
		if _, err := f.insertKeyChain(types.KeyBlocks{block}); err != nil {
			log.Debug("Propagated key block import failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			return
		}
		// If import succeeded, broadcast the block
		propAnnounceOutTimer.UpdateSince(block.ReceivedAt)
		//go f.broadcastKeyBlock(block, false)

		// Invoke the testing hook if needed
		if f.importedKeyBlockHook != nil {
			f.importedKeyBlockHook(block)
		}
	}()
}

// forgetHash removes all traces of a block announcement from the fetcher's
// internal state.
func (f *Fetcher) forgetHash(hash common.Hash) {
	// Remove all pending announces and decrement DOS counters
	for _, announce := range f.announced[hash] {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
	}
	delete(f.announced, hash)
	if f.announceChangeHook != nil {
		f.announceChangeHook(hash, false)
	}
	// Remove any pending fetches and decrement the DOS counters
	if announce := f.fetching[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.fetching, hash)
	}

	// Remove any pending completion requests and decrement the DOS counters
	for _, announce := range f.fetched[hash] {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
	}
	delete(f.fetched, hash)

	// Remove any pending completions and decrement the DOS counters
	if announce := f.completing[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.completing, hash)
	}
}

// forgetBlock removes all traces of a queued block from the fetcher's internal
// state.
func (f *Fetcher) forgetBlock(hash common.Hash) {
	if insert := f.queued[hash]; insert != nil {
		f.queues[insert.origin]--
		if f.queues[insert.origin] == 0 {
			delete(f.queues, insert.origin)
		}
		delete(f.queued, hash)
	}
}
