package core

import (
	"errors"
	"math/big"
	"sync"

	"golang.org/x/crypto/ed25519"

	"bytes"
	//	"net"
	"sort"
	"time"

	"strconv"

	"net"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/cphdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/p2p/netutil"
	"github.com/cypherium/cypherBFT/pow"
)

var (
	// ErrCandidatePowFail is returned if the candidate fails pow verification
	ErrCandidatePowVerificationFail = errors.New("Candidate pow verification failed, discard ")
	ErrCandidateNumberLow           = errors.New("Candidate number lower than key block header number, discard ")
	ErrCandidateExisted             = errors.New("Candidate Existed ")
	ErrCandidateVersionLow          = errors.New("Candidate Version lower than local key block header number, discard ")
)

type candidateLookup struct {
	all              map[common.Hash]*types.Candidate
	DisableIpEncrypt bool
	lock             sync.Mutex
	backend          Backend
}

func newCandidateLookup(cph Backend) *candidateLookup {
	return &candidateLookup{
		all:     make(map[common.Hash]*types.Candidate),
		backend: cph,
	}
}

// Flatten creates a candinonce-sorted slice of cands based on the loosely
//// sorted internal representation. The result of the sorting is cached in case
//// it's requested again before any modifications are made to the contents.
func (t *candidateLookup) Flatten() types.CandsByNonce {
	// If the sorting was not cached yet, create and cache it
	candidates := make(types.CandsByNonce, 0)
	for _, cand := range t.all {
		candidates = append(candidates, cand)
	}
	if len(candidates) > 1 {
		sort.Sort(candidates)

	}
	cands := make(types.CandsByNonce, len(candidates))
	copy(cands, candidates)

	return cands
}
func (t *candidateLookup) SortAndBestCandidate(determintype uint8, delete bool) (types.CandsByNonce, *types.Candidate, error) {
	var index uint64
	var bestCand *types.Candidate
	sortedCandidates := make(types.CandsByNonce, 0)
	itemLen := len(t.all)
	if itemLen <= 0 {
		return nil, nil, errors.New("no candidate exist")
	}
	sortedCandidates = t.Flatten()
	switch determintype {
	case types.DeterminByMinNonce:
		index = 0
	case types.DeterminByMaxNonce:
		index = uint64(itemLen - 1)
	default:
		return nil, nil, errors.New("this type exist not")
	}
	bestCand = sortedCandidates[index]
	if delete {
		log.Info("delete")
		if !t.Remove(bestCand) {
			return sortedCandidates, bestCand, errors.New("candidate do not found")
		}

	}
	return sortedCandidates, bestCand, nil
}

func (t *candidateLookup) Content() []*types.Candidate {
	t.lock.Lock()
	defer t.lock.Unlock()

	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate

	if sortedCandidates, bestCandidate, err = t.PrepareStageSort(types.DeterminByMinNonce); err != nil {
		return nil
	}
	log.Info("Content", "sortedCandidates", sortedCandidates, "bestCandidate nonce", bestCandidate.KeyCandidate.Nonce.Uint64())
	return sortedCandidates
}

func (t *candidateLookup) RandomDecideSortType() (types.CandsByNonce, *types.Candidate, uint8, error) {

	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate
	determinSortType := uint8(time.Now().Unix() % 2)
	if sortedCandidates, bestCandidate, err = t.PrepareStageSort(determinSortType); err != nil {
		return sortedCandidates, bestCandidate, determinSortType, err
	}
	log.Info("RandomDecideSortType", "determinSortType", determinSortType)
	return sortedCandidates, bestCandidate, determinSortType, nil
}
func (t *candidateLookup) PrepareStageSort(determintype uint8) (types.CandsByNonce, *types.Candidate, error) {
	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate
	//bestCandidate will not to be deleted
	if sortedCandidates, bestCandidate, err = t.SortAndBestCandidate(determintype, false); err != nil {
		//log.Info("PrepareStageSort", "", err)
		return sortedCandidates, bestCandidate, err

	}

	return sortedCandidates, bestCandidate, nil
}

func (t *candidateLookup) CommitStageSort(determintype uint8) (types.CandsByNonce, *types.Candidate, error) {
	sortedCandidates := make(types.CandsByNonce, 0)
	var err error
	var bestCandidate *types.Candidate
	//bestCandidate will be deleted
	if sortedCandidates, bestCandidate, err = t.SortAndBestCandidate(determintype, true); err != nil {
		log.Info("CommitStageSort", "", err)
		return sortedCandidates, bestCandidate, err
	}

	return sortedCandidates, bestCandidate, nil
}

// Add adds a candidate to the lookup.
func (t *candidateLookup) Add(c *types.Candidate) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	if _, ok := t.all[c.Hash()]; ok {
		return true // already exists
	}

	t.all[c.Hash()] = c

	return false
}

// Remove deletes a candidate from the maintained map, returning whether the
// candidate was found.
func (t *candidateLookup) Remove(c *types.Candidate) bool {

	for k, v := range t.all {

		if v.PubKey == c.PubKey && bytes.Equal(v.KeyCandidate.Nonce[:], c.KeyCandidate.Nonce[:]) {
			delete(t.all, k)
			return true
		}
	}
	return false
}

func (t *candidateLookup) ClearObsolete(keyHeadNumber *big.Int) {
	t.lock.Lock()
	defer t.lock.Unlock()

	//log.Info("Clear candidates older than", "number", keyHeadNumber.Uint64())
	for k, v := range t.all {
		if keyHeadNumber.Cmp(v.KeyCandidate.Number) >= 0 {
			delete(t.all, k)
		}
	}
}

func (t *candidateLookup) ClearCandidate(pubKey ed25519.PublicKey) {
	t.lock.Lock()
	defer t.lock.Unlock()
	for k, candidate := range t.all {
		if string(pubKey) == candidate.PubKey {
			delete(t.all, k)
		}
	}
}
func (t *candidateLookup) FoundCandidate(number *big.Int, pubKey string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, candidate := range t.all {
		if number.Cmp(candidate.KeyCandidate.Number) == 0 && pubKey == candidate.PubKey {
			return true
		}
	}

	return false
}

// CandidatePoolConfig are the configuration parameters of the transaction pool.
type LocalTestIpConfig struct {
	LocalTestIP string
}

type ExternalIpConfig struct {
	ExternalIP string
}

///////////////////////////////////////////////
type CandidatePool struct {
	candidates     *candidateLookup
	mu             sync.Mutex
	feed           event.Feed
	scope          event.SubscriptionScope
	txFeed         event.Feed
	backend        Backend
	mux            *event.TypeMux
	db             cphdb.Database
	CheckMinerPort func(addr string, blockN uint64, keyblockN uint64)
}

// Backend wraps all methods required for candidate pool.
type Backend interface {
	BlockChain() *BlockChain
	KeyBlockChain() *KeyBlockChain
	Engine() pow.Engine
}

func NewCandidatePool(cph Backend, mux *event.TypeMux, db cphdb.Database) *CandidatePool {
	cp := &CandidatePool{
		db:         db,
		candidates: newCandidateLookup(cph),
		mux:        mux,
		backend:    cph,
	}
	go cp.loop()
	return cp
}

func (cp *CandidatePool) loop() {
	events := cp.mux.Subscribe(RemoteCandidateEvent{})
	defer events.Unsubscribe()
	for ev := range events.Chan() {
		switch obj := ev.Data.(type) {
		case RemoteCandidateEvent:
			candidate := obj.Candidate
			log.Debug("loop RemoteCandidateEvent", "candidate.number", obj.Candidate.KeyCandidate.Number.Uint64(), "candidate.PubKey", obj.Candidate.PubKey, "IP", candidate.IP, "Port", candidate.Port)
			err := cp.AddRemote(candidate, false)
			if err != nil {
				log.Error("loop RemoteCandidateEvent", "err", ErrCandidatePowVerificationFail)
			}

		}
	}
}

func (cp *CandidatePool) add(candidate *types.Candidate, local bool, isPlaintext bool) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	keyBlock := cp.backend.KeyBlockChain().CurrentBlock()
	if candidate.KeyCandidate.T_Number < keyBlock.T_Number() {
		log.Error("CandidatePool.add is too low", "number", candidate.KeyCandidate.T_Number)
		return errors.New("candidate's txBlockNumber is too low")
	}
	cp.CheckMinerPort("127.0.0.1:7100", cp.backend.BlockChain().CurrentBlockN(), cp.backend.KeyBlockChain().CurrentBlockN())
	if exists := cp.candidates.Add(candidate); !exists {
		/*
			log.Info("CandidatePool add new candidate",
				"local", local,
				"candidate.number", candidate.KeyCandidate.Number.Uint64(),
				"pubkey", candidate.PubKey,
				"hash", candidate.Hash(),
			)
		*/
		if local == false {

			// if the candidate comes from network, we need to notify reconfig module which may start doing PBFT consensus
			go cp.mux.Post(RemoteCandidateEvent{Candidate: candidate})

		}

		// Broadcast to p2p network
		go cp.feed.Send(candidate)
	} else {
		//log.Info("Try to add existing candidate, ignored",
		//	"local", local,
		//	"candidate.number", candidate.KeyCandidate.Number.Uint64(),
		//	"pubkey", hex.EncodeToString(candidate.PubKey),
		//	"hash", candidate.Hash(),
		//)
	}

	return nil
}

func (cp *CandidatePool) CheckMinerMsgAck(address string, blockN uint64, keyblockN uint64) {
	//.........
}

func (cp *CandidatePool) Content() []*types.Candidate {
	return cp.candidates.Content()
}

func (cp *CandidatePool) AddLocal(candidate *types.Candidate) error {
	keyHeadNumber := cp.backend.KeyBlockChain().CurrentBlock().Number()
	if keyHeadNumber.Cmp(candidate.KeyCandidate.Number) >= 0 {
		log.Error("Discard local candidate: number too low",
			"candidate.number", candidate.KeyCandidate.Number.Uint64(), "keyNumber", cp.backend.KeyBlockChain().CurrentBlockN())
		return ErrCandidateNumberLow
	}

	if cp.FoundCandidate(candidate.KeyCandidate.Number, candidate.PubKey) {
		log.Error("Candidate Existed")
		return ErrCandidateExisted
	}
	log.Info("Now you will be waitting for at least 10-40 minutes to become leader or committee member.")
	return cp.add(candidate, true, true)
}

func (cp *CandidatePool) AddRemote(candidate *types.Candidate, isPlaintext bool) error {
	if err := cp.verify(candidate); err == nil {
		return cp.add(candidate, false, isPlaintext)
	} else {
		return err
	}
}

func (cp *CandidatePool) SubscribeNewCandidatePoolEvent(ch chan<- *types.Candidate) event.Subscription {
	return cp.scope.Track(cp.feed.Subscribe(ch))
}

func (cp *CandidatePool) verify(candidate *types.Candidate) error {
	err := cp.backend.Engine().VerifyCandidate(cp.backend.KeyBlockChain(), candidate)
	if err != nil {
		return ErrCandidatePowVerificationFail
	}

	keyHeadNumber := cp.backend.KeyBlockChain().CurrentBlock().Number()
	if keyHeadNumber.Cmp(candidate.KeyCandidate.Number) >= 0 {
		return ErrCandidateNumberLow
	}

	keyHeadVersionStr := cp.backend.KeyBlockChain().CurrentBlock().Version()

	var localKeyHeadVersionNumber, remoteKeyHeadVersionNumber int
	localKeyHeadVersionNumber, err = strconv.Atoi(keyHeadVersionStr)
	remoteKeyHeadVersionNumber, err = strconv.Atoi(candidate.KeyCandidate.Version)
	if localKeyHeadVersionNumber > remoteKeyHeadVersionNumber {
		return ErrCandidateVersionLow
	}

	err = netutil.VerifyConnectivity("udp", net.IP(candidate.IP), candidate.Port)
	if err != nil {
		log.Warn("candidate pool verify candidate's ip", "err", err)
		return err
	}
	return nil
}

func (cp *CandidatePool) FoundCandidate(number *big.Int, pubKey string) bool {
	return cp.candidates.FoundCandidate(number, pubKey)
}

func (cp *CandidatePool) ClearCandidate(pubKey ed25519.PublicKey) {
	cp.candidates.ClearCandidate(pubKey)
}

func (cp *CandidatePool) ClearObsolete(keyHeadNumber *big.Int) {
	cp.candidates.ClearObsolete(keyHeadNumber)
}
