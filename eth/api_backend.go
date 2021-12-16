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

package eth

import (
	"context"
	"errors"
	"math/big"

	"github.com/cypherium/cypherBFT/accounts"
	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/math"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/bloombits"
	"github.com/cypherium/cypherBFT/core/rawdb"
	"github.com/cypherium/cypherBFT/core/state"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/core/vm"
	"github.com/cypherium/cypherBFT/eth/downloader"
	"github.com/cypherium/cypherBFT/eth/gasprice"
	"github.com/cypherium/cypherBFT/ethdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/rpc"
)

// EthAPIBackend implements ethapi.Backend for full nodes
type EthAPIBackend struct {
	eth *Cypherium
	gpo *gasprice.Oracle
}

// ChainConfig returns the active chain configuration.
func (b *EthAPIBackend) ChainConfig() *params.ChainConfig {
	return b.eth.chainConfig
}

func (b *EthAPIBackend) CurrentBlock() *types.Block {
	return b.eth.blockchain.CurrentBlock()
}

func (b *EthAPIBackend) Exceptions(blockNumber int64) []string {
	return b.eth.Exceptions(blockNumber)
}

func (b *EthAPIBackend) TakePartInNumberList(address common.Address, blockNumber rpc.BlockNumber) []string {
	return b.eth.TakePartInNumberList(address, blockNumber)
}

func (b *EthAPIBackend) SetHead(number uint64) {
	b.eth.protocolManager.downloader.Cancel()
	b.eth.blockchain.SetHead(number)
}

func (b *EthAPIBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//block := b.eth.miner.PendingBlock()
		//return block.Header(), nil

		return nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.eth.blockchain.CurrentBlock().Header(), nil
	}
	return b.eth.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}

func (b *EthAPIBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	log.Info("BlockByNumber")
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//block := b.eth.miner.PendingBlock()
		//return block, nil

		return nil, errors.New("No pending block for Cypherium")
	}
	var currentBlock *types.Block
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		currentBlock = b.eth.blockchain.CurrentBlock()
	} else {
		currentBlock = b.eth.blockchain.GetBlockByNumber(uint64(blockNr))
	}
	log.Info("BlockByNumber", "currentBlock", currentBlock)
	currentBlock.Header().Time.Set(nil)
	if currentBlock != nil {
		log.Info("BlockByNumber", "currentBlock", currentBlock)
		currentBlock.TrimTimeMs()
	}
	return currentBlock, nil
}

func (b *EthAPIBackend) KeyBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.KeyBlock, error) {
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.eth.keyBlockChain.CurrentBlock(), nil
	}
	return b.eth.keyBlockChain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *EthAPIBackend) KeyBlockByHash(ctx context.Context, blockHash common.Hash) (*types.KeyBlock, error) {
	return b.eth.keyBlockChain.GetBlockByHash(blockHash), nil
}

func (b *EthAPIBackend) GetKeyBlockChain() *core.KeyBlockChain {
	return b.eth.keyBlockChain
}
func (b *EthAPIBackend) MockKeyBlock(amount int64) {
	b.eth.keyBlockChain.MockBlock(amount)
}

func (b *EthAPIBackend) AnnounceBlock(blockNr rpc.BlockNumber) {
	b.eth.keyBlockChain.AnnounceBlock((uint64)(blockNr))
}

func (b *EthAPIBackend) KeyBlockNumber() uint64 {
	return b.eth.keyBlockChain.CurrentBlockN()
}

func (b *EthAPIBackend) CommitteeMembers(ctx context.Context, blockNr rpc.BlockNumber) ([]*common.Cnode, error) {

	// Pending block is only known by the miner
	log.Info("CommitteeMembers call")
	if blockNr == rpc.PendingBlockNumber {
		//block := b.eth.miner.PendingBlock()
		//return block, nil

		return nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.eth.keyBlockChain.CurrentCommittee(), nil
	}
	return b.eth.keyBlockChain.GetCommitteeByNumber(uint64(blockNr)), nil
}

func (b *EthAPIBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//block, state := b.eth.miner.Pending()
		//return state, block.Header(), nil

		return nil, nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	stateDb, err := b.eth.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *EthAPIBackend) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.eth.blockchain.GetBlockByHash(hash), nil
}

func (b *EthAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.eth.chainDb, hash); number != nil {
		return rawdb.ReadReceipts(b.eth.chainDb, hash, *number), nil
	}
	return nil, nil
}

func (b *EthAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	number := rawdb.ReadHeaderNumber(b.eth.chainDb, hash)
	if number == nil {
		return nil, nil
	}
	receipts := rawdb.ReadReceipts(b.eth.chainDb, hash, *number)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *EthAPIBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.eth.blockchain.GetTdByHash(blockHash)
}

func (b *EthAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.eth.BlockChain())
	evm := vm.NewEVM(context, state, b.eth.chainConfig, vmCfg, b.eth.BlockChain())
	return evm, vmError, nil
}

func (b *EthAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *EthAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainEvent(ch)
}

func (b *EthAPIBackend) SubscribeKeyChainHeadEvent(ch chan<- core.KeyChainHeadEvent) event.Subscription {
	return b.eth.KeyBlockChain().SubscribeChainEvent(ch)
}

func (b *EthAPIBackend) SubscribeLatestTPSEvent(ch chan<- uint64) event.Subscription {
	return b.eth.SubscribeLatestTPSEvent(ch)
}

func (b *EthAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *EthAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.eth.BlockChain().SubscribeLogsEvent(ch)
}

func (b *EthAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.eth.txPool.AddLocal(signedTx)
}

func (b *EthAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.eth.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *EthAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.eth.txPool.Get(hash)
}

func (b *EthAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.eth.txPool.State().GetNonce(addr), nil
}

func (b *EthAPIBackend) Stats() (pending int, queued int) {
	return b.eth.txPool.Stats()
}

func (b *EthAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.eth.TxPool().Content()
}

func (b *EthAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.eth.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *EthAPIBackend) Downloader() *downloader.Downloader {
	return b.eth.Downloader()
}

func (b *EthAPIBackend) ProtocolVersion() int {
	return b.eth.EthVersion()
}

func (b *EthAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *EthAPIBackend) ChainDb() ethdb.Database {
	return b.eth.ChainDb()
}

func (b *EthAPIBackend) EventMux() *event.TypeMux {
	return b.eth.EventMux()
}

func (b *EthAPIBackend) AccountManager() *accounts.Manager {
	return b.eth.AccountManager()
}

func (b *EthAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.eth.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *EthAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.eth.bloomRequests)
	}
}

func (b *EthAPIBackend) CandidatePool() *core.CandidatePool {
	return b.eth.CandidatePool()
}

func (b *EthAPIBackend) RosterConfig(data ...interface{}) error {
	return b.GetKeyBlockChain().PostRosterConfigEvent(data)
}

func (b *EthAPIBackend) RollbackKeyChainFrom(blockHash common.Hash) error {
	return b.eth.keyBlockChain.RollbackKeyChainFrom(blockHash)
}

func (b *EthAPIBackend) RollbackTxChainFrom(blockHash common.Hash) error {
	return b.eth.blockchain.RollbackTxChainFrom(blockHash)
}
