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
	"github.com/cypherium/cypherBFT/cph/downloader"
	"github.com/cypherium/cypherBFT/cph/gasprice"
	"github.com/cypherium/cypherBFT/cphdb"
	"github.com/cypherium/cypherBFT/event"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/rpc"
)

// CphAPIBackend implements cphapi.Backend for full nodes
type CphAPIBackend struct {
	cph *Cypherium
	gpo *gasprice.Oracle
}

// ChainConfig returns the active chain configuration.
func (b *CphAPIBackend) ChainConfig() *params.ChainConfig {
	return b.cph.chainConfig
}

func (b *CphAPIBackend) CurrentBlock() *types.Block {
	return b.cph.blockchain.CurrentBlock()
}

func (b *CphAPIBackend) Exceptions(blockNumber int64) []string {
	return b.cph.Exceptions(blockNumber)
}

func (b *CphAPIBackend) TakePartInNumberList(address common.Address, blockNumber rpc.BlockNumber) []string {
	return b.cph.TakePartInNumberList(address, blockNumber)
}

func (b *CphAPIBackend) SetHead(number uint64) {
	b.cph.protocolManager.downloader.Cancel()
	b.cph.blockchain.SetHead(number)
}

func (b *CphAPIBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//block := b.cph.miner.PendingBlock()
		//return block.Header(), nil

		return nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.cph.blockchain.CurrentBlock().Header(), nil
	}
	return b.cph.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}

func (b *CphAPIBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//block := b.cph.miner.PendingBlock()
		//return block, nil

		return nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.cph.blockchain.CurrentBlock(), nil
	}
	return b.cph.blockchain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *CphAPIBackend) KeyBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.KeyBlock, error) {
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.cph.keyBlockChain.CurrentBlock(), nil
	}
	return b.cph.keyBlockChain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *CphAPIBackend) KeyBlockByHash(ctx context.Context, blockHash common.Hash) (*types.KeyBlock, error) {
	return b.cph.keyBlockChain.GetBlockByHash(blockHash), nil
}

func (b *CphAPIBackend) GetKeyBlockChain() *core.KeyBlockChain {
	return b.cph.keyBlockChain
}
func (b *CphAPIBackend) MockKeyBlock(amount int64) {
	b.cph.keyBlockChain.MockBlock(amount)
}

func (b *CphAPIBackend) AnnounceBlock(blockNr rpc.BlockNumber) {
	b.cph.keyBlockChain.AnnounceBlock((uint64)(blockNr))
}

func (b *CphAPIBackend) KeyBlockNumber() uint64 {
	return b.cph.keyBlockChain.CurrentBlockN()
}

func (b *CphAPIBackend) CommitteeMembers(ctx context.Context, blockNr rpc.BlockNumber) ([]*common.Cnode, error) {

	// Pending block is only known by the miner
	log.Info("CommitteeMembers call")
	if blockNr == rpc.PendingBlockNumber {
		//block := b.cph.miner.PendingBlock()
		//return block, nil

		return nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.cph.keyBlockChain.CurrentCommittee(), nil
	}
	return b.cph.keyBlockChain.GetCommitteeByNumber(uint64(blockNr)), nil
}

func (b *CphAPIBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//block, state := b.cph.miner.Pending()
		//return state, block.Header(), nil

		return nil, nil, errors.New("No pending block for Cypherium")
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	stateDb, err := b.cph.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *CphAPIBackend) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.cph.blockchain.GetBlockByHash(hash), nil
}

func (b *CphAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.cph.chainDb, hash); number != nil {
		return rawdb.ReadReceipts(b.cph.chainDb, hash, *number), nil
	}
	return nil, nil
}

func (b *CphAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	number := rawdb.ReadHeaderNumber(b.cph.chainDb, hash)
	if number == nil {
		return nil, nil
	}
	receipts := rawdb.ReadReceipts(b.cph.chainDb, hash, *number)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *CphAPIBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.cph.blockchain.GetTdByHash(blockHash)
}

func (b *CphAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.cph.BlockChain())
	evm := vm.NewEVM(context, state, b.cph.chainConfig, vmCfg, b.cph.BlockChain())
	return evm, vmError, nil
}

func (b *CphAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.cph.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *CphAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.cph.BlockChain().SubscribeChainEvent(ch)
}

func (b *CphAPIBackend) SubscribeKeyChainHeadEvent(ch chan<- core.KeyChainHeadEvent) event.Subscription {
	return b.cph.KeyBlockChain().SubscribeChainEvent(ch)
}

func (b *CphAPIBackend) SubscribeLatestTPSEvent(ch chan<- uint64) event.Subscription {
	return b.cph.SubscribeLatestTPSEvent(ch)
}

func (b *CphAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.cph.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *CphAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.cph.BlockChain().SubscribeLogsEvent(ch)
}

func (b *CphAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.cph.txPool.AddLocal(signedTx)
}

func (b *CphAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.cph.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *CphAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.cph.txPool.Get(hash)
}

func (b *CphAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.cph.txPool.State().GetNonce(addr), nil
}

func (b *CphAPIBackend) Stats() (pending int, queued int) {
	return b.cph.txPool.Stats()
}

func (b *CphAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.cph.TxPool().Content()
}

func (b *CphAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.cph.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *CphAPIBackend) Downloader() *downloader.Downloader {
	return b.cph.Downloader()
}

func (b *CphAPIBackend) ProtocolVersion() int {
	return b.cph.CypherVersion()
}

func (b *CphAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *CphAPIBackend) ChainDb() cphdb.Database {
	return b.cph.ChainDb()
}

func (b *CphAPIBackend) EventMux() *event.TypeMux {
	return b.cph.EventMux()
}

func (b *CphAPIBackend) AccountManager() *accounts.Manager {
	return b.cph.AccountManager()
}

func (b *CphAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.cph.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *CphAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.cph.bloomRequests)
	}
}

func (b *CphAPIBackend) CandidatePool() *core.CandidatePool {
	return b.cph.CandidatePool()
}

func (b *CphAPIBackend) RosterConfig(data ...interface{}) error {
	return b.GetKeyBlockChain().PostRosterConfigEvent(data)
}

func (b *CphAPIBackend) RollbackKeyChainFrom(blockHash common.Hash) error {
	return b.cph.keyBlockChain.RollbackKeyChainFrom(blockHash)
}

func (b *CphAPIBackend) RollbackTxChainFrom(blockHash common.Hash) error {
	return b.cph.blockchain.RollbackTxChainFrom(blockHash)
}
