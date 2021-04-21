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

// Package cphclient provides a client for the Cypherium RPC API.
package cphclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/hexutil"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/cypherI"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/rlp"
	"github.com/cypherium/cypherBFT/rpc"
)

// Client defines typed wrappers for the Cypherium RPC API.
type Client struct {
	c *rpc.Client
}

// Dial connects a client to the given URL.
func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
func NewClient(c *rpc.Client) *Client {
	return &Client{c}
}

func (ec *Client) Close() {
	ec.c.Close()
}

// Blockchain Access

// BlockByHash returns the given full block and number of transactions it may includes
//
// Note that loading full blocks requires two requests. Use HeaderByHash
// if you don't need all transactions or uncle headers.
func (ec *Client) BlockByHash(ctx context.Context, hash common.Hash, inclTx bool) (*types.Block, int, error) {
	return ec.getBlock(ctx, "cph_getTxBlockByHash", hash, inclTx, true)
}

// BlockByNumber returns a block from the current canonical chain. If number is nil, the
// latest known block is returned.
//
// Note that loading full blocks requires two requests. Use HeaderByNumber
// if you don't need all transactions .
func (ec *Client) BlockByNumber(ctx context.Context, number *big.Int, inclTx bool) (*types.Block, int, error) {
	return ec.getBlock(ctx, "cph_getTxBlockByNumber", toBlockNumArg(number), inclTx, true)
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
}

type rpcTransactionNumber struct {
	TxN int `json:"txN"`
}

func (ec *Client) getBlock(ctx context.Context, method string, args ...interface{}) (*types.Block, int, error) {
	log.Info("getBlock...")
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, 0, err
	} else if len(raw) == 0 {
		return nil, 0, cypherI.NotFound
	}

	// Decode header and transactions.
	var head *types.Header
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, 0, err
	}

	inclTx := args[1].(bool)
	if !inclTx {
		var txN rpcTransactionNumber
		if err := json.Unmarshal(raw, &txN); err != nil {
			return nil, 0, err
		}

		return types.NewBlockWithHeader(head), txN.TxN, nil
	}

	var body rpcBlock
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, 0, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, 0, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, 0, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}

	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		if tx.From != nil {
			setSenderFromServer(tx.tx, *tx.From, body.Hash)
		}
		txs[i] = tx.tx
	}
	return types.NewBlockWithHeader(head).WithBody(txs), len(txs), nil
}

func (ec *Client) BlockHeadersByNumbers(ctx context.Context, numbers []int64) ([]*types.Header, []int, error) {
	heads := make([]*types.Header, 0)
	txNs := make([]int, 0)
	raws := make([]json.RawMessage, len(numbers))

	err := ec.c.CallContext(ctx, &raws, "cph_getTxBlockHeadersByNumbers", numbers)
	if err != nil {
		return heads, txNs, cypherI.NotFound
	}

	for _, r := range raws {
		var head *types.Header
		if err := json.Unmarshal(r, &head); err != nil {
			fmt.Printf("unmarshal head error %v\n", err)
			break
		} else {
			heads = append(heads, head)
		}

		var txN rpcTransactionNumber
		if err := json.Unmarshal(r, &txN); err != nil {
			fmt.Printf("unmarshal raw error %v\n", err)
			break
		} else {
			txNs = append(txNs, txN.TxN)
		}
	}

	return heads, txNs, err
}

// HeaderByHash returns the block header with the given hash.
func (ec *Client) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "cph_getTxBlockByHash", hash, false)
	if err == nil && head == nil {
		err = cypherI.NotFound
	}
	return head, err
}

// HeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (ec *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "cph_getTxBlockByNumber", toBlockNumArg(number), false)
	if err == nil && head == nil {
		err = cypherI.NotFound
	}
	return head, err
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

// TransactionByHash returns the transaction with the given hash.
func (ec *Client) TransactionByHash(ctx context.Context, hash common.Hash) (tx *types.Transaction, isPending bool, err error) {
	var json *rpcTransaction
	err = ec.c.CallContext(ctx, &json, "cph_getTransactionByHash", hash)
	if err != nil {
		return nil, false, err
	} else if json == nil {
		return nil, false, cypherI.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, false, fmt.Errorf("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, json.BlockNumber == nil, nil
}

// TransactionSender returns the sender address of the given transaction. The transaction
// must be known to the remote node and included in the blockchain at the given block and
// index. The sender is the one derived by the protocol at the time of inclusion.
//
// There is a fast-path for transactions retrieved by TransactionByHash and
// TransactionInBlock. Getting their sender address can be done without an RPC interaction.
func (ec *Client) TransactionSender(ctx context.Context, tx *types.Transaction, block common.Hash, index uint) (common.Address, error) {
	// Try to load the address from the cache.
	sender, err := types.Sender(&senderFromServer{blockhash: block}, tx)
	if err == nil {
		return sender, nil
	}
	var meta struct {
		Hash common.Hash
		From common.Address
	}
	if err = ec.c.CallContext(ctx, &meta, "cph_getTransactionByBlockHashAndIndex", block, hexutil.Uint64(index)); err != nil {
		return common.Address{}, err
	}
	if meta.Hash == (common.Hash{}) || meta.Hash != tx.Hash() {
		return common.Address{}, errors.New("wrong inclusion block/index")
	}
	return meta.From, nil
}

// TransactionCount returns the total number of transactions in the given block.
func (ec *Client) TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "cph_getBlockTransactionCountByHash", blockHash)
	return uint(num), err
}

// TransactionInBlock returns a single transaction at index in the given block.
func (ec *Client) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	var json *rpcTransaction
	err := ec.c.CallContext(ctx, &json, "cph_getTransactionByBlockHashAndIndex", blockHash, hexutil.Uint64(index))
	if err == nil {
		if json == nil {
			return nil, cypherI.NotFound
		} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
			return nil, fmt.Errorf("server returned transaction without signature")
		}
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, err
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (ec *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var r *types.Receipt
	err := ec.c.CallContext(ctx, &r, "cph_getTransactionReceipt", txHash)
	if err == nil {
		if r == nil {
			return nil, cypherI.NotFound
		}
	}
	return r, err
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

type rpcProgress struct {
	StartingKeyBlock hexutil.Uint64
	CurrentKeyBlock  hexutil.Uint64
	HighestKeyBlock  hexutil.Uint64

	StartingTxBlock hexutil.Uint64
	CurrentTxBlock  hexutil.Uint64
	HighestTxBlock  hexutil.Uint64
	PulledTxStates  hexutil.Uint64
	KnownTxStates   hexutil.Uint64
}

// SyncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (ec *Client) SyncProgress(ctx context.Context) (*cypherI.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, "cph_syncing"); err != nil {
		return nil, err
	}
	// Handle the possible response types
	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}
	var progress *rpcProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		return nil, err
	}
	return &cypherI.SyncProgress{
		StartingKeyBlock: uint64(progress.StartingKeyBlock),
		CurrentKeyBlock:  uint64(progress.CurrentKeyBlock),
		HighestKeyBlock:  uint64(progress.HighestKeyBlock),

		StartingTxBlock: uint64(progress.StartingTxBlock),
		CurrentTxBlock:  uint64(progress.CurrentTxBlock),
		HighestTxBlock:  uint64(progress.HighestTxBlock),
		PulledTxStates:  uint64(progress.PulledTxStates),
		KnownTxStates:   uint64(progress.KnownTxStates),
	}, nil
}

// SubscribeNewHead subscribes to notifications about the current blockchain head
// on the given channel.
func (ec *Client) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (cypherI.Subscription, error) {
	return ec.c.CphSubscribe(ctx, ch, "newHeads")
}

// SubscribeNewKeyHead subscribes to notifications about the current blockchain head
// on the given channel.
func (ec *Client) SubscribeNewKeyHead(ctx context.Context, ch chan<- *types.KeyBlockHeader) (cypherI.Subscription, error) {
	return ec.c.CphSubscribe(ctx, ch, "newKeyHeads")
}

// SubscribeTPSUpdate subscribes to notifications about the latest TPS
// on the given channel.
func (ec *Client) SubscribeLatestTPS(ctx context.Context, ch chan<- uint64) (cypherI.Subscription, error) {
	return ec.c.CphSubscribe(ctx, ch, "latestTPS")
}

// State Access

// NetworkID returns the network ID (also known as the chain ID) for this chain.
func (ec *Client) NetworkID(ctx context.Context) (*big.Int, error) {
	version := new(big.Int)
	var ver string
	if err := ec.c.CallContext(ctx, &ver, "net_version"); err != nil {
		return nil, err
	}
	if _, ok := version.SetString(ver, 10); !ok {
		return nil, fmt.Errorf("invalid net_version result %q", ver)
	}
	return version, nil
}

// BalanceAt returns the wei balance of the given account.
// The block number can be nil, in which case the balance is taken from the latest known block.
func (ec *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "cph_getBalance", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

// StorageAt returns the value of key in the contract storage of the given account.
// The block number can be nil, in which case the value is taken from the latest known block.
func (ec *Client) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "cph_getStorageAt", account, key, toBlockNumArg(blockNumber))
	return result, err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (ec *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "cph_getCode", account, toBlockNumArg(blockNumber))
	return result, err
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
func (ec *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "cph_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// Filters

// FilterLogs executes a filter query.
func (ec *Client) FilterLogs(ctx context.Context, q cypherI.FilterQuery) ([]types.Log, error) {
	var result []types.Log
	err := ec.c.CallContext(ctx, &result, "cph_getLogs", toFilterArg(q))
	return result, err
}

// SubscribeFilterLogs subscribes to the results of a streaming filter query.
func (ec *Client) SubscribeFilterLogs(ctx context.Context, q cypherI.FilterQuery, ch chan<- types.Log) (cypherI.Subscription, error) {
	return ec.c.CphSubscribe(ctx, ch, "logs", toFilterArg(q))
}

func toFilterArg(q cypherI.FilterQuery) interface{} {
	arg := map[string]interface{}{
		"fromBlock": toBlockNumArg(q.FromBlock),
		"toBlock":   toBlockNumArg(q.ToBlock),
		"address":   q.Addresses,
		"topics":    q.Topics,
	}
	if q.FromBlock == nil {
		arg["fromBlock"] = "0x0"
	}
	return arg
}

// Pending State

// PendingBalanceAt returns the wei balance of the given account in the pending state.
func (ec *Client) PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "cph_getBalance", account, "pending")
	return (*big.Int)(&result), err
}

// PendingStorageAt returns the value of key in the contract storage of the given account in the pending state.
func (ec *Client) PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "cph_getStorageAt", account, key, "pending")
	return result, err
}

// PendingCodeAt returns the contract code of the given account in the pending state.
func (ec *Client) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "cph_getCode", account, "pending")
	return result, err
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "cph_getTransactionCount", account, "pending")
	return uint64(result), err
}

// PendingTransactionCount returns the total number of transactions in the pending state.
func (ec *Client) PendingTransactionCount(ctx context.Context) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "cph_getBlockTransactionCountByNumber", "pending")
	return uint(num), err
}

// TODO: SubscribePendingTransactions (needs server side)

// Contract Calling

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
func (ec *Client) CallContract(ctx context.Context, msg cypherI.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "cph_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// PendingCallContract executes a message call transaction using the EVM.
// The state seen by the contract call is the pending state.
func (ec *Client) PendingCallContract(ctx context.Context, msg cypherI.CallMsg) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "cph_call", toCallArg(msg), "pending")
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "cph_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// EstimateGas tries to estimate the gas needed to execute a specific transaction based on
// the current pending state of the backend blockchain. There is no guarantee that this is
// the true gas limit requirement as other transactions may be added or removed by miners,
// but it should provide a basis for setting a reasonable default.
func (ec *Client) EstimateGas(ctx context.Context, msg cypherI.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := ec.c.CallContext(ctx, &hex, "cph_estimateGas", toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "cph_sendRawTransaction", common.ToHex(data))
}

func toCallArg(msg cypherI.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["data"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}
	return arg
}

// Note that loading full key blocks requires two requests.
func (ec *Client) KeyBlockByHash(ctx context.Context, hash common.Hash) (*types.KeyBlock, error) {
	return ec.getKeyBlock(ctx, "cph_getKeyBlockByHash", hash)
}

func (ec *Client) KeyBlockByNumber(ctx context.Context, number *big.Int) (*types.KeyBlock, error) {
	return ec.getKeyBlock(ctx, "cph_getKeyBlockByNumber", toBlockNumArg(number))
}

func (ec *Client) getKeyBlock(ctx context.Context, method string, args ...interface{}) (*types.KeyBlock, error) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, cypherI.NotFound
	}

	// Decode header and body.
	var head *types.KeyBlockHeader
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	fmt.Println("head", head)
	var body *types.KeyBlockBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	fmt.Println("body", body)
	b := types.NewKeyBlockWithHeader(head).WithBody(body.InPubKey, body.InAddress, body.OutPubKey, body.OutAddress, body.LeaderPubKey, body.LeaderAddress).WithSignatrue(body.Signatrue, body.Exceptions)

	return b, nil
}

func (ec *Client) KeyBlocksByNumbers(ctx context.Context, numbers []int64) ([]*types.KeyBlock, error) {

	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, "cph_getKeyBlocksByNumbers", numbers)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, cypherI.NotFound
	}

	heads := make([]*types.KeyBlockHeader, 3)
	if err := json.Unmarshal(raw, &heads); err != nil {
		return nil, err
	}

	blocks := make([]*types.KeyBlock, 0)
	for _, head := range heads {
		blocks = append(blocks, types.NewKeyBlockWithHeader(head))
	}

	return blocks, nil
}

func (ec *Client) RosterConfig(ctx context.Context, data interface{}) error {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, "cph_rosterConfig", data)
	return err
}
