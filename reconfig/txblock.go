// Package reconfig implements Cypherium reconfiguration.
package reconfig

import (
	"fmt"
	"math/big"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/core/state"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/core/vm"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
)

type txService struct {
	s      serviceI
	txPool *core.TxPool
	bc     *core.BlockChain
	kbc    *core.KeyBlockChain
	config *params.ChainConfig
}

func newTxService(s serviceI, cph Backend, config *params.ChainConfig) *txService {
	txS := new(txService)
	txS.s = s
	txS.bc = cph.BlockChain()
	txS.kbc = cph.KeyBlockChain()
	txS.txPool = cph.TxPool()
	txS.config = config
	txS.bc.ProcInsertDone = txS.procBlockDone
	return txS
}

// new Txblock done
func (txS *txService) procBlockDone(block *types.Block) { //callback by tx insertchain)
	log.Info("procBlockDone", "number", block.NumberU64())
	s := txS.s
	s.updateCommittee(nil)
	//log.Trace("procBlockDone.updateCurrentView", "number", block.NumberU64())
	s.updateCurrentView(false)
	//log.Trace("procBlockDone.pace", "number", block.NumberU64())
	s.procBlockDone(block, nil)
	//log.Trace("procBlockDone.end")
}

// Try proposal new txBlock for current txs
func (txS *txService) tryProposalNewBlock(blockType uint8) ([]byte, error) {
	txsCount := txS.txPool.PendingCount()
	if txsCount < 1 {
		return nil, fmt.Errorf("no tx in txpool")
	}

	//timeused := time.Now().Sub(txS.lastProposeTime).Nanoseconds()
	//if txsCount < 100 && timeused < 400000000 { //avoid frequent propose
	//	return nil, fmt.Errorf("frequent propose")
	//}

	block := txS.packageTxs(blockType)
	if block == nil {
		return nil, fmt.Errorf("package tx error")
	}
	return block.EncodeToBytes(), nil
}

// Verify txBlock
func (txS *txService) verifyTxBlock(txblock *types.Block) error {
	var retErr error
	/*
		defer func() {
			if retErr == nil {
				//insert chain
				//??	go s.bc.InsertBlockWithNoSignature(txblock)
			}
		}()
	*/
	bc := txS.bc
	kbc := txS.kbc
	blockNum := txblock.NumberU64()
	header := txblock.Header()
	log.Info("verifyTxBlock", "txblock num", blockNum)

	if blockNum <= bc.CurrentBlockN() {
		retErr = fmt.Errorf("invalid header, number:%d, current block number:%d", blockNum, bc.CurrentBlockN())
		return retErr
	}
	if header.KeyHash != kbc.CurrentBlock().Hash() {
		retErr = fmt.Errorf("keyhash:%x does not match current keyhash: %x", header.KeyHash, kbc.CurrentBlock().Hash())
		return retErr
	}
	if bftview.IamLeader(txS.s.GetCurrentView().LeaderIndex) {
		return nil
	}
	err := bc.Validator.VerifyHeader(header)
	if err != nil {
		retErr = fmt.Errorf("invalid header, error:%s", err.Error())
		return retErr
	}

	err = bc.Validator.ValidateBody(txblock)
	if err == types.ErrFutureBlock || err == types.ErrUnknownAncestor || err == types.ErrPrunedAncestor {
		retErr = fmt.Errorf("invalid body, error:%s", err.Error())
		return retErr
	}

	statedb, err := bc.State()
	if err != nil {
		retErr = fmt.Errorf("cannot get statedb, error:%s", err.Error())
		return retErr
	}
	receipts, _, usedGas, err := bc.Processor.Process(txblock, statedb, vm.Config{})
	if err != nil {
		retErr = fmt.Errorf("cannot get receipts, error:%s", err.Error())
		return retErr
	}
	err = bc.Validator.ValidateState(txblock, bc.GetBlockByHash(txblock.ParentHash()), statedb, receipts, usedGas)
	if err != nil {
		retErr = fmt.Errorf("Invalid state, error:%s", err.Error())
		return retErr
	}

	bc.VerifyCaches.Push(txblock, statedb, receipts, usedGas)

	return nil
}

// New txBlock done, when consensus agreement completed
func (txS *txService) decideNewBlock(block *types.Block, sig []byte, mask []byte) error {
	log.Info("decideNewBlock", "TxBlock Number", block.NumberU64(), "txs", len(block.Transactions()))
	bc := txS.bc
	if bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return nil
	}
	block.SetSignature(sig, mask)
	err := bc.InsertBlock(block)
	if err != nil {
		log.Error("decideNewBlock", "error", err)
		return err
	}
	log.Info("decideNewBlock InsertBlock ok")
	return nil
}

// Package txs
func (txS *txService) packageTxs(blockType uint8) *types.Block {
	bc := txS.bc
	parent := bc.CurrentBlock()
	state, err := bc.StateAt(parent.Root())
	if err != nil {
		log.Error("packageTxs", "Failed to get chain root state", err)
		return nil
	}
	header := packageHeader(txS.kbc.CurrentBlock().Hash(), parent, state, blockType)

	pending, err1 := bc.TxPool.Pending()
	if err1 != nil || len(pending) == 0 {
		log.Error("packageTxs", "Failed to fetch pending transactions", err)
		return nil
	}

	signer := types.NewEIP155Signer(txS.config.ChainID)
	txs := types.NewTransactionsByPriceAndNonce(signer, pending)
	okTxs, receipts, useGas := txS.commitTransactions(signer, txs, header, state)
	tcount := len(okTxs)
	if tcount == 0 {
		log.Error("packageTxs okTxs is empty")
		return nil
	}

	block, err := bc.Processor.Finalize(false, header, state, okTxs, receipts)
	if err != nil {
		log.Error("packageTxs", "Failed to finalize block for sealing", err)
		return nil
	}

	bc.VerifyCaches.Push(block, state, receipts, useGas)

	log.Info("packageTxs", "OK, TxBlock Number=", block.NumberU64())
	return block
}

// Package header of block
func packageHeader(keyHash common.Hash, parent *types.Block, state *state.StateDB, blockType uint8) *types.Header {
	now := time.Now()
	log.Info("packageHeader", "parent number=", parent.NumberU64())

	//d, _ := time.ParseDuration("-24h")
	//now = now.Add(2 * d)

	tstamp := now.UnixNano() //int64(1604127144173089000) //
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {
		tstamp = parent.Time().Int64() + 1
	}
	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		KeyHash:    keyHash,
		Number:     num.Add(num, common.Big1),
		BlockType:  blockType,
		GasLimit:   core.CalcGasLimit(parent),
		GasUsed:    0,
		Extra:      nil,
		Time:       big.NewInt(tstamp),
	}
	return header
}

// Apply transactions
func (txS *txService) commitTransactions(signer types.Signer, txs *types.TransactionsByPriceAndNonce, header *types.Header, state *state.StateDB) (types.Transactions, []*types.Receipt, uint64) {
	var (
		useGas uint64
		//	coalescedLogs []*types.Log
		failedTxs types.Transactions
		okTxs     types.Transactions
		receipts  []*types.Receipt
	)
	bc := txS.bc
	kbc := txS.kbc
	gp := new(core.GasPool).AddGas(header.GasLimit)
	tcount := 0

	for {
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(signer, tx)
		// Start executing the transaction
		state.Prepare(tx.Hash(), common.Hash{}, tcount)
		//commitTX
		snap := state.Snapshot()
		receipt, gas, err := core.ApplyTransaction(true, nil, kbc, txS.config, bc, gp, state, header, tx, &header.GasUsed, bc.VmConfig)
		if err != nil {
			state.RevertToSnapshot(snap)
			switch err {
			case types.ErrGasLimitReached:
				// Pop the current out-of-gas transaction without shifting in the next from the account
				log.Warn("Gas limit exceeded for current block", "sender", from)
				//break
				//failedTxs = append(failedTxs, tx)
				txs.Pop()
			case types.ErrNonceTooHigh:
				txs.Pop()
			default:
				// Pop the current failed transaction without shifting in the next from the account
				log.Trace("Transaction failed, will be removed", "hash", tx.Hash(), "err", err)
				failedTxs = append(failedTxs, tx)
				txs.Pop()
			}
		} else {
			okTxs = append(okTxs, tx) //??
			receipts = append(receipts, receipt)
			//??coalescedLogs = append(coalescedLogs, receipt.Logs...)
			useGas += gas
			tcount++
			if tcount > params.MaxTxCountPerBlock {
				break
			}
			txs.Shift()
		}
	}

	if len(failedTxs) > 0 {
		txS.txPool.RemoveBatch(failedTxs)
	}
	/*
		if len(coalescedLogs) > 0 || tcount > 0 {
			// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
			// logs by filling in the block hash when the block was mined by the local miner. This can
			// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
			cpy := make([]*types.Log, len(coalescedLogs))
			for i, l := range coalescedLogs {
				cpy[i] = new(types.Log)
				*cpy[i] = *l
			}
			go func(logs []*types.Log, tcount int) {
				if len(logs) > 0 {
					mux.Post(core.PendingLogsEvent{Logs: logs})
				}
				if tcount > 0 {
					mux.Post(core.PendingStateEvent{})
				}
			}(cpy, tcount)
		}
	*/
	return okTxs, receipts, useGas
}
