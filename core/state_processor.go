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

package core

import (
	"math"
	"sync"
	"sync/atomic"

	"github.com/cypherium/cypherBFT/core/state"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/core/vm"
	"github.com/cypherium/cypherBFT/crypto"
	"github.com/cypherium/cypherBFT/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config        *params.ChainConfig // Chain configuration options
	bc            *BlockChain         // Canonical block chain
	keyblockchain *KeyBlockChain
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, kbc *KeyBlockChain) *StateProcessor {
	return &StateProcessor{
		config:        config,
		bc:            bc,
		keyblockchain: kbc,
	}
}

// Process processes the state changes according to the Cypherium rules by running
// the transaction messages using the statedb and applying any rewards to both
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	// Iterate over and process the individual transactions
	txs := block.Transactions()
	ntxs := len(txs)
	messages := make(map[int]Message)
	n := int(math.Round(float64(ntxs) / 4))
	if n > 30 {
		var hasError int32
		var wgMu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			i0 := i * n
			i1 := i0 + n
			if i == 3 {
				i1 = ntxs - 1
			}
			wg.Add(1)
			go func(i0, i1 int) {
				for j := i0; j < i1; j++ {
					hasErr := atomic.LoadInt32(&hasError)
					if hasErr > 0 {
						wg.Done()
						return
					}

					msg, err := txs[j].AsMessage(types.MakeSigner(p.config, header.Number))
					if err != nil {
						atomic.StoreInt32(&hasError, 1)
						wg.Done()
						return
					}
					wgMu.Lock()
					messages[j] = msg
					wgMu.Unlock()
				}
				wg.Done()
			}(i0, i1)
		}
		wg.Wait()
	} else {
		for i, tx := range txs {
			msg, err := tx.AsMessage(types.MakeSigner(p.config, header.Number))
			if err != nil {
				return nil, nil, 0, err
			}
			messages[i] = msg
		}
	}

	for i, tx := range txs {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, _, err := ApplyTransaction(false, messages[i], p.keyblockchain, p.config, p.bc, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	p.Finalize(true, header, statedb, txs, receipts)

	return receipts, allLogs, *usedGas, nil
}

func (p *StateProcessor) Finalize(onlyCheck bool, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate any block and uncle rewards and commit the final state root
	//accumulateRewards(keyChain,  p.bc.Config(), state, header)
	//if header.BlockType == types.IsKeyBlockType {
	//	RewardCommites(p.bc, state, header, KeyBlock_Reward)
	//} else
	{
		if !params.DisableGAS {
			var totalGas uint64
			for _, r := range receipts {
				totalGas += r.GasUsed
			}
			RewardCommites(p.bc, state, header, totalGas)
		} else {
			//	RewardCommites(p.bc, state, header, params.TxBlock_Reward)
		}
	}
	header.Root = state.IntermediateRoot()
	// Header seems complete, assemble into a block and return
	if onlyCheck {
		return nil, nil
	}
	return types.NewBlock(header, txs, receipts), nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(onlyGas bool, msg Message, keyChain types.KeyChainReader, config *params.ChainConfig, bc types.ChainReader, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, uint64, error) {

	if msg == nil {
		var err error
		msg, err = tx.AsMessage(types.MakeSigner(config, header.Number))
		if err != nil {
			return nil, 0, err
		}

	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg, bc)
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(onlyGas, header, vmenv, msg, gp)
	if err != nil {
		return nil, 0, err
	}
	// Update the state with pending changes
	root := statedb.IntermediateRoot().Bytes()
	*usedGas += gas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())

	return receipt, gas, err
}
