// Copyright 2014 The cypherBFT Authors
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
	"errors"
	"math/big"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/core/vm"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
	"github.com/cypherium/cypherBFT/reconfig/hotstuff"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	gas := params.TxGas //params.TxGasContractCreation
	// Bump the required gas by the amount of transactional data
	gas += uint64(len(data)) * params.TxDataGas
	/*
		if len(data) > 0 {
			// Zero and non-zero bytes are priced differently
			var nz uint64
			for _, byt := range data {
				if byt != 0 {
					nz++
				}
			}
			// Make sure we don't exceed uint64 for all data combinations
			if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
				log.Error("IntrinsicGas out of gas..1")
				return 0, vm.ErrOutOfGas
			}
			gas += nz * params.TxDataNonZeroGas

			z := uint64(len(data)) - nz
			if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
				log.Error("IntrinsicGas out of gas..2")
				return 0, vm.ErrOutOfGas
			}
			gas += z * params.TxDataZeroGas
		}
	*/
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:       gp,
		evm:      evm,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(onlyGas bool, header *types.Header, evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb(onlyGas, header)
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) useGas(amount uint64) error {
	if params.DisableGAS {
		return nil
	}
	if st.gas < amount {
		log.Error("useGas out of gas", "st.gas", st.gas, "amount", amount)
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	if params.DisableGAS {
		return nil
	}
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	if st.state.GetBalance(st.msg.From()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	st.state.SubBalance(st.msg.From(), mgval) //??
	return nil
}

func (st *StateTransition) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return types.ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the the used gas. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionDb(onlyGas bool, header *types.Header) (ret []byte, usedGas uint64, failed bool, err error) {
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	sender := vm.AccountRef(msg.From())
	contractCreation := msg.To() == nil

	if !params.DisableGAS {
		// Pay intrinsic gas
		gas, err := IntrinsicGas(st.data, contractCreation)
		if err != nil {
			return nil, 0, false, err
		}
		if err = st.useGas(gas); err != nil {
			return nil, 0, false, err
		}
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	//?? if onlyGas {}
	//?? If only calculate the gas, it can optimized, it canuse other methods to get gas of the smart contract creation
	if contractCreation {
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		nonce := st.state.GetNonce(sender.Address()) + 1
		//st.evm.Chain.(BlockChain).TxPool.LogTxMsg("TransitionDb", "nonce", nonce)
		st.state.SetNonce(msg.From(), nonce)
		ret, st.gas, vmerr = evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		//if vmerr == vm.ErrInsufficientBalance
		{
			return nil, 0, false, vmerr
		}
	}
	st.refundGas()

	return ret, st.gasUsed(), vmerr != nil, err
}

func RewardCommites(bc types.ChainReader, state vm.StateDB, header *types.Header, blockReward uint64) {
	bRewardAll := false
	//if header.BlockType == types.IsKeyBlockType {
	//		bRewardAll = true
	//}
	//log.Info("RewardCommites", "blockReward", blockReward)
	if blockReward == 0 {
		return
	}
	pBlock := bc.GetBlock(header.ParentHash, header.Number.Uint64()-1)
	if pBlock == nil {
		log.Error("RewardCommites", "not found parent header hash", header.ParentHash)
		return
	}
	keyHash := pBlock.GetKeyHash()
	if header.KeyHash != keyHash {
		kheader := bc.GetKeyChainReader().GetHeaderByHash(header.KeyHash)
		if kheader.HasNewNode() {
			kNumber := kheader.NumberU64()
			cnodes := bc.GetKeyChainReader().GetCommitteeByNumber(kNumber)
			if cnodes == nil {
				log.Error("RewardCommites", "not found committee keyNumber", kNumber)
				return
			}
			c := &bftview.Committee{List: cnodes}
			state.AddBalance(common.HexToAddress(c.In().CoinBase), big.NewInt(params.KeyBlock_Reward))
		}
	}

	kheader := bc.GetKeyChainReader().GetHeaderByHash(keyHash)
	if kheader == nil {
		log.Error("RewardCommites", "not found key hash", keyHash)
		return
	}
	kNumber := kheader.NumberU64()
	cnodes := bc.GetKeyChainReader().GetCommitteeByNumber(kNumber)
	if cnodes == nil {
		log.Error("RewardCommites", "not found committee keyNumber", kNumber)
		return
	}
	var addresses []common.Address
	if bRewardAll {
		for _, r := range cnodes {
			addresses = append(addresses, common.HexToAddress(r.CoinBase))
		}
	} else {
		mycommittee := &bftview.Committee{List: cnodes}
		pubs := mycommittee.ToBlsPublicKeys(keyHash)
		exceptions := hotstuff.MaskToException(pBlock.Exceptions(), pubs)
		for i, pub := range pubs {
			isException := false
			for _, exp := range exceptions {
				if exp.IsEqual(pub) {
					isException = true
					break
				}
			}

			if !isException {
				//address := crypto.PubKeyToAddressCypherium(publicKey)
				addr := mycommittee.List[i].CoinBase
				//log.Info("Rewards", "address", addr)
				//if len(addr) > 16 {
				addresses = append(addresses, common.HexToAddress(addr))
				//}
			}
		}
	}
	n := len(addresses)
	if n < 4 {
		return
	}

	average := blockReward / uint64(n)
	bigAverage := big.NewInt(int64(average))
	//log.Info("Rewards", "BlockType", header.BlockType, "total", blockReward, "committeeCount", n, "average", average)
	for i := 0; i < n; i++ {
		if i == 0 {
			left := blockReward - average*uint64(n-1)
			//log.Info("Rewards", "leader address", addresses[i], "value", left)
			state.AddBalance(addresses[i], big.NewInt(int64(left)))
		} else {
			//log.Info("Rewards", "address", addresses[i], "average", average)
			state.AddBalance(addresses[i], bigAverage)
		}
	}
}

func (st *StateTransition) refundGas() {
	if params.DisableGAS {
		return
	}
	// Apply refund counter, capped to half of the used gas.
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return CPH for remaining gas, exchanged at the original rate.
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(st.msg.From(), remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
