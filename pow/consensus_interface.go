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

// Package consensus implements different Cypherium consensus engines.
package pow

import (
	"math/big"

	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/rpc"
)

// Engine is an algorithm agnostic consensus engine.
type Engine interface {

	// Seal generates a new block for the given input block with the local miner's
	// seal place on top.
	//Seal(chain ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error)

	// SealCandidate generates a new candidate with the local miner's seal place on top.
	SealCandidate(candidate *types.Candidate, stop <-chan struct{}) (*types.Candidate, error)

	// VerifyCandidate checks whether the crypto seal on a candidate is valid according to
	// the consensus rules of the given engine.
	VerifyCandidate(chain types.KeyChainReader, candidate *types.Candidate) error

	// Prepare initializes the consensus fields of a candidate according to the
	// rules of a particular engine. The changes are executed inline.
	PrepareCandidate(chain types.KeyChainReader, candidate *types.Candidate, CommitteeSize int) error

	// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
	// that a new block should have.
	//CalcDifficulty(chain ChainReader, time uint64, parent *types.Header) *big.Int

	// APIs returns the RPC APIs this consensus engine provides.
	APIs(chain types.ChainReader) []rpc.API

	CalcKeyBlockDifficulty(chain types.KeyChainReader, time uint64, parent *types.KeyBlockHeader) *big.Int
	PowMode() uint
	PowRangeMode() uint
	ReleaseVM()
}

// PoW is a consensus engine based on proof-of-work.
type PoW interface {
	Engine

	// Hashrate returns the current mining hashrate of a PoW consensus engine.
	Hashrate() float64
}
