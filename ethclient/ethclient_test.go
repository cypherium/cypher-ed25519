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

package ethclient

import "github.com/cypherium/cypherBFT/cypherI"

// Verify that Client implements the cypherium interfaces.
var (
	_ = cypherI.ChainReader(&Client{})
	_ = cypherI.TransactionReader(&Client{})
	_ = cypherI.ChainStateReader(&Client{})
	_ = cypherI.ChainSyncReader(&Client{})
	_ = cypherI.ContractCaller(&Client{})
	_ = cypherI.GasEstimator(&Client{})
	_ = cypherI.GasPricer(&Client{})
	_ = cypherI.LogFilterer(&Client{})
	_ = cypherI.PendingStateReader(&Client{})
	// _ = cypherI.PendingStateEventer(&Client{})
	_ = cypherI.PendingContractCaller(&Client{})
)
