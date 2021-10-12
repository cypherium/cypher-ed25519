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

package params

import (
	"errors"
	"time"
)

// These are network parameters that need to be constant between clients, but
// aren't necesarilly consensus related.

const (
	// BloomBitsBlocks is the number of blocks a single bloom bit section vector
	// contains.
	BloomBitsBlocks uint64 = 4096
)

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
var (
	MainnetBootnodes = []string{
		"cnode://377333498fe00b675b710beee2cdf2c5d8235b056cd7a98fcd65763a01d8e5a5d796c7bc43c67486ce96b27aed2f31431e015ef9ecb46bccbe03ae28376ea41d@54.244.144.111:7100", // IE
	}
	TestnetBootnodes = []string{
		"cnode://30b7ab30a01c124a6cceca36863ece12c4f5fa68e3ba9b0b51407ccc002eeed3b3102d20a88f1c1d3c3154e2449317b8ef95090e77b312d5cc39354f86d5d606@52.176.7.10:30303", // US-Azure cypher
	}
	RinkebyBootnodes = []string{
		"cnode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30303", // IE
	}
	DiscoveryV5Bootnodes = []string{
		"cnode://06051a5573c81934c9554ef2898eb13b33a34b94cf36b202b69fde139ca17a85051979867720d4bdae4323d4943ddf9aeeb6643633aa656e0be843659795007a@35.177.226.168:30303",
	}
)

var SendOverFlowErr = errors.New("Network send queue overflow!")

const (
	MaxSendBlocks    = 5
	SendErrReTryTime = 60 * time.Second
	// HelperTrieConfirmations is the number of confirmations before a client is expected
	// to have the given HelperTrie available.
	HelperTrieConfirmations = 2048

	// HelperTrieProcessConfirmations is the number of confirmations before a HelperTrie
	// is generated
	HelperTrieProcessConfirmations = 256

	// CheckpointFrequency is the block frequency for creating checkpoint
	CheckpointFrequency = 32768

	// CheckpointProcessConfirmations is the number before a checkpoint is generated
	CheckpointProcessConfirmations = 256
	FullImmutabilityThreshold = 90000
)
