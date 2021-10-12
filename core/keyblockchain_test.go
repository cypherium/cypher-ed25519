package core

import (
	"github.com/cypherium/cypherBFT/core/rawdb"
	"github.com/cypherium/cypherBFT/ethdb"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/pow"
	"github.com/cypherium/cypherBFT/pow/ethash"
	"testing"
)

// newKeyBlockChain creates a chain database, and injects a deterministic key block
// chain.
func newKeyBlockChain(engine pow.Engine, n int) (ethdb.Database, *KeyBlockChain, error) {
	var (
		db      = ethdb.NewMemDatabase()
		genesis = new(GenesisKey).MustCommit(db)
	)

	// Initialize a fresh chain with only a genesis block
	blockchain, _ := NewKeyBlockChain(db, nil, params.AllEthashProtocolChanges, engine)
	// Create and inject the requested chain
	if n == 0 {
		return db, blockchain, nil
	}

	blocks := makeKeyBlockChain(genesis, n, engine, db, canonicalSeed)
	_, err := blockchain.InsertChain(nil, blocks)
	return db, blockchain, err
}

func TestLastKeyBlock(t *testing.T) {
	var (
		BLOCK_NUM = 5
	)

	_, blockchain, err := newKeyBlockChain(ethash.NewFaker(), 0)
	if err != nil {
		t.Fatalf("failed to create key block chain: %v", err)
	}
	defer blockchain.Stop()

	blocks := makeKeyBlockChain(blockchain.CurrentBlock(), BLOCK_NUM, ethash.NewFullFaker(), blockchain.db, 0)
	if _, err := blockchain.InsertChain(nil, blocks); err != nil {
		t.Fatalf("Failed to insert block: %v", err)
	}
	if blocks[len(blocks)-1].Hash() != rawdb.ReadHeadKeyBlockHash(blockchain.db) {
		t.Fatalf("Write/Get HeadBlockHash failed")
	}

	// Test reading keyblock height
	height := rawdb.ReadKeyHeaderNumber(blockchain.db, rawdb.ReadHeadKeyHeaderHash(blockchain.db))
	if height == nil {
		t.Fatalf("Missing block number for head key block hash")
	}
	if *height != uint64(BLOCK_NUM) {
		t.Fatalf("block number should be equal to 5")
	}

	// Test get current key block header
	currentHeader := blockchain.CurrentHeader()
	if currentHeader.Hash() != blocks[len(blocks)-1].Header().Hash() {
		t.Fatalf("CurrentHeader failed")
	}

	block := blockchain.GetBlockByNumber(2)
	if block == nil || block.NumberU64() != 2 {
		t.Fatalf("GetBlockByNumber failed")
	}

	rlpBlock := blockchain.GetBlockRLPByNumber(5)
	if rlpBlock == nil {
		t.Fatalf("GetBlockRLPByNumber failed")
	}

	header := blockchain.GetHeaderByHash(block.Header().Hash())
	if header == nil || header.Hash() != block.Header().Hash() {
		t.Fatalf("GetHeaderByHash failed")
	}

	td_2 := blockchain.GetTd(block.Header().Hash(), 2)
	if td_2.Uint64() != block.Difficulty().Uint64() {
		t.Fatalf("GetTd failed")
	}

	block = blockchain.GetBlock(blocks[1].Hash(), 2)
	if block == nil || block.Hash() != blocks[1].Hash() {
		t.Fatalf("GetBlock failed")
	}

	header = blockchain.GetHeaderByNumber(2)
	if header == nil || header.Hash() != blocks[1].Header().Hash() {
		t.Fatalf("GetHeaderByNumber failed")
	}

	header = blockchain.GetHeader(blocks[1].Hash(), 2)
	if header == nil || header.Hash() != blocks[1].Header().Hash() {
		t.Fatalf("GetHeader failed")
	}

	block = blockchain.GetBlockByHash(blocks[1].Hash())
	if block == nil || block.Hash() != blocks[1].Hash() {
		t.Fatalf("GetBlockByHash failed")
	}

}
