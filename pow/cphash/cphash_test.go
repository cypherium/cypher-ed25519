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

package cphash

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/core/types"
)

// Tests that cphash works correctly in test mode.
func TestTestMode(t *testing.T) {
	etHash := NewTester()
	etHash.SetThreads(1)

	keyHead := &types.KeyBlockHeader{
		Number:     big1,
		Time:       big.NewInt(time.Now().UnixNano()),
		Difficulty: big.NewInt(int64(0x87e7c4)),
	}

	time.Sleep(time.Second * 20)

	for i := 0; i < 10; i++ {
		candidate := types.NewCandidate(
			common.Hash{},
			big.NewInt(int64(0xFFFFF)),
			uint64(keyHead.Number.Uint64()+1),
			"",
			net.IPv4(192, 168, 0, 1),
			"",
			3000,
		)

		candidate.KeyCandidate.Difficulty = calcCandidateDifficulty(candidate.KeyCandidate.Time.Uint64(), keyHead)

		start := time.Now()
		candidate, err := etHash.SealCandidate(candidate, make(chan struct{}))
		if err != nil {
			t.Fatalf("failed to seal candidate: %v", err)
		}
		if err := etHash.VerifyCandidate(nil, candidate); err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}

		fmt.Printf("Seal candidate time elapsed: %s, difficulty: %d, number: %d\n\r", time.Since(start), candidate.KeyCandidate.Difficulty.Uint64(), candidate.KeyCandidate.Number.Uint64())

		keyHead = &types.KeyBlockHeader{
			Number:     candidate.KeyCandidate.Number,
			Time:       candidate.KeyCandidate.Time,
			Difficulty: candidate.KeyCandidate.Difficulty,
		}
	}

}

// This test checks that cache lru logic doesn't crash under load.
// It reproduces https://github.com/cypherium/cypherBFT/issues/14943
func TestCacheFileEvict(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "cphash-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	e := New(Config{CachesInMem: 3, CachesOnDisk: 10, CacheDir: tmpdir, PowMode: ModeTest})

	workers := 8
	epochs := 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go verifyTest(&wg, e, i, epochs)
	}
	wg.Wait()
}

func verifyTest(wg *sync.WaitGroup, e *Cphash, workerIndex, epochs int) {
	defer wg.Done()

	const wiggle = 4 * epochLength
	r := rand.New(rand.NewSource(int64(workerIndex)))
	for epoch := 0; epoch < epochs; epoch++ {
		block := int64(epoch)*epochLength - wiggle/2 + r.Int63n(wiggle)
		if block < 0 {
			block = 0
		}
		candidate := types.NewCandidate(
			common.Hash{},
			big.NewInt(int64(100)),
			uint64(block),
			"",
			net.IPv4(192, 168, 0, 1),
			"",
			3000,
		)
		e.VerifyCandidate(nil, candidate)
	}
}
