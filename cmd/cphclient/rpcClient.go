// This file is used to benchmark the speed of transaction verification
// build:
// 	go to the top directory, type: make txtest, then executable file can be found in build/bin
// run:
//  ./build/bin/txtest
//
// Test results:
// Use EIP155 plus ED25519 to verify transaction signature (10000 times), time elapsed:    1.604913 seconds
// Use native ED25519 to verify transaction signature (10000 times), time elapsed:         1.554256 seconds
// Generate hash values (10000 times), time elapsed:                                       0.027268 seconds
// Use native secp256k1 to verify transaction signature (10000 times), time elapsed:       1.714036 seconds
// DeriveSHA from 1000 transactions, time elapsed:                                         0.004769 seconds

package main

import (
	"context"
	//"encoding/hex"
	"fmt"
	"github.com/cypherium/cypherBFT/common"

	"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/ethclient"
	"github.com/cypherium/cypherBFT/crypto/sha3"
	"github.com/cypherium/cypherBFT/rlp"
	"github.com/hashicorp/golang-lru"
	"math/big"

	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"
)

func DumpStruct(x interface{}) {
	s := reflect.ValueOf(x).Elem()
	typeOfT := s.Type()

	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		if f.CanInterface() {
			fmt.Printf("%d: %s %s: %v\n", i, typeOfT.Field(i).Name, typeOfT.Field(i).Type, f.Interface())
		}
	}
}

const (
	//remote = "ws://127.0.0.1:8546"
	remote = "ws://137.117.70.161:8546"
	//remote = "ws://18.237.213.2:8546"
	//remote = "ws://18.237.157.189:8546"
)

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func testCache() {
	cache, _ := lru.New(256)
	rlpBlock, _ := rlp.EncodeToBytes(remote)
	hash := rlpHash(remote)

	cache.Add(hash, rlpBlock)

	if cached, ok := cache.Get(hash); ok {
		cachedRlpBlock := cached.([]uint8)
		fmt.Println("Good Cache", len(cachedRlpBlock))
	}
}
func main() {
	client, err := ethclient.Dial(remote)
	if err != nil {
		fmt.Println("Dial failed", err)
		return
	}
	defer client.Close()

	ctx := context.Background()

	netWorkID, _ := client.NetworkID(ctx)
	fmt.Printf("Dial succeed, networkId = %d\n", netWorkID.Uint64())

	//keyBlock, err := client.KeyBlockByNumber(ctx, new(big.Int).SetInt64(0))
	//if keyBlock != nil {
	//	fmt.Printf("KeyBlockByNumber returns key block of number 0: %s\n", keyBlock.Hash().Hex())
	//} else {
	//	fmt.Println("KeyBlockByNumber returns error", err)
	//	return
	//}
	block, txN, err := client.BlockByNumber(ctx, new(big.Int).SetInt64(0), false)
	if err != nil {
		fmt.Println("BlockByNumber failed", err)
		return
	}

	fmt.Printf("BlockByNumber returns block of number 0: %s, txN = %d\n", block.Hash().Hex(), txN)

	headers, _, err := client.BlockHeadersByNumbers(ctx, []int64{1, 2, 3})
	if err != nil {
		fmt.Println("BlockHeadersByNumbers failed", err)
		return
	}

	if headers != nil {
		fmt.Println("BlockHeadersByNumbers returns", len(headers))
	}

	for i, header := range headers {
		fmt.Printf("BlockHeadersByNumbers returns header %d, hash = %s\n", i, header.Hash().Hex())
	}

	keyBlock, err := client.KeyBlockByNumber(ctx, new(big.Int).SetInt64(2))
	if keyBlock != nil {
		fmt.Printf("KeyBlockByNumber returns key block of number 10415: %s\n", keyBlock.Hash().Hex())
		fmt.Printf("KeyBlockByNumber timestamp : %d\n", keyBlock.Time().Int64())
	} else {
		fmt.Println("KeyBlockByNumber returns error", err)
		return
	}

	keyBlock, err = client.KeyBlockByHash(ctx, keyBlock.Hash())
	if keyBlock != nil {
		fmt.Printf("KeyBlockByHash returns key block: %s\n", keyBlock.Hash().Hex())

	} else {
		fmt.Println("KeyBlockByHash returns error", err)
	}

	keyBlocks, err := client.KeyBlocksByNumbers(ctx, []int64{1, 2, 3})
	if err != nil {
		fmt.Println("KeyBlocksByNumbers failed", err)
		return
	}

	if keyBlocks != nil {
		fmt.Println("KeyBlocksByNumbers returns", len(keyBlocks))

		for i, kb := range keyBlocks {
			fmt.Printf("KeyBlocksByNumbers hash %d = %s\n", i, kb.Hash().Hex())
		}
	}

	// subscribe new key block head
	keyHeadChan := make(chan *types.KeyBlockHeader)
	keyHeadSub, err := client.SubscribeNewKeyHead(ctx, keyHeadChan)

	// subscribe new block head
	headChan := make(chan *types.Header)
	headSub, err := client.SubscribeNewHead(ctx, headChan)
	if err != nil {
		fmt.Println("SubscribeNewHead failed", err)
	}

	//tpsChan := make(chan uint64)
	//tpsSub, err := client.SubscribeLatestTPS(ctx, tpsChan)
	//if err != nil {
	//	fmt.Println("SubscribeLatestTPS failed", err)
	//}

	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	fmt.Println("\n\rSubscribe new heads... \n\r")
out:
	for {
		select {
		case <-c:
			fmt.Println("\n\rCtrl+C pressed in Terminal, quit\n\r")
			break out
		//case tps := <-tpsChan:
		//	fmt.Printf("Got new tps: %d\n\r", tps)

		case newKeyHead := <-keyHeadChan:
			fmt.Printf("Got new key block head: hash = %s\n\r", newKeyHead.Hash().Hex())
			DumpStruct(newKeyHead)

		case newHead := <-headChan:
			fmt.Printf("Got new block number: %d\n\r", newHead.Number.Uint64())

			block, txN, err := client.BlockByNumber(ctx, newHead.Number, true)
			if err != nil {
				fmt.Println("BlockByNumber failed", err)
			} else {
				fmt.Printf("BlockByNumber returns block of number %d: %s, txN = %d\n", block.NumberU64(), block.Hash().Hex(), txN)
				t := block.Time().Uint64()
				fmt.Println("block time", time.Unix(0, int64(t)).Format(time.RFC3339))
			}
		}
	}

	keyHeadSub.Unsubscribe()
	headSub.Unsubscribe()
	//tpsSub.Unsubscribe()
}

func main1() {
	client, err := ethclient.Dial(remote)
	if err != nil {
		fmt.Println("Dial failed", err)
		return
	}
	defer client.Close()

	ctx := context.Background()

	netWorkID, _ := client.NetworkID(ctx)
	fmt.Printf("Dial succeed, networkId = %d\n", netWorkID.Uint64())

	balance, err := client.BalanceAt(ctx, common.HexToAddress("0x461f9d24b10edca41c1d9296f971c5c028e6c64c"), nil)
	if err != nil {
		fmt.Printf("balance :%v\n", err)
		return
	}

	fmt.Printf("balance : %s\n", balance.String())
	return

	block, _, err := client.BlockByNumber(ctx, new(big.Int).SetInt64(300), true)
	if err != nil {
		fmt.Println("BlockByNumber failed", err)
		return
	}

	fmt.Printf("Block Hash %s\n", block.Hash().String())
	fmt.Printf("Key Hash %s\n", block.Header().KeyHash.String())
	fmt.Printf("Parent Hash %s\n", block.Header().ParentHash.String())

	fmt.Printf("Transaction 0 Hash %s\n", block.Transactions()[0].Hash().String())
	fmt.Printf("Transaction Number %d\n", len(block.Transactions()))

	keyBlock, err := client.KeyBlockByNumber(ctx, new(big.Int).SetInt64(0))
	if err != nil {
		fmt.Println("Key BlockByNumber failed", err)
		return
	}

	fmt.Printf("keyBlock Hash %s\n", keyBlock.Hash().String())
	fmt.Printf("keyBlock Diff 0x%x\n", keyBlock.Difficulty())
	fmt.Printf("keyBlock Nonce 0x%x\n", keyBlock.Nonce())
	fmt.Printf("keyBlock Size %d\n", uint64(keyBlock.Size()))
	//fmt.Printf("keyBlock Leader %s\n", hex.EncodeToString(keyBlock.Leader()))
	//fmt.Printf("keyBlock Sig %s\n", hex.EncodeToString(keyBlock.Signatrue())
	//fmt.Printf("keyBlock Mask %s\n", hex.EncodeToString(keyBlock.Mask()))

	//for i := range keyBlock.Body().InPubKey {
	//	fmt.Printf("keyBlock InPubKey %s\n", hex.EncodeToString(keyBlock.Body().InPubKey[i]))
	//}
	//for i := range keyBlock.Body().OutPubKey {
	//	fmt.Printf("keyBlock OutPubKey %s\n", hex.EncodeToString(keyBlock.Body().OutPubKey[i]))
	//}

	headers, txNs, err := client.BlockHeadersByNumbers(ctx, []int64{300, 301, 302})
	if err != nil {
		fmt.Println("BlockHeadersByNumbers failed", err)
		return
	}

	if headers != nil {
		fmt.Println("BlockHeadersByNumbers returns", len(headers))
	}

	for i := range txNs {
		fmt.Printf("Block %d: TxN %d\n", i, txNs[i])
	}

}
