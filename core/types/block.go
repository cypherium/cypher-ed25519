package types

import (
	"bytes"
	"io"
	"math/big"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/hexutil"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/rlp"
)

var (
	EmptyRootHash = DeriveSha(Transactions{})
)

const (
	IsTxBlockType uint8 = iota
	IsKeyBlockType
	IsKeyBlockSkipType
)

// Header represents a block header in the Cypherium blockchain.
type Header struct {
	ParentHash  common.Hash `json:"parentHash"       gencodec:"required"`
	Root        common.Hash `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash `json:"receiptsRoot"     gencodec:"required"`
	Number      *big.Int    `json:"number"           gencodec:"required"`
	GasLimit    uint64      `json:"gasLimit"         gencodec:"required"`
	GasUsed     uint64      `json:"gasUsed"          gencodec:"required"`
	Time        *big.Int    `json:"timestamp"        gencodec:"required"`
	BlockType   uint8       `json:"blockType"      gencodec:"required"`
	KeyHash     common.Hash `json:"KeyHash"  	      gencodec:"required"`
	Extra       []byte      `json:"extraData"        gencodec:"required"`
	Signature   []byte      `json:"signature"     gencodec:"required"`
	Exceptions  []byte      `json:"Exceptions"       gencodec:"required"`
}

// gencodec -type Header -field-override headerMarshaling -out gen_header_json.go
// field type overrides for gencodec
type headerMarshaling struct {
	Number   *hexutil.Big
	GasLimit hexutil.Uint64
	GasUsed  hexutil.Uint64
	Time     *hexutil.Big
	Extra    hexutil.Bytes
	Hash     common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	return rlpHash([]interface{}{
		h.ParentHash,
		h.Root,
		h.TxHash,
		h.ReceiptHash,
		h.Number,
		h.GasLimit,
		h.GasUsed,
		h.Time,
		h.BlockType,
		h.KeyHash,
		h.Extra,
	})
	//	return rlpHash(h)
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	return common.StorageSize(unsafe.Sizeof(*h)) + common.StorageSize(len(h.Extra)+len(h.Signature)+len(h.Exceptions)+(h.Number.BitLen()+h.Time.BitLen())/8)
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions) together.
type Body struct {
	Transactions []*Transaction
}

// Block represents an entire block in the Cypherium blockchain.
type Block struct {
	header       *Header
	transactions Transactions

	// caches
	hash atomic.Value
	size atomic.Value

	// Td is used by package core to store the total difficulty
	// of the chain up to and including the block.
	td *big.Int

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// DeprecatedTd is an old relic for extracting the TD of a block. It is in the
// code solely to facilitate upgrading the database from the old format to the
// new, after which it should be deleted. Do not use!
func (b *Block) DeprecatedTd() *big.Int {
	return b.td
}

// "external" block encoding. used for cph protocol, etc.
type extblock struct {
	Header *Header
	Txs    []*Transaction
}

// NewBlock creates a new block. The input data is copied,
// changes to header and to the field values will not affect the
// block.
//
// The values of TxHash, UncleHash, ReceiptHash and Bloom in header
// are ignored and set to values derived from the given txs, uncles
// and receipts.
func NewBlock(header *Header, txs []*Transaction, receipts []*Receipt) *Block {
	b := &Block{header: CopyHeader(header), td: new(big.Int)}

	// TODO: panic if len(txs) != len(receipts)
	if len(txs) == 0 {
		b.header.TxHash = EmptyRootHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs))
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyRootHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts))
	}

	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// CopyHeader creates a deep copy of a block header to prevent side effects from
// modifying a header variable.
func CopyHeader(h *Header) *Header {
	cpy := *h
	if cpy.Time = new(big.Int); h.Time != nil {
		cpy.Time.Set(h.Time)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	if len(h.Signature) > 0 {
		cpy.Signature = make([]byte, len(h.Signature))
		copy(cpy.Signature, h.Signature)
	}
	if len(h.Exceptions) > 0 {
		cpy.Exceptions = make([]byte, len(h.Exceptions))
		copy(cpy.Exceptions, h.Exceptions)
	}

	return &cpy
}

func (b *Block) SetSignature(sig []byte, exceptions []byte) {
	b.header.Signature = make([]byte, len(sig))
	copy(b.header.Signature, sig)
	b.header.Exceptions = make([]byte, len(exceptions))
	copy(b.header.Exceptions, exceptions)
}

func (b *Block) GetSignature() ([]byte, []byte) {
	return b.header.Signature, b.header.Exceptions
}

func (b *Block) SetKeyHash(hash common.Hash) {
	b.header.KeyHash = hash
}

func (b *Block) GetKeyHash() common.Hash {
	return b.header.KeyHash
}

// DecodeRLP decodes the Cypherium
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.transactions = eb.Header, eb.Txs
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the Cypherium RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extblock{
		Header: b.header,
		Txs:    b.transactions,
	})
}

func (b *Block) EncodeToBytes() []byte {
	m := make([]byte, 0)
	buff := bytes.NewBuffer(m)
	err := b.EncodeRLP(buff)
	if err != nil {
		log.Error("Block.EncodeToBytes", "error", err)
		return nil
	}

	return buff.Bytes()
}

func DecodeToBlock(data []byte) *Block {
	block := &Block{}
	buff := bytes.NewBuffer(data)
	c := rlp.NewStream(buff, 0)
	err := block.DecodeRLP(c)
	if err != nil {
		log.Error("Block.DecodeToBlock", "error", err)
		return nil
	}
	return block
}

func (b *Block) Transactions() Transactions { return b.transactions }

func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

func (b *Block) Number() *big.Int     { return new(big.Int).Set(b.header.Number) }
func (b *Block) GasLimit() uint64     { return b.header.GasLimit }
func (b *Block) GasUsed() uint64      { return b.header.GasUsed }
func (b *Block) Difficulty() *big.Int { return big.NewInt(1) }
func (b *Block) Time() *big.Int       { return new(big.Int).Set(b.header.Time) }
func (b *Block) SetToCurrentTime()    { b.header.Time = big.NewInt(time.Now().Unix() * 1e3) }
func (b *Block) TrimTimeMs() {
	timeStr := b.header.Time.String()
	log.Info("getBlock", "timeStr", timeStr, "len", len(timeStr))
	timeStrTrimMs := timeStr[0:13]
	log.Info("getBlock", "timeStrTrimMs", timeStrTrimMs, "len", len(timeStrTrimMs))
	timeIntValue, err := strconv.ParseInt(timeStrTrimMs, 10, 64)
	if err == nil {
		b.header.Time = big.NewInt(timeIntValue)
	}
}

func (b *Block) NumberU64() uint64        { return b.header.Number.Uint64() }
func (b *Block) Root() common.Hash        { return b.header.Root }
func (b *Block) ParentHash() common.Hash  { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash      { return b.header.TxHash }
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }
func (b *Block) Extra() []byte            { return common.CopyBytes(b.header.Extra) }
func (b *Block) Signature() []byte        { return common.CopyBytes(b.header.Signature) }
func (b *Block) Exceptions() []byte       { return common.CopyBytes(b.header.Exceptions) }
func (b *Block) BlockType() uint8         { return b.header.BlockType }
func (b *Block) Header() *Header          { return CopyHeader(b.header) }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body { return &Body{b.transactions} }

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previsouly cached value.
func (b *Block) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
func (b *Block) WithSeal(header *Header, withSig bool) *Block {
	cpy := *header
	p := &Block{header: &cpy, transactions: b.transactions}
	if !withSig {
		p.header.Signature = nil
		p.header.Exceptions = nil
	}
	return p
}

// WithBody returns a new block with the given transaction and uncle contents.
//func (b *Block) WithBody(transactions []*Transaction, uncles []*Header) *Block {
func (b *Block) WithBody(transactions []*Transaction) *Block {
	block := &Block{
		header:       CopyHeader(b.header),
		transactions: make([]*Transaction, len(transactions)),
	}
	copy(block.transactions, transactions)
	return block
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}

type Blocks []*Block

// Make use of sort package to do blocks sorting
type SortBlocksByNumber []*Block

func (a SortBlocksByNumber) Len() int { return len(a) }
func (a SortBlocksByNumber) Less(i, j int) bool {
	return a[i].header.Number.Cmp(a[j].header.Number) < 0
}
func (a SortBlocksByNumber) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
