package onet

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/onet/network"
	"github.com/dedis/kyber"
	uuid "gopkg.in/satori/go.uuid.v1"
)

func init() {
	network.RegisterMessage(Tree{})
	network.RegisterMessage(tbmStruct{})
}

// Tree is a topology to be used by any network layer/host layer.
// It contains the peer list we use, and the tree we use
type Tree struct {
	ID     TreeID
	Roster *Roster
	Root   *TreeNode
}

// TreeID uniquely identifies a Tree struct in the onet framework.
type TreeID uuid.UUID

// Equal returns true if and only if tID2 equals this TreeID.
func (tId TreeID) Equal(tID2 TreeID) bool {
	return uuid.Equal(uuid.UUID(tId), uuid.UUID(tID2))
}

// Equals will be removed!
func (tId TreeID) Equals(tID2 TreeID) bool {
	log.Warn("Deprecated: TreeID.Equals will be removed in onet.v2")
	return tId.Equal(tID2)
}

// String returns a canonical representation of the TreeID.
func (tId TreeID) String() string {
	return uuid.UUID(tId).String()
}

// IsNil returns true iff the TreeID is Nil
func (tId TreeID) IsNil() bool {
	return tId.Equal(TreeID(uuid.Nil))
}

type tbmStruct struct {
	T  []byte
	Ro *Roster
}

// TreeMarshal is used to send and receive a tree-structure without having
// to copy the whole nodelist
type TreeMarshal struct {
	// This is the UUID of the corresponding TreeNode
	TreeNodeID TreeNodeID
	// TreeId identifies the Tree for the top-node
	TreeID TreeID
	// This is the UUID of the ServerIdentity, except
	ServerIdentityID network.ServerIdentityID
	// for the top-node this contains the Roster's ID
	RosterID RosterID
	// All children from this tree. The top-node only has one child, which is
	// the root
	Children []*TreeMarshal
}

// TreeMarshalTypeID of TreeMarshal message as registered in network
var TreeMarshalTypeID = network.RegisterMessage(TreeMarshal{})

// A Roster is a list of ServerIdentity we choose to run some tree on it ( and
// therefor some protocols). Access is not safe from multiple goroutines.
type Roster struct {
	ID RosterID
	// List is the list of actual entities.
	List      []*network.ServerIdentity
	Aggregate kyber.Point
}

// RosterID uniquely identifies an Roster
type RosterID uuid.UUID

// String returns the default representation of the ID (wrapper around
// uuid.UUID.String()
func (roID RosterID) String() string {
	return uuid.UUID(roID).String()
}

// Equal returns true if and only if roID2 equals this RosterID.
func (roID RosterID) Equal(roID2 RosterID) bool {
	return uuid.Equal(uuid.UUID(roID), uuid.UUID(roID2))
}

// IsNil returns true iff the RosterID is Nil
func (roID RosterID) IsNil() bool {
	return roID.Equal(RosterID(uuid.Nil))
}

// RosterTypeID of Roster message as registered in network
var RosterTypeID = network.RegisterMessage(Roster{})

// NewRoster creates a new roster from a list of entities. It also
// adds a UUID which is randomly chosen.
func NewRoster(ids []*network.ServerIdentity) *Roster {
	// Don't allow a crash if things are not as expected.
	if len(ids) < 1 || ids[0].Public == nil {
		return nil
	}

	h := sha256.New()
	for _, id := range ids {
		_, err := id.Public.MarshalTo(h)
		if err != nil {
			log.Error("NewRoster", "error", err)
		}
	}

	r := &Roster{
		ID: RosterID(uuid.NewV5(uuid.NamespaceURL, hex.EncodeToString(h.Sum(nil)))),
	}

	// Take a copy of ids, in case the caller tries to change it later.
	r.List = append(r.List, ids...)
	return r
}

// Get simply returns the entity that is stored at that index in the entitylist
// returns nil if index error
func (ro *Roster) Get(idx int) *network.ServerIdentity {
	if idx < 0 || idx > len(ro.List) {
		return nil
	}
	return ro.List[idx]
}

// TreeNode is one node in the tree
type TreeNode struct {
	// The Id represents that node of the tree
	ID TreeNodeID
	// The ServerIdentity points to the corresponding host. One given host
	// can be used more than once in a tree.
	ServerIdentity *network.ServerIdentity
	// RosterIndex is the index in the Roster where the `ServerIdentity` is located
	RosterIndex int
	// Parent link
	Parent *TreeNode
	// Children links
	Children []*TreeNode
}

// TreeNodeID identifies a given TreeNode struct in the onet framework.
type TreeNodeID uuid.UUID

// String returns a canonical representation of the TreeNodeID.
func (tId TreeNodeID) String() string {
	return uuid.UUID(tId).String()
}

// Equal returns true if and only if the given TreeNodeID equals tId.
func (tId TreeNodeID) Equal(tID2 TreeNodeID) bool {
	return uuid.Equal(uuid.UUID(tId), uuid.UUID(tID2))
}

// IsNil returns true iff the TreeNodID is Nil
func (tId TreeNodeID) IsNil() bool {
	return tId.Equal(TreeNodeID(uuid.Nil))
}
