package onet

import (
	"errors"
	"sync"
	"time"

	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/onet/network"
)

// Overlay keeps all trees and entity-lists for a given Server. It creates
// Nodes and ProtocolInstances upon request and dispatches the messages.
type Overlay struct {
	server *Server
	// mapping from Tree.Id to Tree
	//	trees    map[TreeID]*Tree
	//	treesMut sync.Mutex
	// mapping from Roster.id to Roster
	//entityLists    map[RosterID]*Roster
	//entityListLock sync.Mutex
	// cache for relating token(~Node) to TreeNode
	cache *treeNodeCache

	// TreeNodeInstance part
	//	instances         map[TokenID]*TreeNodeInstance
	//	instancesInfo     map[TokenID]bool
	//	instancesLock     sync.Mutex
	//protocolInstances map[TokenID]ProtocolInstance

	// treeMarshal that needs to be converted to Tree but host does not have the
	// entityList associated yet.
	// map from Roster.ID => trees that use this entity list
	//pendingTreeMarshal map[RosterID][]*TreeMarshal
	// lock associated with pending TreeMarshal
	//pendingTreeLock sync.Mutex

	// pendingMsg is a list of message we received that does not correspond
	// to any local Tree or/and Roster. We first request theses so we can
	// instantiate properly protocolInstance that will use these ProtocolMsg msg.
	pendingMsg []pendingMsg
	// lock associated with pending ProtocolMsg
	pendingMsgLock sync.Mutex

	//transmitMux sync.Mutex

	//protoIO *messageProxyStore

	pendingConfigs    map[TokenID]*GenericConfig
	pendingConfigsMut sync.Mutex
}

// NewOverlay creates a new overlay-structure
func NewOverlay(c *Server) *Overlay {
	o := &Overlay{
		server: c,
		//		trees:       make(map[TreeID]*Tree),
		//entityLists: make(map[RosterID]*Roster),
		cache: newTreeNodeCache(),
		//		instances:          make(map[TokenID]*TreeNodeInstance),
		//		instancesInfo:      make(map[TokenID]bool),
		//		protocolInstances:  make(map[TokenID]ProtocolInstance),
		//		pendingTreeMarshal: make(map[RosterID][]*TreeMarshal),
		//		pendingConfigs:     make(map[TokenID]*GenericConfig),
	}
	//o.protoIO = newMessageProxyStore(c.suite, c, o)
	// messages going to protocol instances
	c.RegisterProcessor(o,
		ProtocolMsgID,      // protocol instance's messages
		RequestTreeMsgID,   // request a tree
		SendTreeMsgID,      // send a tree back to a request
		RequestRosterMsgID, // request a roster
		SendRosterMsgID,    // send a roster back to request
		ConfigMsgID)        // fetch config information
	return o
}

// stop stops goroutines associated with this overlay.
func (o *Overlay) stop() {
	o.cache.stop()
}

// Process implements the Processor interface so it process the messages that it
// wants.
func (o *Overlay) Process(env *network.Envelope) {
	// Messages handled by the overlay directly without any messageProxyIO
	if env.MsgType.Equal(ConfigMsgID) {
		o.handleConfigMessage(env)
		return
	}

}

// Rx implements the CounterIO interface, should be the same as the server
func (o *Overlay) Rx() uint64 {
	return o.server.Rx()
}

// Tx implements the CounterIO interface, should be the same as the server
func (o *Overlay) Tx() uint64 {
	return o.server.Tx()
}

// handleConfigMessage stores the config message so it can be dispatched
// alongside with the protocol message later to the service.
func (o *Overlay) handleConfigMessage(env *network.Envelope) {
	config, ok := env.Msg.(*ConfigMsg)
	if !ok {
		// This should happen only if a bad packet gets through
		log.Error("handleConfigMessage", "address", o.server.Address(), "error", "Wrong config type, most likely invalid packet got through.")
		return
	}

	o.pendingConfigsMut.Lock()
	defer o.pendingConfigsMut.Unlock()
	o.pendingConfigs[config.Dest] = &config.Config
}

// getConfig returns the generic config corresponding to this node if present,
// and removes it from the list of pending configs.
func (o *Overlay) getConfig(id TokenID) *GenericConfig {
	o.pendingConfigsMut.Lock()
	defer o.pendingConfigsMut.Unlock()
	c := o.pendingConfigs[id]
	delete(o.pendingConfigs, id)
	return c
}

func (o *Overlay) suite() network.Suite {
	return o.server.Suite()
}

// ServerIdentity Returns the entity of the Host
func (o *Overlay) ServerIdentity() *network.ServerIdentity {
	return o.server.ServerIdentity
}

// ErrWrongTreeNodeInstance is returned when you already binded a TNI with a PI.
var ErrWrongTreeNodeInstance = errors.New("This TreeNodeInstance doesn't exist")

// ErrProtocolRegistered is when the protocolinstance is already registered to
// the overlay
var ErrProtocolRegistered = errors.New("a ProtocolInstance already has been registered using this TreeNodeInstance")

// pendingMsg is used to store messages destined for ProtocolInstances but when
// the tree designated is not known to the Overlay. When the tree is sent to the
// overlay, then the pendingMsg that are relying on this tree will get
// processed.
type pendingMsg struct {
	*ProtocolMsg
}

// treeNodeCache is a cache that maps from token to treeNode. Since
// the mapping is not 1-1 (many Tokens can point to one TreeNode, but
// one token leads to one TreeNode), we have to do certain lookup, but
// that's better than searching the tree each time.
type treeNodeCache struct {
	Entries  map[TreeID]*cacheEntry
	stopCh   chan (struct{})
	stopOnce sync.Once
	sync.Mutex
}

type cacheEntry struct {
	treeNodeMap map[TreeNodeID]*TreeNode
	expiration  time.Time
}

var cacheTime = 5 * time.Minute
var cleanEvery = 1 * time.Minute

func newTreeNodeCache() *treeNodeCache {
	tnc := &treeNodeCache{
		Entries: make(map[TreeID]*cacheEntry),
		stopCh:  make(chan struct{}),
	}
	go tnc.cleaner()
	return tnc
}

func (tnc *treeNodeCache) stop() {
	tnc.stopOnce.Do(func() {
		close(tnc.stopCh)
	})
}

func (tnc *treeNodeCache) cleaner() {
	for {
		select {
		case <-time.After(cleanEvery):
			tnc.clean()
		case <-tnc.stopCh:
			return
		}
	}
}

func (tnc *treeNodeCache) clean() {
	tnc.Lock()
	now := time.Now()
	for k := range tnc.Entries {
		if now.After(tnc.Entries[k].expiration) {
			delete(tnc.Entries, k)
		}
	}
	tnc.Unlock()
}

// Set sets an entry in the cache. It will also cache the parent and
// children of the treenode since that's most likely what we are going
// to query.
func (tnc *treeNodeCache) Set(tree *Tree, treeNode *TreeNode) {
	tnc.Lock()
	ce, ok := tnc.Entries[tree.ID]
	if !ok {
		ce = &cacheEntry{
			treeNodeMap: make(map[TreeNodeID]*TreeNode),
			expiration:  time.Now().Add(cacheTime),
		}
	}
	// add treenode
	ce.treeNodeMap[treeNode.ID] = treeNode
	// add parent if not root
	if treeNode.Parent != nil {
		ce.treeNodeMap[treeNode.Parent.ID] = treeNode.Parent
	}
	// add children
	for _, c := range treeNode.Children {
		ce.treeNodeMap[c.ID] = c
	}
	// add cache
	tnc.Entries[tree.ID] = ce
	tnc.Unlock()
}
