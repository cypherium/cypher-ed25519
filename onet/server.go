package onet

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/onet/network"
	"rsc.io/goversion/version"
)

// Server connects the Router, the Overlay, and the Services together. It sets
// up everything and returns once a working network has been set up.
type Server struct {
	*network.Router
	// Overlay handles the mapping from tree and entityList to ServerIdentity.
	// It uses tokens to represent an unique ProtocolInstance in the system
	overlay *Overlay
	// lock associated to access trees
	treesLock            sync.Mutex
	serviceManager       *serviceManager
	statusReporterStruct *statusReporterStruct
	// protocols holds a map of all available protocols and how to create an
	// instance of it
	//protocols *protocolStorage
	// when this node has been started
	started time.Time
	// once everything's up and running
	closeitChannel chan bool
	IsStarted      bool

	suite network.Suite
}

// NewServer returns a fresh Server tied to a given Router.
// If dbPath is "", the server will write its database to the default
// location. If dbPath is != "", it is considered a temp dir, and the
// DB is deleted on close.
func newServer(s network.Suite, r *network.Router) *Server {
	c := &Server{
		statusReporterStruct: newStatusReporterStruct(),
		Router:               r,
		//protocols:            newProtocolStorage(),
		suite:          s,
		closeitChannel: make(chan bool),
	}
	c.overlay = NewOverlay(c)
	c.serviceManager = newServiceManager(c, c.overlay)
	/*
		c.statusReporterStruct.RegisterStatusReporter("Generic", c)
		for name, inst := range protocols.instantiators {
			log.Debug("Registering global protocol", "name", name)
			c.ProtocolRegister(name, inst)
		}
	*/
	return c
}

func NewKcpServer(addr string) *Server {
	serverIdentity := &network.ServerIdentity{}
	serverIdentity.Address = network.Address("kcp://" + addr)
	return NewServerKCPWithListenAddr(serverIdentity, network.EncSuite, "")
}

// NewServerKCPWithListenAddr returns a new Server out of a private-key and
// its related public key within the ServerIdentity. The server will use a
// KcpRouter listening on the given address as Router.
func NewServerKCPWithListenAddr(e *network.ServerIdentity, suite network.Suite, listenAddr string) *Server {
	r, _ := network.NewKCPRouterWithListenAddr(e, suite, listenAddr)
	return newServer(suite, r)
}

// Suite can (and should) be used to get the underlying Suite.
// Currently the suite is hardcoded into the network library.
// Don't use network.Suite but Host's Suite function instead if possible.
func (c *Server) Suite() network.Suite {
	return c.suite
}

var gover version.Version
var goverOnce sync.Once
var goverOk = false

// GetStatus is a function that returns the status report of the server.
func (c *Server) GetStatus() *Status {
	v := "2.0"

	a := c.serviceManager.availableServices()
	sort.Strings(a)

	st := &Status{Field: map[string]string{
		"Available_Services": strings.Join(a, ","),
		"TX_bytes":           strconv.FormatUint(c.Router.Tx(), 10),
		"RX_bytes":           strconv.FormatUint(c.Router.Rx(), 10),
		"Uptime":             time.Now().Sub(c.started).String(),
		"System":             fmt.Sprintf("%s/%s/%s", runtime.GOOS, runtime.GOARCH, runtime.Version()),
		"Version":            v,
		"Host":               c.ServerIdentity.Address.Host(),
		"Port":               c.ServerIdentity.Address.Port(),
		"Description":        c.ServerIdentity.Description,
		"ConnType":           string(c.ServerIdentity.Address.ConnType()),
	}}

	goverOnce.Do(func() {
		v, err := version.ReadExe(os.Args[0])
		if err == nil {
			gover = v
			goverOk = true
		}
	})

	if goverOk {
		st.Field["GoRelease"] = gover.Release
		st.Field["GoModuleInfo"] = gover.ModuleInfo
	}

	return st
}

// Close closes the overlay and the Router
func (c *Server) Close() error {
	c.Lock()
	if c.IsStarted {
		// c.closeitChannel <- true
		c.IsStarted = false
	}
	c.Unlock()

	c.overlay.stop()
	//??c.overlay.Close()
	err := c.Router.Stop()
	log.Warn("Close", "Host Close", c.ServerIdentity.Address, "listening?", c.Router.Listening())
	return err
}

// Address returns the address used by the Router.
func (c *Server) Address() network.Address {
	return c.ServerIdentity.Address
}

// Service returns the service with the given name.
func (c *Server) Service(name string) Service {
	return c.serviceManager.service(name)
}

// GetService is kept for backward-compatibility.
func (c *Server) GetService(name string) Service {
	log.Warn("This method is deprecated - use `Server.Service` instead")
	return c.Service(name)
}

/*
// ProtocolRegister will sign up a new protocol to this Server.
// It returns the ID of the protocol.
func (c *Server) ProtocolRegister(name string, protocol NewProtocol) (ProtocolID, error) {
	return c.protocols.Register(name, protocol)
}
*/
// Start makes the router listen on their respective
// ports. It returns once all servers are started.
func (c *Server) Start() {
	/*
		protocols.Lock()
		if protocols.serverStarted {
			protocols.Unlock()
			return
		}
		protocols.Unlock()
	*/
//	InformServerStarted()
	c.started = time.Now()
	log.Info(fmt.Sprintf("Starting server at %s on address %s ", c.started.Format("2006-01-02 15:04:05"), c.ServerIdentity.Address))
	go c.Router.Start()

	// go func() {
	// 	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 		fmt.Fprintf(w, "PONG")
	// 	})

	// 	http.ListenAndServe(":6688", nil) // TODO: make this health check port configurable
	// }()

	for !c.Router.Listening() {
		time.Sleep(50 * time.Millisecond)
	}
	c.Lock()
	c.IsStarted = true
	c.Unlock()
	// Wait for closing of the channel
	//<-c.closeitChannel
}

func (c *Server) Start_client() {
	//InformServerStarted()
	c.started = time.Now()
	log.Info(fmt.Sprintf("Starting server at %s on address %s ", c.started.Format("2006-01-02 15:04:05"), c.ServerIdentity.Address))
	go c.Router.Start()

	// go func() {
	// 	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 		fmt.Fprintf(w, "PONG")
	// 	})

	// 	http.ListenAndServe(":6688", nil) // TODO: make this health check port configurable
	// }()

	for !c.Router.Listening() {
		time.Sleep(50 * time.Millisecond)
	}
	c.Lock()
	c.IsStarted = true
	c.Unlock()
	// Wait for closing of the channel
	<-c.closeitChannel
}

// StartInBackground starts the services and returns once everything
// is up and running.
func (c *Server) StartInBackground() {
	go c.Start()
	c.WaitStartup()
}

// WaitStartup can be called to ensure that the server is up and
// running. It will loop and wait 50 milliseconds between each
// test.
func (c *Server) WaitStartup() {
	for {
		c.Lock()
		s := c.IsStarted
		c.Unlock()
		if s {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// CloseConnect close remote connection
func (c *Server) AdjustConnect(list []*common.Cnode) {
}
