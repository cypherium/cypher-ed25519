// Copyright 2016 The cypherBFT Authors
// This file is part of cypherBFT.
//
// cypherBFT is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// cypherBFT is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with cypherBFT. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"crypto/rand"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cypherium/cypherBFT/params"
)

const (
	ipcAPIs  = "reconfig:1.0 manualreconfig:1.0 admin:1.0 debug:1.0 cph:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 shh:1.0 txpool:1.0 web3c:1.0"
	httpAPIs = "cph:1.0 net:1.0 rpc:1.0 web3c:1.0"
)

// Tests that a node embedded within a console can be started up properly and
// then terminated by closing the input stream.
func TestConsoleWelcome(t *testing.T) {

	// Start a cypher console, make sure it's cleaned up and terminate the console
	cypher := runCph(t,
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--shh", "console")

	// Gather all the infos the welcome message needs to contain
	cypher.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	cypher.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	cypher.SetTemplateFunc("gover", runtime.Version)
	cypher.SetTemplateFunc("gcphver", func() string { return params.Version })
	cypher.SetTemplateFunc("niltime", func() string { return time.Unix(0, 0).Format(time.RFC1123) })
	cypher.SetTemplateFunc("apis", func() string { return ipcAPIs })

	// Verify the actual welcome message to the required template
	cypher.Expect(`
Welcome to the Cypher JavaScript console!

instance: Cypher/v{{gcphver}}/{{goos}}-{{goarch}}/{{gover}}
at block: 0 ({{niltime}})
 datadir: {{.Datadir}}
 modules: {{apis}}

> {{.InputLine "exit"}}
`)
	cypher.ExpectExit()
}

// Tests that a console can be attached to a running node via various means.
func TestIPCAttachWelcome(t *testing.T) {
	// Configure the instance for IPC attachement
	var ipc string
	if runtime.GOOS == "windows" {
		ipc = `\\.\pipe\cypher` + strconv.Itoa(trulyRandInt(100000, 999999))
	} else {
		ws := tmpdir(t)
		defer os.RemoveAll(ws)
		ipc = filepath.Join(ws, "cypher.ipc")
	}
	// Note: we need --shh because testAttachWelcome checks for default
	// list of ipc modules and shh is included there.
	cypher := runCph(t,
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--shh", "--ipcpath", ipc)

	time.Sleep(2 * time.Second) // Simple way to wait for the RPC endpoint to open
	testAttachWelcome(t, cypher, "ipc:"+ipc, ipcAPIs)

	cypher.Interrupt()
	cypher.ExpectExit()
}

func TestHTTPAttachWelcome(t *testing.T) {
	port := strconv.Itoa(trulyRandInt(1024, 65536)) // Yeah, sometimes this will fail, sorry :P
	cypher := runCph(t,
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--rpc", "--rpcport", port)

	time.Sleep(2 * time.Second) // Simple way to wait for the RPC endpoint to open
	testAttachWelcome(t, cypher, "http://localhost:"+port, httpAPIs)

	cypher.Interrupt()
	cypher.ExpectExit()
}

func TestWSAttachWelcome(t *testing.T) {
	port := strconv.Itoa(trulyRandInt(1024, 65536)) // Yeah, sometimes this will fail, sorry :P

	cypher := runCph(t,
		"--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none",
		"--ws", "--wsport", port)

	time.Sleep(2 * time.Second) // Simple way to wait for the RPC endpoint to open
	testAttachWelcome(t, cypher, "ws://localhost:"+port, httpAPIs)

	cypher.Interrupt()
	cypher.ExpectExit()
}

func testAttachWelcome(t *testing.T, cypher *testgcph, endpoint, apis string) {
	// Attach to a running cypher note and terminate immediately
	attach := runCph(t, "attach", endpoint)
	defer attach.ExpectExit()
	attach.CloseStdin()

	// Gather all the infos the welcome message needs to contain
	attach.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	attach.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	attach.SetTemplateFunc("gover", runtime.Version)
	attach.SetTemplateFunc("gcphver", func() string { return params.Version })
	attach.SetTemplateFunc("niltime", func() string { return time.Unix(0, 0).Format(time.RFC1123) })
	attach.SetTemplateFunc("ipc", func() bool { return strings.HasPrefix(endpoint, "ipc") })
	attach.SetTemplateFunc("datadir", func() string { return cypher.Datadir })
	attach.SetTemplateFunc("apis", func() string { return apis })

	// Verify the actual welcome message to the required template
	attach.Expect(`
Welcome to the Cypher JavaScript console!

instance: Cypher/v{{gcphver}}/{{goos}}-{{goarch}}/{{gover}}
at block: 0 ({{niltime}}){{if ipc}}
 datadir: {{datadir}}{{end}}
 modules: {{apis}}

> {{.InputLine "exit" }}
`)
	attach.ExpectExit()
}

// trulyRandInt generates a crypto random integer used by the console tests to
// not clash network ports with other tests running cocurrently.
func trulyRandInt(lo, hi int) int {
	num, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	return int(num.Int64()) + lo
}
