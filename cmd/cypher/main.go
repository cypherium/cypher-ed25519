// Copyright 2014 The cypherBFT Authors
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

// cypher is the official command-line client for Cypherium.
package main

import (
	"fmt"
	"math"
	"os"
	"runtime"
	godebug "runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/cypherium/cypherBFT/accounts"
	"github.com/cypherium/cypherBFT/accounts/keystore"
	"github.com/cypherium/cypherBFT/cmd/utils"
	"github.com/cypherium/cypherBFT/console"
	"github.com/cypherium/cypherBFT/core/vm"
	"github.com/cypherium/cypherBFT/ethclient"
	"github.com/cypherium/cypherBFT/crypto/bls"
	"github.com/cypherium/cypherBFT/internal/debug"
	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/metrics"
	"github.com/cypherium/cypherBFT/node"
	"github.com/cypherium/cypherBFT/params"

	cli "gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "cypher" // Client identifier to advertise over the network
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	// The app that holds all commands and flags.
	app = utils.NewApp(gitCommit, "the cypherBFT command line interface")
	// flags that configure the node
	nodeFlags = []cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.BootnodesV4Flag,
		utils.BootnodesV5Flag,
		utils.DataDirFlag,
		utils.KeyStoreDirFlag,
		utils.NoUSBFlag,
		utils.CphashCacheDirFlag,
		utils.CphashCachesInMemoryFlag,
		utils.CphashCachesOnDiskFlag,
		utils.CphashDatasetDirFlag,
		utils.CphashDatasetsInMemoryFlag,
		utils.CphashDatasetsOnDiskFlag,
		utils.TxPoolNoLocalsFlag,
		utils.TxPoolJournalFlag,
		utils.TxPoolRejournalFlag,
		utils.TxPoolPriceLimitFlag,
		utils.TxPoolPriceBumpFlag,
		utils.TxPoolAccountSlotsFlag,
		utils.TxPoolGlobalSlotsFlag,
		utils.TxPoolAccountQueueFlag,
		utils.TxPoolGlobalQueueFlag,
		utils.TxPoolLifetimeFlag,
		utils.TxPoolEnabledTPSFlag,
		utils.TxPoolDisabledGASFlag,
		utils.TxPoolEnabledJVMFlag,
		utils.TxPoolEnabledEVMFlag,
		utils.IpEncryptDisableFlag,
		utils.LocalTestIpConfig,
		utils.FastSyncFlag,
		utils.LightModeFlag,
		utils.SyncModeFlag,
		utils.GCModeFlag,
		utils.LightServFlag,
		utils.LightPeersFlag,
		utils.LightKDFFlag,
		utils.CacheFlag,
		utils.CacheDatabaseFlag,
		utils.CacheGCFlag,
		utils.TrieCacheGenFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.GasPriceFlag,
		utils.MinerThreadsFlag,
		utils.MiningEnabledFlag,
		utils.TargetGasLimitFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DeveloperFlag,
		utils.DeveloperPeriodFlag,
		utils.TestnetFlag,
		utils.RinkebyFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.RPCCORSDomainFlag,
		utils.RPCVirtualHostsFlag,
		utils.CphStatsURLFlag,
		utils.MetricsEnabledFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.ExtraDataFlag,
		configFileFlag,
	}

	rpcFlags = []cli.Flag{
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
	}

	rnetFlags = []cli.Flag{
		utils.RnetDebugFlag,
		utils.RnetPortFlag,
		utils.PublicKeyFlag,
	}

	metricsFlags = []cli.Flag{
		utils.MetricsEnableInfluxDBFlag,
		utils.MetricsInfluxDBEndpointFlag,
		utils.MetricsInfluxDBDatabaseFlag,
		utils.MetricsInfluxDBUsernameFlag,
		utils.MetricsInfluxDBPasswordFlag,
		utils.MetricsInfluxDBHostTagFlag,
	}
)

func init() {
	// Initialize the CLI app and start Cypher
	app.Action = cypher
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2018 The cypherBFT Authors"
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		//		importCommand,
		//		exportCommand,
		//		importPreimagesCommand,
		//		exportPreimagesCommand,
		//		copydbCommand,
		//		removedbCommand,
		//		dumpCommand,
		// See monitorcmd.go:
		monitorCommand,
		// See accountcmd.go:
		accountCommand,
		//walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		//makecacheCommand,
		//makedagCommand,
		versionCommand,
		bugCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
		setupCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = append(app.Flags, nodeFlags...)
	app.Flags = append(app.Flags, rpcFlags...)
	app.Flags = append(app.Flags, consoleFlags...)
	app.Flags = append(app.Flags, debug.Flags...)
	app.Flags = append(app.Flags, rnetFlags...)
	app.Flags = append(app.Flags, metricsFlags...)

	app.Before = func(ctx *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		// Ensure Go's GC ignores the database cache for trigger percentage
		cache := ctx.GlobalInt(utils.CacheFlag.Name)
		gogc := math.Max(20, math.Min(100, 100/(float64(cache)/1024)))

		log.Debug("Sanitizing Go's GC trigger", "percent", int(gogc))
		godebug.SetGCPercent(int(gogc))

		// Start metrics export if enabled
		utils.SetupMetrics(ctx)

		// Start system runtime metrics collection
		go metrics.CollectProcessMetrics(3 * time.Second)

		utils.SetupNetwork(ctx)

		bls.Init(bls.CurveFp254BNb)

		return nil
	}

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// cypher is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func cypher(ctx *cli.Context) error {

	//usr, err := user.Current()
	//if err != nil {
	//	log.Error("Cannot get home directory")
	//}
	//RnetPort := ctx.GlobalString(utils.RnetPortFlag.Name)
	//logFile, _ := os.OpenFile(strings.Join([]string{usr.HomeDir, "/", RnetPort, ".log"}, ""), os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0755)
	//syscall.Dup2(int(logFile.Fd()), 1)
	//syscall.Dup2(int(logFile.Fd()), 2)
	//fmt.Println(logFile, syscall.Getuid())
	log.Info("FLAG", "DisableJVM", params.DisableJVM, "DisableEVM", params.DisableEVM)

	node := makeFullNode(ctx)
	startNode(ctx, node)
	vm.CVM_init()

	node.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node) {
	debug.Memsize.Add("node", stack)

	// Start up the node itself
	utils.StartNode(stack)

	// Unlock any account specifically requested
	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

	passwords := utils.MakePasswordList(ctx)
	unlocks := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for i, account := range unlocks {
		if trimmed := strings.TrimSpace(account); trimmed != "" {
			unlockAccount(ctx, ks, trimmed, i, passwords)
		}
	}
	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	go func() {
		// Create a chain state reader for self-derivation
		rpcClient, err := stack.Attach()
		if err != nil {
			utils.Fatalf("Failed to attach to self: %v", err)
		}
		stateReader := ethclient.NewClient(rpcClient)

		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				if event.Wallet.URL().Scheme == "ledger" {
					event.Wallet.SelfDerive(accounts.DefaultLedgerBaseDerivationPath, stateReader)
				} else {
					event.Wallet.SelfDerive(accounts.DefaultBaseDerivationPath, stateReader)
				}

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()
	// Start auxiliary services if enabled
	//if ctx.GlobalBool(utils.MiningEnabledFlag.Name) || ctx.GlobalBool(utils.DeveloperFlag.Name) {
	//	// Mining only makes sense if a full Cypherium node is running
	//	if ctx.GlobalBool(utils.LightModeFlag.Name) || ctx.GlobalString(utils.SyncModeFlag.Name) == "light" {
	//		utils.Fatalf("Light clients do not support mining")
	//	}
	//	var cypherium *eth.Cypherium
	//	if err := stack.Service(&cypherium); err != nil {
	//		utils.Fatalf("Cypherium service not running: %v", err)
	//	}
	//	// Use a reduced number of threads if requested
	//	if threads := ctx.GlobalInt(utils.MinerThreadsFlag.Name); threads > 0 {
	//		type threaded interface {
	//			SetThreads(threads int)
	//		}
	//		if th, ok := cypherI.Engine().(threaded); ok {
	//			th.SetThreads(threads)
	//		}
	//	}
	//	// Set the gas price to the limits from the CLI and start mining
	//	cypherI.TxPool().SetGasPrice(utils.GlobalBig(ctx, utils.GasPriceFlag.Name))
	//	if err := cypherI.StartMining(true, common.Address{}); err != nil {
	//		utils.Fatalf("Failed to start mining: %v", err)
	//	}
	//}
}
