// Copyright 2015 The cypherBFT Authors
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
	"encoding/json"
	"os"

	"github.com/cypherium/cypherBFT/cmd/utils"
	"github.com/cypherium/cypherBFT/core"
	"github.com/cypherium/cypherBFT/log"
	"gopkg.in/urfave/cli.v1"
)

var (
	initCommand = cli.Command{
		Action:    utils.MigrateFlags(initGenesis),
		Name:      "init",
		Usage:     "Bootstrap and initialize a new genesis keyblock",
		ArgsUsage: "<genesisPath>",
		Flags: []cli.Flag{
			utils.DataDirFlag,
			utils.LightModeFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The init command initializes a new genesis keyblock and definition for the network.
This is a destructive action and changes the network in which you will be
participating.

It expects the genesis file as argument.`,
	}
	/*
			   	importCommand = cli.Command{
			   		Action:    utils.MigrateFlags(importChain),
			   		Name:      "import",
			   		Usage:     "Import a blockchain file",
			   		ArgsUsage: "<filename> (<filename 2> ... <filename N>) ",
			   		Flags: []cli.Flag{
			   			utils.DataDirFlag,
			   			utils.CacheFlag,
			   			utils.LightModeFlag,
			   			utils.GCModeFlag,
			   			utils.CacheDatabaseFlag,
			   			utils.CacheGCFlag,
			   		},
			   		Category: "BLOCKCHAIN COMMANDS",
			   		Description: `
			   The import command imports blocks from an RLP-encoded form. The form can be one file
			   with several RLP-encoded blocks, or several files can be used.

			   If only one file is used, import error will result in failure. If several files are used,
			   processing will proceed even if an individual RLP-file import failure occurs.`,
			   	}
			   	exportCommand = cli.Command{
			   		Action:    utils.MigrateFlags(exportChain),
			   		Name:      "export",
			   		Usage:     "Export blockchain into file",
			   		ArgsUsage: "<filename> [<blockNumFirst> <blockNumLast>]",
			   		Flags: []cli.Flag{
			   			utils.DataDirFlag,
			   			utils.CacheFlag,
			   			utils.LightModeFlag,
			   		},
			   		Category: "BLOCKCHAIN COMMANDS",
			   		Description: `
			   Requires a first argument of the file to write to.
			   Optional second and third arguments control the first and
			   last block to write. In this mode, the file will be appended
			   if already existing.`,
			   	}
			   	importPreimagesCommand = cli.Command{
			   		Action:    utils.MigrateFlags(importPreimages),
			   		Name:      "import-preimages",
			   		Usage:     "Import the preimage database from an RLP stream",
			   		ArgsUsage: "<datafile>",
			   		Flags: []cli.Flag{
			   			utils.DataDirFlag,
			   			utils.CacheFlag,
			   			utils.LightModeFlag,
			   		},
			   		Category: "BLOCKCHAIN COMMANDS",
			   		Description: `
			   	The import-preimages command imports hash preimages from an RLP encoded stream.`,
			   	}
			   	exportPreimagesCommand = cli.Command{
			   		Action:    utils.MigrateFlags(exportPreimages),
			   		Name:      "export-preimages",
			   		Usage:     "Export the preimage database into an RLP stream",
			   		ArgsUsage: "<dumpfile>",
			   		Flags: []cli.Flag{
			   			utils.DataDirFlag,
			   			utils.CacheFlag,
			   			utils.LightModeFlag,
			   		},
			   		Category: "BLOCKCHAIN COMMANDS",
			   		Description: `
			   The export-preimages command export hash preimages to an RLP encoded stream`,
			   	}
			   	copydbCommand = cli.Command{
			   		Action:    utils.MigrateFlags(copyDb),
			   		Name:      "copydb",
			   		Usage:     "Create a local chain from a target chaindata folder",
			   		ArgsUsage: "<sourceChaindataDir>",
			   		Flags: []cli.Flag{
			   			utils.DataDirFlag,
			   			utils.CacheFlag,
			   			utils.SyncModeFlag,
			   			utils.FakePoWFlag,
			   			utils.TestnetFlag,
			   			utils.RinkebyFlag,
			   		},
			   		Category: "BLOCKCHAIN COMMANDS",
			   		Description: `
			   The first argument must be the directory containing the blockchain to download from`,
			   	}
			   	removedbCommand = cli.Command{
			   		Action:    utils.MigrateFlags(removeDB),
			   		Name:      "removedb",
			   		Usage:     "Remove blockchain and state databases",
			   		ArgsUsage: " ",
			   		Flags: []cli.Flag{
			   			utils.DataDirFlag,
			   			utils.LightModeFlag,
			   		},
			   		Category: "BLOCKCHAIN COMMANDS",
			   		Description: `
			   Remove blockchain and state databases`,
			   	}
			dumpCommand = cli.Command{
				Action:    utils.MigrateFlags(dump),
				Name:      "dump",
				Usage:     "Dump a specific block from storage",
				ArgsUsage: "[<blockHash> | <blockNum>]...",
				Flags: []cli.Flag{
					utils.DataDirFlag,
					utils.CacheFlag,
					utils.LightModeFlag,
				},
				Category: "BLOCKCHAIN COMMANDS",
				Description: `
		The arguments are interpreted as block numbers or hashes.
		Use "cypherium dump 0" to dump the genesis block.`,
			}
	*/
)

// initGenesis will initialise the given JSON format genesis file and writes it as
// the zero'd block (i.e. genesis) or will fail hard if it can't succeed.
func initGenesis(ctx *cli.Context) error {
	// Make sure we have a valid genesis JSON
	genesisPath := ctx.Args().First()
	if len(genesisPath) == 0 {
		utils.Fatalf("Must supply path to genesis JSON file")
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		utils.Fatalf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	keyGenesis := new(core.GenesisKey)
	if err := json.NewDecoder(file).Decode(keyGenesis); err != nil {
		utils.Fatalf("init keychain, invalid genesis file: %v", err)
	}

	file.Seek(0, 0)
	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		utils.Fatalf("init blockchain,invalid genesis file: %v", err)
	}

	// Open and initialise both full and light databases
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()
	for _, name := range []string{"chaindata"} {
		chaindb, err := stack.OpenDatabase(name, 0, 0, "")
		if err != nil {
			utils.Fatalf("Failed to open database: %v", err)
		}

		_, hash, err := core.SetupGenesisKeyBlock(chaindb, keyGenesis)
		if err != nil {
			utils.Fatalf("Failed to write genesis key block: %v", err)
		}

		genesis.KeyHash = hash
		_, hash, err = core.SetupGenesisBlock(chaindb, genesis)
		if err != nil {
			utils.Fatalf("Failed to write genesis block: %v", err)
		}

		log.Info("Successfully wrote genesis state", "database", name, "hash", hash)
	}

	return nil
}
