/*
* Copyright 2022-present Open Networking Foundation
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package main

import (
	"fmt"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"
	"voltha-go-controller/voltha-go-controller/cli/commands"
	"voltha-go-controller/voltha-go-controller/cli/config"
	"voltha-go-controller/voltha-go-controller/cli/database"
)

func registerCommands(parser *flags.Parser) {
	commands.RegisterIGMPCommands(parser)
	commands.RegisterVNETCommands(parser)
	commands.RegisterMVLANCommands(parser)
	commands.RegisterFlowCommands(parser)
	commands.RegisterServiceCommands(parser)
	commands.RegisterPortCommands(parser)
	commands.RegisterVpvsCommands(parser)
	commands.RegisterMeterCommands(parser)
	commands.RegisterGroupCommands(parser)
	commands.RegisterIGMPGroupCommands(parser)
	commands.RegisterIGMPChannelCommands(parser)
	commands.RegisterIGMPDeviceCommands(parser)
	commands.RegisterIGMPPortCommands(parser)
	commands.RegisterCacheIcmpCommands(parser)
	commands.RegisterCacheMvlanCommands(parser)
	commands.RegisterCachePortCommands(parser)
	commands.RegisterTaskListCommands(parser)
	commands.RegisterDeviceInfoCommands(parser)
	commands.RegisterPonPortInfoCommands(parser)
	commands.RegisterDHCPSessionInfoCommands(parser)
	commands.RegisterFlowHashCommands(parser)
	commands.RegisterMCASTCommands(parser)
}

func main() {
	cfg := config.NewConfig()
	cfg.ParseEnvironmentVariables()

	// initialize the database
	if err := database.Init(cfg.KVStoreType,
		fmt.Sprintf("%s:%d", cfg.KVStoreHost, cfg.KVStorePort),
		cfg.KVStoreTimeout); err != nil {
		log.Fatal("Failed to make connection to KV Store. ", err)
	}
	var options Options
	parser := flags.NewParser(&options, flags.Default)
	registerCommands(parser)

	if _, err := parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}
}

// Options struct
type Options struct{}
