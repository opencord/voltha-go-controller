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

package commands

import (
	"fmt"
	"log"

	db "voltha-go-controller/database"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"

	flags "github.com/jessevdk/go-flags"
)

// RegisterMCASTCommands to register mcast command
func RegisterMCASTCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("mcast", "Displays current MCAST configuration", "Commands to display mcast configuration", &mcastCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register mcast commands : %s", err)
	}
}

// MCASTCommand structure
type MCASTCommand struct{}

var mcastCommand MCASTCommand

// Execute for execution of mcast command
func (ic *MCASTCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		config, err := rc.GetAll(db.GetKeyPath(db.McastConfigPath))
		if err != nil {
			return fmt.Errorf("Error fetching the MCAST configuration: %s", err)
		}
		if config == nil {
			return fmt.Errorf("No MCAST configuration found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.MCAST, models.Vertical).MultipleEntries(config)
	default:
		return fmt.Errorf("Usage: %s", models.MCASTUsage)
	}
	return nil
}
