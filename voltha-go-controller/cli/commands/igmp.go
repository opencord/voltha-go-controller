/*
* Copyright 2022-2024present Open Networking Foundation
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

// RegisterIGMPCommands to register igmp command
func RegisterIGMPCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("igmp", "Displays current IGMP configuration", "Commands to display igmp configuration", &igmpCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register igmp commands : %s", err)
	}
}

// IGMPCommand structure
type IGMPCommand struct{}

var igmpCommand IGMPCommand

// Execute for execution of igmp command
func (ic *IGMPCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		key := db.GetKeyPath(db.IgmpProfPath)
		config, err := rc.GetAll(key)
		if err != nil {
			return fmt.Errorf("Error fetching the IGMP configuration: %s", err)
		}
		if config == nil {
			return fmt.Errorf("No IGMP configuration found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.IGMP, models.Vertical).MultipleEntries(config)
	default:
		return fmt.Errorf("Usage: %s", models.IGMPUsage)
	}
	return nil
}
