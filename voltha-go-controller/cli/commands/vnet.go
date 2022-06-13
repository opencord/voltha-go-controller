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

	flags "github.com/jessevdk/go-flags"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"
	db "voltha-go-controller/database"
)

// RegisterVNETCommands  to register vnet command
func RegisterVNETCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("vnet", "Lists configured VNET profiles", "Commands to display VNET configuration", &vnetCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register vnet commands : %s", err)
	}

}

// VNETCommand structure
type VNETCommand struct{}

var vnetCommand VNETCommand

// Execute for execution of vnet command
func (ic *VNETCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		// Get all VNET profiles
		profiles, err := rc.GetAll(db.GetKeyPath(db.VnetPath))
		if err != nil {
			return fmt.Errorf("Error fetching the VNET profile: %s", err)
		}
		if len(profiles) == 0 {
			return fmt.Errorf("No VNET profiles found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllVNET, models.Horizontal).MultipleEntries(profiles)
	case 1:
		// VNET ID provided in the command
		vnetID := args[0]
		profile, err := rc.Get(db.GetKeyPath(db.VnetPath), vnetID)
		if err != nil {
			return fmt.Errorf("Error fetching the VNET details: %s", err)
		}
		if profile == nil {
			return fmt.Errorf("No VNET profile found with ID %s", vnetID)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleVNET), vnetID))
		format.NewTable(tableTitle, models.Horizontal).SingleEntry(profile)
	default:
		return fmt.Errorf("Usage: %s", models.VNETUsage)
	}
	return nil
}
