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

// RegisterMVLANCommands to register mvlan command
func RegisterMVLANCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("mvlan", "Lists configured MVLANs", "Commands to display MVLAN configuration", &mvlanCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register mvlan commands : %s", err)
	}
}

// MVLANCommand structure
type MVLANCommand struct{}

var mvlanCommand MVLANCommand

// Execute for execution of mvlan command
func (ic *MVLANCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		profiles, err := rc.GetAll(db.GetKeyPath(db.MvlanPath))
		if err != nil {
			return fmt.Errorf("Error fetching the MVLAN details: %s", err)
		}
		if len(profiles) == 0 {
			return fmt.Errorf("No mvlan found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllMVLAN, models.Vertical).MultipleEntries(profiles)
	case 1:
		mvlanID := args[0]
		profile, err := rc.Get(db.GetKeyPath(db.MvlanPath), mvlanID)
		if err != nil {
			return fmt.Errorf("Error fetching the MVLAN details: %s", err)
		}
		if profile == nil {
			return fmt.Errorf("No mvlan found with ID %s", mvlanID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleMVLAN), mvlanID))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(profile)
	default:
		return fmt.Errorf("Usage: %s", models.MVLANUsage)
	}
	return nil
}
