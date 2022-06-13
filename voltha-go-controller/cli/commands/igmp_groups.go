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

// RegisterIGMPGroupCommands to register igmp group command
func RegisterIGMPGroupCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("igmpgroup", "Lists configured IGMP Groups", "Commands to display IGMP Group configuration", &igmpgroupCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register igmp group commands : %s", err)
	}

}

// IGMPGroupCommand structure
type IGMPGroupCommand struct{}

var igmpgroupCommand IGMPGroupCommand

// Execute for execution of igmp group command
func (ic *IGMPGroupCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store : %v ", err)
	}

	switch len(args) {
	case 0:
		groups, err := rc.GetAll(db.GetKeyPath(db.IgmpGroupPath))
		if err != nil {
			return fmt.Errorf("Error fetching the IGMP Group details: %s", err)
		}
		if len(groups) == 0 {
			return fmt.Errorf("No igmp groups found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllIGMPGroups, models.Vertical).MultipleEntries(groups)
	case 1:
		igmpGroupID := args[0]
		group, err := rc.Get(db.GetKeyPath(db.IgmpGroupPath), igmpGroupID)
		if err != nil {
			return fmt.Errorf("Error fetching the IGMP Group details: %s", err)
		}
		if group == nil {
			return fmt.Errorf("No igmp group found with ID %s", igmpGroupID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleIGMPGroup), igmpGroupID))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(group)
	default:
		return fmt.Errorf("Usage: %s", models.IGMPGroupUsage)
	}
	return nil
}
