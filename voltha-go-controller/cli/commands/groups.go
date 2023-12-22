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

// RegisterGroupCommands to register group command
func RegisterGroupCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("group", "Lists configured Groups", "Commands to display Group configuration", &groupCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register group commands : %s", err)
	}
}

// GroupCommand to register group command
type GroupCommand struct{}

var groupCommand GroupCommand

// Execute for execution of group command
func (gc *GroupCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		deviceIDList := DeviceIDForGetAll()
		if deviceIDList == nil {
			return fmt.Errorf("No groups found")
		}
		for _, deviceID := range deviceIDList {
			groups, err := rc.GetAll(fmt.Sprintf(db.GetKeyPath(db.DeviceGroupPath), deviceID))
			if err != nil {
				return fmt.Errorf("Error fetching the MVLAN details: %s", err)
			}
			if len(groups) == 0 {
				return fmt.Errorf("No groups found")
			}
			// call the formating function and display it in a table
			format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(groups)
		}
	case 1:
		deviceID := args[0]
		groups, err := rc.GetAll(fmt.Sprintf(db.GetKeyPath(db.DeviceGroupPath), deviceID))
		if err != nil {
			return fmt.Errorf("Error fetching the flow details: %s", err)
		}
		if len(groups) == 0 {
			return fmt.Errorf("No groups found for the device with ID %s", deviceID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(groups)
	case 2:
		deviceID := args[0]
		groupID := args[1]
		group, err := rc.Get(fmt.Sprintf(db.GetKeyPath(db.DeviceGroupPath), deviceID), groupID)
		if err != nil {
			return fmt.Errorf("Error fetching the Group details: %s", err)
		}
		if group == nil {
			return fmt.Errorf("No group found with ID %s found for device with ID %s ", deviceID, groupID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).SingleEntry(group)
	default:
		return fmt.Errorf("Usage: %s", models.GroupUsage)
	}
	return nil
}
# [EOF] - delta:force
