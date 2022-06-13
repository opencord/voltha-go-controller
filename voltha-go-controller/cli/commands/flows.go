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

// RegisterFlowCommands to register flow command.
func RegisterFlowCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("flows", "Lists configured flows", "Commands to query flows", &flowCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register flow commands : %s", err)
	}

}

// FlowCommand structure
type FlowCommand struct{}

var flowCommand FlowCommand

// Execute for execution of flow command
func (ic *FlowCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v", err)
	}

	switch len(args) {
	case 0:
		deviceIDList := DeviceIDForGetAll()

		if deviceIDList == nil {
			return fmt.Errorf("No flows found")
		}
		for _, deviceID := range deviceIDList {
			flows, err := rc.GetAll(fmt.Sprintf(db.GetKeyPath(db.DeviceFlowPath), deviceID))
			if err != nil {
				return fmt.Errorf("Error fetching the flow details: %s", err)
			}
			if len(flows) == 0 {
				return fmt.Errorf("No flows found")
			}
			// call the formating function and display it in a table
			format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(flows)
		}
	case 1:
		deviceID := args[0]
		flows, err := rc.GetAll(fmt.Sprintf(db.GetKeyPath(db.DeviceFlowPath), deviceID))
		if err != nil {
			return fmt.Errorf("Error fetching the flow details: %s", err)
		}
		if len(flows) == 0 {
			return fmt.Errorf("No flows found for the device with ID %s", deviceID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(flows)
	case 2:
		deviceID := args[0]
		flowID := args[1]
		flows, err := rc.Get(fmt.Sprintf(db.GetKeyPath(db.DeviceFlowPath), deviceID), flowID)
		if err != nil {
			return fmt.Errorf("Error fetching the flow details: %s", err)
		}
		if flows == nil {
			return fmt.Errorf("No flows with ID %s found for the device with ID %s", flowID, deviceID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).SingleEntry(flows)
	default:
		return fmt.Errorf("Usage: %s", models.FlowUsage)
	}
	return nil
}
