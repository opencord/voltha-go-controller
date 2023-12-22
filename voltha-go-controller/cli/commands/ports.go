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

// RegisterPortCommands to register port command
func RegisterPortCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("port", "Lists all the logical ports", "Commands to display ports for vgc", &portCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register port commands : %s", err)
	}
}

// PortCommand structure
type PortCommand struct{}

var portCommand PortCommand

// Execute for execution of port command
func (port *PortCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		deviceIDList := DeviceIDForGetAll()
		if deviceIDList == nil {
			return fmt.Errorf("No ports found")
		}
		for _, deviceID := range deviceIDList {
			portInfo, err := rc.GetAll(fmt.Sprintf(db.GetKeyPath(db.DevicePortPath), deviceID))
			if err != nil {
				return fmt.Errorf("Error fetching the port details: %s", err)
			}
			if len(portInfo) == 0 {
				return fmt.Errorf("No ports found")
			}
			// call the formating function and display it in a table
			format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(portInfo)
		}
	case 1:
		deviceID := args[0]
		portInfo, err := rc.GetAll(fmt.Sprintf(db.GetKeyPath(db.DevicePortPath), deviceID))
		if err != nil {
			return fmt.Errorf("Error fetching the port details: %s", err)
		}
		if len(portInfo) == 0 {
			return fmt.Errorf("No ports found for Device-ID %s", deviceID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(portInfo)
	case 2:
		deviceID := args[0]
		portID := args[1]
		portInfo, err := rc.Get(fmt.Sprintf(db.GetKeyPath(db.DevicePortPath), deviceID), portID)
		if err != nil {
			return fmt.Errorf("Error fetching the port details: %s", err)
		}
		if portInfo == nil {
			return fmt.Errorf("No port found with Device-ID %s and Port-ID %s", deviceID, portID)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SinglePort), deviceID, portID))
		format.NewTable(tableTitle, models.Horizontal).SingleEntry(portInfo)
	default:
		return fmt.Errorf("Usage: %s", models.PortUsage)
	}
	return nil
}
# [EOF] - delta:force
