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

// RegisterMeterCommands to register meter command
func RegisterMeterCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("meter", "Lists all the meter profiles", "Commands to display meter profiles", &meterCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register port commands : %s", err)
	}

}

// MeterCommand structure
type MeterCommand struct{}

var meterCommand MeterCommand

// Execute for execution of meter command
func (meter *MeterCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %s ", err)
	}

	switch len(args) {
	case 0:
		meters, err := rc.GetAll(db.GetKeyPath(db.MeterPath))
		if err != nil {
			return fmt.Errorf("Error fetching the meter details: %s", err)
		}
		if len(meters) == 0 {
			return fmt.Errorf("No meters found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).MultipleEntries(meters)
	case 1:
		meterID := args[0]
		meter, err := rc.Get(db.GetKeyPath(db.MeterPath), meterID)
		if err != nil {
			return fmt.Errorf("Error fetching the meter details: %s", err)
		}
		if meter == nil {
			return fmt.Errorf("No meter found with ID %s", meterID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllPorts, models.Horizontal).SingleEntry(meter)
	default:
		return fmt.Errorf("Usage: %s", models.MeterUsage)
	}
	return nil
}
