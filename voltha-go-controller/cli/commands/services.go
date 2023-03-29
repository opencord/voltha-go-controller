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

// RegisterServiceCommands to register service command
func RegisterServiceCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("service", "Lists configured services", "Commands to display service information", &serviceCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register service commands : %s", err)
	}
}

// ServiceCommand structure
type ServiceCommand struct{}

var serviceCommand ServiceCommand

// Execute for execution of service command
func (serv *ServiceCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store : %s", err)
	}

	switch len(args) {
	case 0:
		serviceInfo, err := rc.GetAll(db.GetKeyPath(db.ServicePath))
		if err != nil {
			return fmt.Errorf("Error fetching the service details: %s", err)
		}
		if len(serviceInfo) == 0 {
			return fmt.Errorf("No service found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllServices, models.Vertical).MultipleEntries(serviceInfo)
	case 1:
		serviceID := args[0]
		serviceInfo, err := rc.Get(db.GetKeyPath(db.ServicePath), serviceID)
		if err != nil {
			return fmt.Errorf("Error fetching the service details: %s", err)
		}
		if serviceInfo == nil {
			return fmt.Errorf("No service found with ID %s", serviceID)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleService), serviceID))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(serviceInfo)
	default:
		return fmt.Errorf("Usage: %s", models.ServiceUsage)
	}
	return nil
}
