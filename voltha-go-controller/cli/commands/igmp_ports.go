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

// RegisterIGMPPortCommands to register igmp port command
func RegisterIGMPPortCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("igmpport", "Lists configured IGMP ports", "Commands to display igmp port information", &igmpportCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register service commands : %s", err)
	}

}

// IGMPPortCommand structure
type IGMPPortCommand struct{}

var igmpportCommand IGMPPortCommand

// Execute for execution of igmp port command
func (serv *IGMPPortCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		return fmt.Errorf("Missing all arguements, Correct format is: igmpport [mvlan] [channel-ip] [device-id]")
	case 1:
		return fmt.Errorf("Missing [channel-ip] and [device-id], Correct format is: igmpport [mvlan] [channel-ip] [device-id]")
	case 2:
		return fmt.Errorf("Missing [device-id], Correct format is: igmpport [mvlan] [channel-ip] [device-id]")
	case 3:
		mvlan := args[0]
		channelIP := args[1]
		deviceID := args[2]
		key := mvlan + "/" + channelIP + "/" + deviceID + "/"
		path := db.GetKeyPath(db.IgmpPortPath) + key
		igmpPortInfo, err := rc.GetAll(path)
		if err != nil {
			return fmt.Errorf("Error fetching the  details: %s", err)
		}
		if igmpPortInfo == nil {
			return fmt.Errorf("No igmp port found with mvlan %s channel-ip %s device-id %s", mvlan, channelIP, deviceID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllIGMPPorts, models.Vertical).MultipleEntries(igmpPortInfo)

	case 4:
		mvlan := args[0]
		channelIP := args[1]
		deviceID := args[2]
		ports := args[3]
		key := mvlan + "/" + channelIP + "/" + deviceID + "/"
		path := db.GetKeyPath(db.IgmpPortPath) + key
		igmpPortInfo, err := rc.Get(path, ports)
		if err != nil {
			return fmt.Errorf("Error fetching the  details: %s", err)
		}
		if igmpPortInfo == nil {
			return fmt.Errorf("No igmp port found with mvlan %s channel-ip %s device-id %s ports %s", mvlan, channelIP, deviceID, ports)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleIGMPPort), mvlan, channelIP, deviceID, ports))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(igmpPortInfo)
	default:
		return fmt.Errorf("Usage: %s", models.IGMPPortUsage)
	}
	return nil
}
