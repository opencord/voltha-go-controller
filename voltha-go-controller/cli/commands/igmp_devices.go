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

// RegisterIGMPDeviceCommands to register igmp device command
func RegisterIGMPDeviceCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("igmpdevice", "Lists configured IGMP devices", "Commands to display igmp device information", &igmpdeviceCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register service commands : %s", err)
	}
}

// IGMPDeviceCommand structure
type IGMPDeviceCommand struct{}

var igmpdeviceCommand IGMPDeviceCommand

// Execute for execution of igmp device command
func (serv *IGMPDeviceCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		return fmt.Errorf("Missing all arguments, Correct format is: igmpdevice [mvlan] [group-id] [channel-ip]")
	case 1:
		return fmt.Errorf("Missing [group-id] and [channel-ip], Correct format is: igmpdevice [mvlan] [group-id] [channel-ip]")
	case 2:
		return fmt.Errorf("Missing [channel-ip], Correct format is: igmpdevice [mvlan] [group-id] [channel-ip]")
	case 3:
		mvlan := args[0]
		groupID := args[1]
		channelIP := args[2]
		key := mvlan + "/" + groupID + "/" + channelIP + "/"
		path := db.GetKeyPath(db.IgmpDevicePath) + key
		igmpDeviceInfo, err := rc.GetAll(path)
		if err != nil {
			return fmt.Errorf("Error fetching the  details: %s", err)
		}
		if igmpDeviceInfo == nil {
			return fmt.Errorf("No igmp device found with mvlan %s group-id %s channel-ip %s", mvlan, groupID, channelIP)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllIGMPDevices, models.Vertical).MultipleEntries(igmpDeviceInfo)

	case 4:
		mvlan := args[0]
		groupID := args[1]
		channelIP := args[2]
		deviceID := args[3]
		key := mvlan + "/" + groupID + "/" + channelIP + "/"
		path := db.GetKeyPath(db.IgmpDevicePath) + key

		igmpDeviceInfo, err := rc.Get(path, deviceID)
		if err != nil {
			return fmt.Errorf("Error fetching the  details: %s", err)
		}
		if igmpDeviceInfo == nil {
			return fmt.Errorf("No igmp device found with mvlan %s group-id %s channel-ip %s device-id %s", mvlan, groupID, channelIP, deviceID)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleIGMPDevice), mvlan, groupID, channelIP, deviceID))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(igmpDeviceInfo)
	default:
		return fmt.Errorf("Usage: %s", models.IGMPDeviceUsage)
	}
	return nil
}
# [EOF] - delta:force
