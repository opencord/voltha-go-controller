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

// RegisterIGMPChannelCommands to register igmp channel command
func RegisterIGMPChannelCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("igmpchannel", "Lists configured IGMP channels", "Commands to display igmp device information", &igmpchannelCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register service commands : %s", err)
	}
}

// IGMPChannelCommand structure
type IGMPChannelCommand struct{}

var igmpchannelCommand IGMPChannelCommand

// Execute for execution of igmp channel command
func (serv *IGMPChannelCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 0:
		return fmt.Errorf("Missing all arguments, Correct format is: igmpchannel [mvlan] [group-name] [device-id]")
	case 1:
		return fmt.Errorf("Missing [group-name] and [device-id], Correct format is: igmpchannel [mvlan] [group-name] [device-id]")
	case 2:
		return fmt.Errorf("Missing [device-id], Correct format is : igmpchannel [mvlan] [group-name] [device-id]")
	case 3:
		mvlan := args[0]
		groupName := args[1]
		deviceID := args[2]
		key := mvlan + "/" + groupName + "/" + deviceID + "/"
		path := db.GetKeyPath(db.IgmpChannelPath) + key
		igmpChannelInfo, err := rc.GetAll(path)

		if err != nil {
			return fmt.Errorf("Error fetching the  details: %s", err)
		}
		if igmpChannelInfo == nil {
			return fmt.Errorf("No igmp channel found with mvlan %s group-name %s device-id %s", mvlan, groupName, deviceID)
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllIGMPChannels, models.Vertical).MultipleEntries(igmpChannelInfo)

	case 4:
		mvlan := args[0]
		groupName := args[1]
		deviceID := args[2]
		channelIP := args[3]
		key := mvlan + "/" + groupName + "/" + deviceID + "/"
		path := db.GetKeyPath(db.IgmpChannelPath) + key

		igmpChannelInfo, err := rc.Get(path, channelIP)
		if err != nil {
			return fmt.Errorf("Error fetching the  details: %s", err)
		}
		if igmpChannelInfo == nil {
			return fmt.Errorf("No igmp channel found with mvlan %s group-name %s device-id %s channel-ip %s", mvlan, groupName, deviceID, channelIP)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleIGMPChannel), mvlan, groupName, deviceID, channelIP))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(igmpChannelInfo)
	default:
		return fmt.Errorf("Usage: %s", models.IGMPChannelUsage)
	}
	return nil
}
# [EOF] - delta:force
