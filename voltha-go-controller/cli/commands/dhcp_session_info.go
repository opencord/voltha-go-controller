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
	"encoding/json"
	"fmt"
	"log"

	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"
	"voltha-go-controller/voltha-go-controller/nbi"

	flags "github.com/jessevdk/go-flags"
)

// RegisterDHCPSessionInfoCommands to register dhcp session info command
func RegisterDHCPSessionInfoCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("dhcpsession", "Lists DHCP Session Info", "Commands to display dhcp session info", &dhcpSessionInfoCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register dhcp session info commands : %s", err)
	}
}

// DhcpSessionInfoCommand structure
type DhcpSessionInfoCommand struct{}

var dhcpSessionInfoCommand DhcpSessionInfoCommand

// Execute for execution of dhcp session info command
func (ic *DhcpSessionInfoCommand) Execute(args []string) error {
	switch len(args) {
	case 0:
		return fmt.Errorf("Missing all arguments, Correct formats are: \n dhcpsession [device-id] \n dhcpsession [device-id] [mac] \n dhcpsession [device-id] [svlan] [cvlan] \n dhcpsession [device-id] [mac] [svlan] [cvlan]")

	case 1:
		deviceID := args[0]
		// url to fetch dhcp session info
		baseURL := database.DHCPSessionPath
		url := fmt.Sprintf("%s%s", baseURL, deviceID)
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching dhcp session data: %s", err)
		}
		data := []*nbi.DhcpSessionInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling dhcp session info details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No dhcp session info found with Device ID: %s", deviceID)
		}
		format.NewTable(models.AllDHCPSessions, models.Vertical).MultipleDhcpSessionInfo(data)

	case 2:
		deviceID := args[0]
		mac := args[1]
		path := deviceID + "/" + mac
		// url to fetch dhcp session info
		baseURL := database.DHCPSessionPath
		url := baseURL + path
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching dhcp session data: %s", err)
		}
		data := []*nbi.DhcpSessionInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling dhcp session info details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No dhcp session info found with Device ID: %s and Mac Address: %s", deviceID, mac)
		}
		format.NewTable(models.DHCPSessionsWithMAC, models.Vertical).MultipleDhcpSessionInfo(data)

	case 3:
		deviceID := args[0]
		svlan := args[1]
		cvlan := args[2]
		path := deviceID + "/" + svlan + "/" + cvlan
		// url to fetch dhcp session info
		baseURL := database.DHCPSessionPath
		url := baseURL + path
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching dhcp session data: %s", err)
		}
		data := []*nbi.DhcpSessionInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling dhcp session info details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No dhcp session info found with Device ID: %s SVLAN:%s CVLAN:%s", deviceID, svlan, cvlan)
		}
		format.NewTable(models.DHCPSessionsWithVLAN, models.Vertical).MultipleDhcpSessionInfo(data)

	case 4:
		deviceID := args[0]
		mac := args[1]
		svlan := args[2]
		cvlan := args[3]
		path := deviceID + "/" + mac + "/" + svlan + "/" + cvlan
		// url to fetch dhcp session info
		baseURL := database.DHCPSessionPath
		url := baseURL + path
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching dhcp session data: %s", err)
		}
		data := []*nbi.DhcpSessionInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling dhcp session info details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No dhcp session info found with Device ID: %s Mac-Address: %s SVLAN:%s CVLAN:%s", deviceID, mac, svlan, cvlan)
		}
		format.NewTable(models.SingleDHCPSession, models.Vertical).SingleDhcpSessionInfo(data)

	default:
		return fmt.Errorf("Usage: %s", models.DHCPSessionUsage)
	}
	return nil
}
