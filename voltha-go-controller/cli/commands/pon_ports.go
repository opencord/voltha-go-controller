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

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"

	flags "github.com/jessevdk/go-flags"
)

// RegisterPonPortInfoCommands to register pon port info command
func RegisterPonPortInfoCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("ponports", "Lists PON Port", "Commands to display cached PON Port", &ponPortCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register pon port commands : %s", err)
	}
}

// PonPortCommand structure
type PonPortCommand struct{}

var ponPortCommand PonPortCommand

// Execute for execution of pon port info command
func (ic *PonPortCommand) Execute(args []string) error {
	switch len(args) {
	case 0:
		// url to fetch cache ports
		baseURL := database.PonPortsPath
		body, err := GetAPIData(baseURL)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}
		data := make(map[string][]*app.PonPortCfg)
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling PON ports details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No PON ports found")
		}

		// call the formating function and display it in a table
		format.NewTable(models.AllCachePorts, models.Vertical).MultiplePonPortDataEntries(data)
	case 1:
		deviceID := args[0]
		// url to fetch PON port
		baseURL := database.PonPortsPath
		url := fmt.Sprintf("%s%s", baseURL, deviceID)
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}
		data := make(map[string][]*app.PonPortCfg)
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling PON port details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No PON port found with device-id: %s", deviceID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SinglePONPorts), deviceID))
		format.NewTable(tableTitle, models.Vertical).SinglePonPortDataEntry(data)
	default:
		return fmt.Errorf("Usage: %s", models.PonPortsUsage)
	}
	return nil
}
# [EOF] - delta:force
