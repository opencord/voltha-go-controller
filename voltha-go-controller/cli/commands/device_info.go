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

// RegisterDeviceInfoCommands to register device info command
func RegisterDeviceInfoCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("device", "Lists Device Info", "Commands to display device info", &deviceinfoCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register device info commands : %s", err)
	}
}

// DeviceInfoCommand structure
type DeviceInfoCommand struct{}

var deviceinfoCommand DeviceInfoCommand

// Execute for execution of dveice info command
func (ic *DeviceInfoCommand) Execute(args []string) error {
	switch len(args) {
	case 0:
		// url to fetch device info
		baseURL := database.DeviceCommandPath
		body, err := GetAPIData(baseURL)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}
		data := map[string]map[string]*nbi.DeviceInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling device info details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No device found")
		}
		for deviceID, value := range data {
			header := fmt.Sprintf("==========================Device Information for Device ID:%s=========================", deviceID)
			fmt.Println(header)
			// call the formating function and display it in a table
			deviceInfo := map[string]map[string]*nbi.DeviceInfo{}
			deviceInfo[deviceID] = value
			format.NewTable(models.AllDeviceInfo, models.Vertical).MultipleDeviceInfo(deviceInfo)
		}

	case 1:
		deviceID := args[0]
		// url to fetch device info
		baseURL := database.DeviceCommandPath
		url := fmt.Sprintf("%s%s", baseURL, deviceID)
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}
		data := map[string]map[string]*nbi.DeviceInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling device info details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No device found with device-id: %s", deviceID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleDeviceInfo), deviceID))
		format.NewTable(tableTitle, models.Vertical).SingleDeviceInfo(data)
	default:
		return fmt.Errorf("Usage: %s", models.DeviceInfoUsage)
	}
	return nil
}
# [EOF] - delta:force
