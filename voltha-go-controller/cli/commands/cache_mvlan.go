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

	flags "github.com/jessevdk/go-flags"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"
)

// RegisterCacheMvlanCommands to register cache mvlan command
func RegisterCacheMvlanCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("cachemvlan", "Lists Cache Mvlans", "Commands to display Cache Mvlans", &cachemvlanCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register cache mvlan commands : %s", err)
	}

}

// CacheMvlanCommand structure
type CacheMvlanCommand struct{}

var cachemvlanCommand CacheMvlanCommand

// Execute for execution of cache mvlan command
func (ic *CacheMvlanCommand) Execute(args []string) error {
	switch len(args) {
	case 0:
		// url to fetch cache mvlan
		baseURL := database.MvlanCachePath
		body, err := GetAPIData(baseURL)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}

		data := map[string]map[string]bool{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling cache mvlan details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No cache mvlan found")
		}

		// call the formating function and display it in a table
		format.NewTable(models.AllCacheMvlans, models.Vertical).MultipleDataEntries(data)

	case 1:
		deviceID := args[0]
		// url to fetch cache mvlan
		baseURL := database.MvlanCachePath
		url := fmt.Sprintf("%s%s", baseURL, deviceID)
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}

		data := map[string]map[string]bool{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling cache mvlan details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No cache mvlan found with device-id: %s", deviceID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleCacheMvlan), deviceID))
		format.NewTable(tableTitle, models.Vertical).SingleDataEntry(data)

	default:
		return fmt.Errorf("Usage: %s", models.CacheMvlanUsage)
	}
	return nil
}
