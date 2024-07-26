/*
* Copyright 2022-2024present Open Networking Foundation
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

	flags "github.com/jessevdk/go-flags"
)

// RegisterCacheIcmpCommands to register cache icmp command
func RegisterCacheIcmpCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("cacheicmp", "Lists Cache ICMPs", "Commands to display Cache ICMPs", &cacheicmpCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register cache icmp commands : %s", err)
	}
}

// CacheIcmpCommand structure
type CacheIcmpCommand struct{}

var cacheicmpCommand CacheIcmpCommand

// Execute for execution of cache icmp command
func (ic *CacheIcmpCommand) Execute(args []string) error {
	switch len(args) {
	case 0:
		// url to fetch cache icmp
		baseURL := database.IcmpCachePath

		body, err := GetAPIData(baseURL)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}

		data := map[string]map[string]int{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling cache icmp details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No cache icmp found")
		}

		// call the formating function and display it in a table
		format.NewTable(models.AllCacheIcmps, models.Vertical).MultipleIcmpDataEntries(data)

	case 1:
		deviceID := args[0]
		// url to fetch cache icmp
		baseURL := database.IcmpCachePath
		url := fmt.Sprintf("%s%s", baseURL, deviceID)
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}

		data := map[string]map[string]int{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling cache icmp details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No cache icmp found with device-id: %s", deviceID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleCacheIcmp), deviceID))
		format.NewTable(tableTitle, models.Vertical).SingleIcmpDataEntry(data)

	default:
		return fmt.Errorf("Usage: %s", models.CacheIcmpUsage)
	}
	return nil
}
