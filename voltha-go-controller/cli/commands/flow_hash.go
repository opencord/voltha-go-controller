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
	"fmt"
	"log"
	"strconv"
	"strings"

	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"

	flags "github.com/jessevdk/go-flags"
)

// RegisterFlowHashCommands to get Cache Flow Hash Command
func RegisterFlowHashCommands(parser *flags.Parser) {
	if _, err := parser.AddCommand("setflowhash", "Sets the flow hash for flow throttling per device", "Commands to display setflowhash", &flowHashCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register setflowhash commands : %s", err)
	}
	if _, err := parser.AddCommand("getflowhash", "gets the flow hash for flow throttling per device", "Commands to display getflowhash", &getflowHashCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register getflowhash commands : %s", err)
	}
}

// FlowHashCommand structure
type FlowHashCommand struct{}

// GetFlowHashCommand structure
type GetFlowHashCommand struct{}

var flowHashCommand FlowHashCommand

var getflowHashCommand GetFlowHashCommand

// Execute for execution of setflowhash command
func (ic *FlowHashCommand) Execute(args []string) error {
	switch len(args) {
	case 2:
		// url to fetch setflowhash
		urlpath := fmt.Sprintf(database.FlowHashPath, args[0])
		flowhash := args[1]
		hashNum, _ := strconv.ParseUint(flowhash, 10, 32)
		if hashNum < 37 || hashNum > 151 {
			return fmt.Errorf("Number not in the permissible range of 37 - 151")
		}
		if !checkPrime(int(hashNum)) {
			return fmt.Errorf("Hash number provided is not a prime")
		}

		err := PutAPIData(urlpath, strings.NewReader(flowhash))
		if err != nil {
			return fmt.Errorf("Error while setting device data: %s", err)
		}

	default:
		return fmt.Errorf("Usage: %s len of args %d", models.SetflowhashUsage, len(args))
	}
	return nil
}

// Execute for execution of getflowhash command
func (ic *GetFlowHashCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %v ", err)
	}

	switch len(args) {
	case 1:
		// url to fetch flowhash
		urlpath := fmt.Sprintf(string(database.GetFlowHashPath), args[0])

		flowhash, err := rc.GetValue(urlpath)
		if err != nil {
			return fmt.Errorf("Error while getting device flowhash: %s", err)
		}
		if flowhash == nil {
			return fmt.Errorf("Data not available for device %s", args[0])
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.GetFlowHash), args[0]))
		format.NewTable(tableTitle, models.Horizontal).SingleEntry(flowhash)

	default:
		return fmt.Errorf("Usage: %s len of args %d", models.GetflowhashUsage, len(args))
	}
	return nil
}

func checkPrime(number int) bool {
	for i := 2; i <= number/2; i++ {
		if number%i == 0 {
			return false
		}
	}
	return true
}
