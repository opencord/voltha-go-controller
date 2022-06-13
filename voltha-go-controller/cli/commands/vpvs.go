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

// RegisterVpvsCommands to register vpvs command
func RegisterVpvsCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("vpvs", "Lists configured vpvs", "Commands to display vpvs information", &vpvsCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register service commands : %s", err)
	}

}

// VpvsCommand structure
type VpvsCommand struct{}

var vpvsCommand VpvsCommand

// Execute for execution of vpvs command
func (serv *VpvsCommand) Execute(args []string) error {
	rc, err := database.GetRedisClient()
	if err != nil {
		return fmt.Errorf("Failed to make connection to KV Store: %s ", err)
	}

	switch len(args) {
	case 0:
		vpvInfo, err := rc.GetAll(db.GetKeyPath(db.VpvPath))
		if err != nil {
			return fmt.Errorf("Error fetching the vpvs details: %s", err)
		}
		if len(vpvInfo) == 0 {
			return fmt.Errorf("No vpvs found")
		}
		// call the formating function and display it in a table
		format.NewTable(models.AllVpvs, models.Vertical).MultipleEntries(vpvInfo)
	case 1:
		return fmt.Errorf("Missing [svlan] and [cvlan]: Correct format is vpvs [port] [svlan] [cvlan]")
	case 2:
		return fmt.Errorf("Missing [cvlan]: Correct format is vpvs [port] [svlan] [cvlan]")
	case 3:
		port := args[0]
		svlan := args[1]
		cvlan := args[2]
		key := fmt.Sprintf("%s%s%s", port, svlan, cvlan)
		vpvInfo, err := rc.Get(db.GetKeyPath(db.VpvPath), key)
		if err != nil {
			return fmt.Errorf("Error fetching the vpv details: %s", err)
		}
		if vpvInfo == nil {
			return fmt.Errorf("No vpvs found with Port %s SVlan %s CVlan %s", port, svlan, cvlan)
		}
		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleVpv), port, svlan, cvlan))
		format.NewTable(tableTitle, models.Vertical).SingleEntry(vpvInfo)
	default:
		return fmt.Errorf("Usage: %s", models.VpvsUsage)
	}
	return nil
}
