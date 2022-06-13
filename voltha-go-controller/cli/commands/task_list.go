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
	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/format"
	"voltha-go-controller/voltha-go-controller/cli/models"
)

// RegisterTaskListCommands to register task list command
func RegisterTaskListCommands(parser *flags.Parser) {

	if _, err := parser.AddCommand("tasklist", "Lists TaskList", "Commands to display TaskList", &tasklistCommand); err != nil {
		log.Fatalf("Unexpected error while attempting to register task list commands : %s", err)
	}

}

// TaskListCommand structure
type TaskListCommand struct{}

var tasklistCommand TaskListCommand

// Execute for execution of task list command
func (ic *TaskListCommand) Execute(args []string) error {
	switch len(args) {
	case 0:
		// url to fetch task list
		baseURL := database.TaskListPath
		body, err := GetAPIData(baseURL)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}
		data := map[string]map[int]*app.TaskInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling task list details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No task list found")
		}

		// call the formating function and display it in a table
		format.NewTable(models.AllTaskLists, models.Vertical).MultipleDeviceTaskList(data)

	case 1:
		deviceID := args[0]
		// url to fetch task list
		baseURL := database.TaskListPath
		url := fmt.Sprintf("%s%s", baseURL, deviceID)
		body, err := GetAPIData(url)
		if err != nil {
			return fmt.Errorf("Error while fetching api device data: %s", err)
		}

		data := map[string]map[int]*app.TaskInfo{}
		marshErr := json.Unmarshal([]byte(body), &data)
		if err != nil {
			return fmt.Errorf("Error while unmarshalling task list details: %s", marshErr)
		}

		if len(data) == 0 {
			return fmt.Errorf("No task list found with device-id: %s", deviceID)
		}

		// call the formating function and display it in a table
		tableTitle := models.TableTitle(fmt.Sprintf(string(models.SingleTaskList), deviceID))
		format.NewTable(tableTitle, models.Vertical).SingleDeviceTaskList(data)
	default:
		return fmt.Errorf("Usage: %s", models.TaskListUsage)
	}
	return nil
}
