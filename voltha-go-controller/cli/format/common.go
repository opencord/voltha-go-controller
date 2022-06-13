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

package format

import (
	"os"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/models"
	"voltha-go-controller/voltha-go-controller/nbi"
)

// Table interface for entry type in the table
type Table interface {
	// For database based commands
	SingleEntry(config *database.Data)
	MultipleEntries(configs map[string]*database.Data)
	// For API based Cache commands
	SingleDataEntry(config map[string]map[string]bool)
	MultipleDataEntries(configs map[string]map[string]bool)
	// For API based ICMPv6 Cache commands
	SingleIcmpDataEntry(config map[string]map[string]int)
	MultipleIcmpDataEntries(configs map[string]map[string]int)
	// For API based Cache Port commands
	SinglePortDataEntry(config map[string][]*app.VoltPort)
	MultiplePortDataEntries(configs map[string][]*app.VoltPort)
	// For API based TaskList commands
	SingleDeviceTaskList(config map[string]map[int]*app.TaskInfo)
	MultipleDeviceTaskList(configs map[string]map[int]*app.TaskInfo)
	// For API based Device Info commands
	SingleDeviceInfo(config map[string]map[string]*nbi.DeviceInfo)
	MultipleDeviceInfo(configs map[string]map[string]*nbi.DeviceInfo)
	// For API based PON Ports commands
	SinglePonPortDataEntry(config map[string][]*app.PonPortCfg)
	MultiplePonPortDataEntries(configs map[string][]*app.PonPortCfg)
	// For API based DHCP Session Info Commands
	MultipleDhcpSessionInfo(config []*nbi.DhcpSessionInfo)
	SingleDhcpSessionInfo(config []*nbi.DhcpSessionInfo)
}

// NewTable function to create a new table
func NewTable(title models.TableTitle, orientation models.Orientation) Table {
	switch orientation {
	case models.Horizontal:
		return newHorizontalTable(title, os.Stdout)
	case models.Vertical:
		return newVerticalTable(title, os.Stdout)
	}
	return newHorizontalTable(title, os.Stdout)
}
