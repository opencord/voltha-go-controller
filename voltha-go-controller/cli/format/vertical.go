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
	"encoding/json"
	"io"
	"log"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/models"
	"voltha-go-controller/voltha-go-controller/nbi"

	"github.com/guumaster/tablewriter"
)

type verticalTable struct {
	writer *tablewriter.Table
	title  models.TableTitle
}

func newVerticalTable(title models.TableTitle, outputBuffer io.Writer) Table {
	vt := verticalTable{}
	vt.title = title
	vt.writer = tablewriter.NewWriter(outputBuffer)
	vt.writer.SetAlignment(tablewriter.ALIGN_LEFT)
	return &vt
}

func (vt *verticalTable) SingleEntry(config *database.Data) {
	configs := make(map[string]*database.Data, 1)
	configs["singleEntry"] = config
	vt.MultipleEntries(configs)
}

func (vt *verticalTable) SingleDataEntry(config map[string]map[string]bool) {
	vt.MultipleDataEntries(config)
}

func (vt *verticalTable) SingleIcmpDataEntry(config map[string]map[string]int) {
	vt.MultipleIcmpDataEntries(config)
}

func (vt *verticalTable) SinglePortDataEntry(config map[string][]*app.VoltPort) {
	vt.MultiplePortDataEntries(config)
}

func (vt *verticalTable) SinglePonPortDataEntry(config map[string][]*app.PonPortCfg) {
	vt.MultiplePonPortDataEntries(config)
}

func (vt *verticalTable) SingleDeviceTaskList(config map[string]map[int]*app.TaskInfo) {
	vt.MultipleDeviceTaskList(config)
}

func (vt *verticalTable) SingleDeviceInfo(config map[string]map[string]*nbi.DeviceInfo) {
	vt.MultipleDeviceInfo(config)
}

func (vt *verticalTable) SingleDhcpSessionInfo(config []*nbi.DhcpSessionInfo) {
	vt.MultipleDhcpSessionInfo(config)
}

func (vt *verticalTable) MultipleEntries(configs map[string]*database.Data) {
	var rows [][]string
	isMultiline := len(configs) > 1
	for key, value := range configs {
		var data map[string]interface{}
		err := json.Unmarshal(value.Value, &data)
		if err != nil {
			log.Fatalf("Data saved in database seems to be corrupted: %s", err)
		}
		sortedData := sortData(data)
		if isMultiline {
			vt.writer.Append([]string{"ID", key})
			vt.writer.AddSeparator()
		}
		for i := range sortedData {
			parseAndAppendRowNew(vt.writer, sortedData[i].Key, sortedData[i].Value, "", &rows)
		}
		if isMultiline {
			vt.writer.AddSeparator()
		}
	}
	vt.writer.Render()
}

// Formatting for Cache API commands
func (vt *verticalTable) MultipleDataEntries(configs map[string]map[string]bool) {
	var rows [][][]string
	isMultiline := len(configs) > 1

	// adding table header
	parseAndAppendHeaderRowForAPICmd(vt.writer, "DeviceID", "vlan", "status", "", &rows)
	vt.writer.AddSeparator()

	for key, value := range configs {
		data := value
		if isMultiline {
			vt.writer.Append([]string{"ID", key})
			vt.writer.AddSeparator()
		}
		for k, v := range data {
			parseAndAppendRowNewForAPICmd(vt.writer, key, k, v, "", &rows)
		}
		if isMultiline {
			vt.writer.AddSeparator()
		}
	}
	vt.writer.Render()
}

// Formatting for Cache API commands
func (vt *verticalTable) MultipleIcmpDataEntries(configs map[string]map[string]int) {
	var rows [][][]string
	isMultiline := len(configs) > 1

	// adding table header
	parseAndAppendHeaderRowForAPICmd(vt.writer, "DeviceID", "vlan", "status", "", &rows)
	vt.writer.AddSeparator()

	for key, value := range configs {
		data := value
		if isMultiline {
			vt.writer.Append([]string{"ID", key})
			vt.writer.AddSeparator()
		}
		for k, v := range data {
			parseAndAppendRowNewForIcmpAPICmd(vt.writer, key, k, v, "", &rows)
		}
		if isMultiline {
			vt.writer.AddSeparator()
		}
	}
	vt.writer.Render()
}

// Formatting for API based task list commands
func (vt *verticalTable) MultipleDeviceTaskList(configs map[string]map[int]*app.TaskInfo) {
	var rows [][][][][]string
	isMultiline := len(configs) > 1

	// adding table header
	parseAndAppendHeaderRowForTaskList(vt.writer, "DeviceID", "Position", "Task-ID", "Task-Name", "Timestamp", "", &rows)
	vt.writer.AddSeparator()

	for key, value := range configs {
		data := value
		if isMultiline {
			vt.writer.Append([]string{"ID", key})
			vt.writer.AddSeparator()
		}
		for k, v := range data {
			parseAndAppendRowNewForTaskList(vt.writer, key, k, v.ID, v.Name, v.Timestamp, "", &rows)
		}
		if isMultiline {
			vt.writer.AddSeparator()
		}
	}
	vt.writer.Render()
}

// Formatting for Port Cache API command
func (vt *verticalTable) MultiplePortDataEntries(configs map[string][]*app.VoltPort) {
	// update in case voltPort is updated.
	var rows [][][][][][]string
	isMultiline := len(configs) > 1

	// adding table header
	parseAndAppendHeaderRowForPortAPI(vt.writer, "DeviceID", "ID", "Name", "Device", "Type", "State", "ActiveChannelCount", "", &rows)
	vt.writer.AddSeparator()

	for key, value := range configs {
		data := value
		for i := range data {
			if isMultiline {
				vt.writer.Append([]string{"ID", key})
				vt.writer.AddSeparator()
			}
			var portType string
			var portState string

			// Checking for port type
			if data[i].Type == 0 {
				portType = "Access Port"
			} else {
				portType = "NNI port"
			}

			// Checking for port state
			if data[i].State == 0 {
				portState = "DOWN"
			} else {
				portState = "UP"
			}

			parseAndAppendRowNewForPortAPI(vt.writer, key, data[i].ID, data[i].Name, data[i].Device, portType, portState, data[i].ActiveChannels, "", &rows)
			if isMultiline {
				vt.writer.AddSeparator()
			}
		}
	}
	vt.writer.Render()
}

// Formatting for PON Port API command
func (vt *verticalTable) MultiplePonPortDataEntries(configs map[string][]*app.PonPortCfg) {
	// update in case voltPort is updated.
	var rows [][][][][][]string
	isMultiline := len(configs) > 1

	// adding table header
	parseAndAppendHeaderRowForPonPortAPI(vt.writer, "DeviceID", "PONID", "McastKPIsFlag", "MaxActiveChannels", "CurrActiveChannels", "", &rows)
	vt.writer.AddSeparator()

	for key, value := range configs {
		data := value
		for i := range data {
			if isMultiline {
				vt.writer.Append([]string{"ID", key})
				vt.writer.AddSeparator()
			}

			parseAndAppendNewRowForPonPortAPI(vt.writer, key, data[i].PortID, data[i].EnableMulticastKPI, data[i].MaxActiveChannels, data[i].ActiveIGMPChannels, "", &rows)
			if isMultiline {
				vt.writer.AddSeparator()
			}
		}
	}
	vt.writer.Render()
}

// Formatting for API based device info commands
func (vt *verticalTable) MultipleDeviceInfo(configs map[string]map[string]*nbi.DeviceInfo) {
	var rows [][][][][]string
	isMultiline := len(configs) > 1

	// adding table header
	parseAndAppendRowNewForDeviceInfo(vt.writer, "DeviceID", "Serial Number", "State", "", &rows)
	vt.writer.AddSeparator()

	for deviceID, data := range configs {
		if isMultiline {
			vt.writer.Append([]string{"ID", deviceID})
			vt.writer.AddSeparator()
		}
		for serialNum, deviceInfo := range data {
			if isMultiline {
				vt.writer.AddSeparator()
			}
			parseAndAppendRowNewForDeviceInfo(vt.writer, deviceID, serialNum, deviceInfo.State, "", &rows)
			if isMultiline {
				vt.writer.AddSeparator()
			}
		}
	}
	vt.writer.Render()
}

// Formatting for Api based DHCP session command
func (vt *verticalTable) MultipleDhcpSessionInfo(value []*nbi.DhcpSessionInfo) {
	var rows [][][][][][][][][][][][]string
	isMultiline := len(value) > 1

	// adding table header
	parseAndAppendRowNewForDhcpCmd(vt.writer, "DeviceID", "UniPort", "SVlan", "CVlan", "UniVlan", "MacAddress", "IpAddress", "IPv6Address", "State-DHCPv4", "State-DHCP-v6", "LeaseTime IPv4", "LeaseTime IPv6", "", &rows)
	vt.writer.AddSeparator()

	for i := range value {
		if isMultiline {
			vt.writer.AddSeparator()
		}
		var rState string
		var rStatev6 string

		// Checking for state-DHCPv4
		switch value[i].State {
		case "0":
			rState = "None"
		case "1":
			rState = "Discover"
		case "2":
			rState = "Offer"
		case "3":
			rState = "Request"
		case "4":
			rState = "Ack"
		case "5":
			rState = "NAK"
		case "6":
			rState = "Release"
		}

		// Checking for state-DHCPv6
		switch value[i].Statev6 {
		case "0":
			rStatev6 = "None"
		case "1":
			rStatev6 = "Solicit"
		case "2":
			rStatev6 = "Reply"
		case "3":
			rStatev6 = "Release"
		}

		parseAndAppendRowNewForDhcpCmd(vt.writer, value[i].DeviceID, value[i].Uniport, value[i].Svlan, value[i].Cvlan, value[i].UniVlan, value[i].MacAddress, value[i].IPAddress, value[i].Ipv6Address, rState, rStatev6, value[i].LeaseTime, value[i].LeaseTimev6, "", &rows)
	}
	vt.writer.Render()
}
