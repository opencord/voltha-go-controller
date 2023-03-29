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
	"fmt"
	"io"
	"log"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/voltha-go-controller/cli/database"
	"voltha-go-controller/voltha-go-controller/cli/models"
	"voltha-go-controller/voltha-go-controller/nbi"

	"github.com/guumaster/tablewriter"
)

type horizontalTable struct {
	writer *tablewriter.Table
	title  models.TableTitle
}

func newHorizontalTable(title models.TableTitle, outputBuffer io.Writer) Table {
	ht := horizontalTable{}
	ht.title = title
	ht.writer = tablewriter.NewWriter(outputBuffer)
	ht.writer.SetAlignment(tablewriter.ALIGN_RIGHT)
	return &ht
}

func (ht *horizontalTable) SingleEntry(value *database.Data) {
	values := make(map[string]*database.Data, 1)
	values["singleEntry"] = value
	ht.MultipleEntries(values)
}

func (ht *horizontalTable) SinglePortDataEntry(value map[string][]*app.VoltPort) {
	ht.MultiplePortDataEntries(value)
}

func (ht *horizontalTable) SinglePonPortDataEntry(value map[string][]*app.PonPortCfg) {
	ht.MultiplePonPortDataEntries(value)
}

func (ht *horizontalTable) SingleDataEntry(value map[string]map[string]bool) {
	ht.MultipleDataEntries(value)
}

func (ht *horizontalTable) SingleIcmpDataEntry(value map[string]map[string]int) {
	ht.MultipleIcmpDataEntries(value)
}

func (ht *horizontalTable) SingleDeviceTaskList(value map[string]map[int]*app.TaskInfo) {
	ht.MultipleDeviceTaskList(value)
}

func (ht *horizontalTable) SingleDeviceInfo(value map[string]map[string]*nbi.DeviceInfo) {
	ht.MultipleDeviceInfo(value)
}

func (ht *horizontalTable) SingleDhcpSessionInfo(value []*nbi.DhcpSessionInfo) {
	ht.MultipleDhcpSessionInfo(value)
}

func (ht *horizontalTable) MultipleEntries(values map[string]*database.Data) {
	for _, value := range values {
		var data map[string]interface{}
		err := json.Unmarshal(value.Value, &data)
		if err != nil {
			log.Fatalf("Data saved in database seems to be corrupted: %s", err)
		}
		sortedData := sortData(data)
		var header []string
		for i := range sortedData {
			header = append(header, sortedData[i].Key)
		}
		ht.writer.Append(header)
		ht.writer.AddSeparator()
		break
	}
	var rows [][]string
	for _, value := range values {
		var data map[string]interface{}
		err := json.Unmarshal(value.Value, &data)
		if err != nil {
			log.Fatalf("Data saved in database seems to be corrupted: %s", err)
		}
		sortedData := sortData(data)
		var row []string
		for i := range sortedData {
			switch (sortedData[i].Value).(type) {
			case float64:
				row = append(row, fmt.Sprintf("%d", int((sortedData[i].Value).(float64))))
			case uint64, uint32:
				row = append(row, fmt.Sprintf("%d", sortedData[i].Value))
			default:
				row = append(row, fmt.Sprintf("%v", sortedData[i].Value))
			}
		}
		rows = append(rows, row)
	}
	ht.writer.AppendBulk(rows)
	ht.writer.Render()
}

func (ht *horizontalTable) MultipleDataEntries(configs map[string]map[string]bool) {
	// TO DO
}

func (ht *horizontalTable) MultipleIcmpDataEntries(configs map[string]map[string]int) {
	// TO DO
}

func (ht *horizontalTable) MultiplePortDataEntries(configs map[string][]*app.VoltPort) {
	// TO DO
}

func (ht *horizontalTable) MultiplePonPortDataEntries(configs map[string][]*app.PonPortCfg) {
	// TO DO
}

func (ht *horizontalTable) MultipleDeviceTaskList(configs map[string]map[int]*app.TaskInfo) {
	// TO DO
}

func (ht *horizontalTable) MultipleDeviceInfo(configs map[string]map[string]*nbi.DeviceInfo) {
	// TO DO
}

func (ht *horizontalTable) MultipleDhcpSessionInfo(configs []*nbi.DhcpSessionInfo) {
	// TO DO
}
