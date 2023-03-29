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
	"fmt"
	"reflect"

	"github.com/guumaster/tablewriter"
)

// To append rows for database based commands.
func parseAndAppendRowNew(t *tablewriter.Table, key string, value interface{}, tab string, row *[][]string) {
	switch reflect.ValueOf(value).Kind() {
	case reflect.Map:
		t.Append([]string{tab + key, ""})
		newValue := value.(map[string]interface{})
		pl := sortData(newValue)
		for i := range pl {
			parseAndAppendRowNew(t, pl[i].Key, pl[i].Value, tab+" ", row)
		}
	default:
		switch value := value.(type) {
		case float64:
			t.Append([]string{tab + key, fmt.Sprint(float64(value))})
		case uint64, uint32:
			t.Append([]string{tab + key, fmt.Sprintf("%d", value)})
		default:
			t.Append([]string{tab + key, fmt.Sprintf("%v", value)})
		}
	}
}

// parseAndAppendRowNewForAPICmd to append rows for api based commands.
func parseAndAppendRowNewForAPICmd(t *tablewriter.Table, key string, field string, value bool, tab string, row *[][][]string) {
	t.Append([]string{tab + string(key), fmt.Sprintf("%v", field), fmt.Sprintf("%v", value)})
}

// parseAndAppendRowNewForIcmpAPICmd to append rows for api based commands.
func parseAndAppendRowNewForIcmpAPICmd(t *tablewriter.Table, key string, field string, value int, tab string, row *[][][]string) {
	t.Append([]string{tab + string(key), fmt.Sprintf("%v", field), fmt.Sprintf("%d", value)})
}

// parseAndAppendHeaderRowForAPICmd adding table-header for api based commands.
func parseAndAppendHeaderRowForAPICmd(t *tablewriter.Table, deviceID string, vlan string, status string, tab string, row *[][][]string) {
	t.Append([]string{tab + string(deviceID), fmt.Sprintf("%v", vlan), fmt.Sprintf("%v", status)})
}

// parseAndAppendRowNewForPortAPI to append row for cache port command.
func parseAndAppendRowNewForPortAPI(t *tablewriter.Table, key string, id uint32, name string, device string, ptype string, state string, count uint32, tab string, row *[][][][][][]string) {
	t.Append([]string{tab + string(key), fmt.Sprintf("%v", id), fmt.Sprintf("%v", name), fmt.Sprintf("%v", device), fmt.Sprintf("%v", ptype), fmt.Sprintf("%v", state), fmt.Sprintf("%v", count)})
}

// parseAndAppendHeaderRowForPortAPI adding table header for port cache command.
func parseAndAppendHeaderRowForPortAPI(t *tablewriter.Table, key string, id string, name string, device string, ptype string, state string, count string, tab string, row *[][][][][][]string) {
	t.Append([]string{tab + string(key), fmt.Sprintf("%v", id), fmt.Sprintf("%v", name), fmt.Sprintf("%v", device), fmt.Sprintf("%v", ptype), fmt.Sprintf("%v", state), fmt.Sprintf("%v", count)})
}

// parseAndAppendHeaderRowForPonPortAPI adding table header for PON port command.
func parseAndAppendHeaderRowForPonPortAPI(t *tablewriter.Table, key string, id string, kpiFlag string, maxActChan string, currChan string, tab string, row *[][][][][][]string) {
	t.Append([]string{tab + string(key), fmt.Sprintf("%v", id), fmt.Sprintf("%v", kpiFlag), fmt.Sprintf("%v", maxActChan), fmt.Sprintf("%v", currChan)})
}

// parseAndAppendNewRowForPonPortAPI adding table row for PON port command.
func parseAndAppendNewRowForPonPortAPI(t *tablewriter.Table, key string, id uint32, kpiFlag bool, maxActChan uint32, currChan uint32, tab string, row *[][][][][][]string) {
	t.Append([]string{tab + string(key), fmt.Sprintf("%v", id), fmt.Sprintf("%v", kpiFlag), fmt.Sprintf("%v", maxActChan), fmt.Sprintf("%v", currChan)})
}

// parseAndAppendHeaderRowForTaskList adding table-header for task list command.
func parseAndAppendHeaderRowForTaskList(t *tablewriter.Table, deviceID string, position string, taskID string, taskName string, time string, tab string, row *[][][][][]string) {
	t.Append([]string{tab + string(deviceID), fmt.Sprintf("%v", position), fmt.Sprintf("%v", taskID), fmt.Sprintf("%v", taskName), fmt.Sprintf("%v", time)})
}

// parseAndAppendRowNewForTaskList adding new row for task list command.
func parseAndAppendRowNewForTaskList(t *tablewriter.Table, deviceID string, position int, taskID string, taskName string, time string, tab string, row *[][][][][]string) {
	t.Append([]string{tab + string(deviceID), fmt.Sprintf("%v", position), fmt.Sprintf("%v", taskID), fmt.Sprintf("%v", taskName), fmt.Sprintf("%v", time)})
}

// parseAndAppendRowNewForDeviceInfo adding new row for device info command.
func parseAndAppendRowNewForDeviceInfo(t *tablewriter.Table, deviceID string, serialNum string, state string, tab string, row *[][][][][]string) {
	t.Append([]string{tab + string(deviceID), fmt.Sprintf("%v", serialNum), fmt.Sprintf("%v", state)})
}

// parseAndAppendRowNewForDhcpCmd adding new row for api based dhcp command.
func parseAndAppendRowNewForDhcpCmd(t *tablewriter.Table, deviceID string, port string, svlan string, cvlan string, univlan string, macAddress string, ipAddress string, ipv6Address string, state string, statev6 string, leaseTime string, leaseTimev6 string, tab string, row *[][][][][][][][][][][][]string) {
	t.Append([]string{tab + string(deviceID), fmt.Sprintf("%v", port), fmt.Sprintf("%v", svlan), fmt.Sprintf("%v", cvlan), fmt.Sprintf("%v", univlan), fmt.Sprintf("%v", macAddress), fmt.Sprintf("%v", ipAddress), fmt.Sprintf("%v", ipv6Address), fmt.Sprintf("%v", state), fmt.Sprintf("%v", statev6), fmt.Sprintf("%v", leaseTime), fmt.Sprintf("%v", leaseTimev6)})
}
