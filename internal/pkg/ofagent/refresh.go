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

package ofagent

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"voltha-go-controller/internal/pkg/intf"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
	"github.com/opencord/voltha-protos/v5/go/voltha"
)

func (ofa *OFAgent) synchronizeDeviceList(ctx context.Context) {
	// Send reconnection indication to the devices already known
	for _, ofc := range ofa.clientMap {
		ofc.ConnectInd(context.TODO(), intf.DeviceReDisc)
	}

	// Refresh once to get everything started
	ofa.refreshDeviceList()

	tick := time.NewTicker(ofa.DeviceListRefreshInterval)
loop:
	for {
		select {
		case <-ctx.Done():
			logger.Errorw(ctx, "Context Done", log.Fields{"Context": ctx})
			break loop
		case <-tick.C:
			ofa.refreshDeviceList()
		}
	}
	tick.Stop()
}

func (ofa *OFAgent) refreshDeviceList() {
	// If we exit, assume disconnected
	if ofa.volthaClient == nil {
		logger.Error(ctx, "no-voltha-connection")
		ofa.events <- ofaEventVolthaDisconnected
		return
	}
	deviceList, err := ofa.volthaClient.Get().ListLogicalDevices(context.Background(), &empty.Empty{})
	if err != nil {
		logger.Errorw(ctx, "ofagent failed to query device list from voltha",
			log.Fields{"error": err})
		ofa.events <- ofaEventVolthaDisconnected
		return
	}

	var toAdd []int
	var toDel []string
	var deviceIDMap = make(map[string]string)
	for index, d := range deviceList.Items {
		deviceID := d.Id
		deviceIDMap[deviceID] = deviceID
		if ofa.clientMap[deviceID] == nil {
			toAdd = append(toAdd, index)
		}
	}
	for key := range ofa.clientMap {
		deviceID, ok := deviceIDMap[key]
		if !ok || (ok && deviceID == "") {
			toDel = append(toDel, key)
		}
	}
	logger.Debugw(ctx, "Device Refresh", log.Fields{"ToAdd": toAdd, "ToDel": toDel})
	for i := 0; i < len(toAdd); i++ {
		device := deviceList.Items[toAdd[i]]
		serialNum := device.Desc.SerialNum
		// If the blocked device list contain device serial number, do not add OFClient.
		if ofa.OFClientAgent.IsBlockedDevice(serialNum) {
			logger.Debugw(ctx, "Device Serial Number is present in the blocked device list", log.Fields{"device-serial-number": serialNum})
		} else {
			ofa.addOFClient(device) // client is started in addOFClient
		}
	}

	for i := 0; i < len(toDel); i++ {
		ofa.OFClientAgent.DelDevice(toDel[i])
		ofa.mapLock.Lock()
		delete(ofa.clientMap, toDel[i])
		ofa.mapLock.Unlock()
	}
}

func (ofa *OFAgent) addOFClient(device *voltha.LogicalDevice) intf.IOFClient {
	logger.Warnw(ctx, "GrpcClient addClient called ", log.Fields{"device-id": device.Id})
	ofa.mapLock.Lock()
	defer ofa.mapLock.Unlock()
	var serialNum = "Unknown"
	if device.Desc != nil {
		serialNum = device.Desc.SerialNum
	}
	ofc := ofa.clientMap[device.Id]
	if ofc == nil {
		ofa.OFClientAgent.AddNewDevice(&intf.OFClientCfg{
			DeviceID:         device.Id,
			SerialNum:        serialNum,
			SouthBoundID:     device.RootDeviceId,
			VolthaClient:     ofa.volthaClient,
			PacketOutChannel: ofa.packetOutChannel,
		})

	}
	logger.Debugw(ctx, "Finished with addClient", log.Fields{"deviceID": device.Id})
	return ofc
}

//AddClientToClientMap - called by controller once device obj is created
func (ofa *OFAgent) AddClientToClientMap(deviceID string, ofc intf.IOFClient) {
	ofa.mapLock.Lock()
	defer ofa.mapLock.Unlock()

	if ofc != nil {
		ofa.clientMap[deviceID] = ofc
	}
}

func (ofa *OFAgent) getOFClient(deviceID string) intf.IOFClient {
	if ofc, ok := ofa.clientMap[deviceID]; ok {
		return ofc
	}
	return nil
}
