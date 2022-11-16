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

package vpagent

import (
	"context"
	"time"

	"voltha-go-controller/internal/pkg/intf"

	"github.com/golang/protobuf/ptypes/empty"
	"voltha-go-controller/log"
	"github.com/opencord/voltha-protos/v5/go/voltha"
)

func (vpa *VPAgent) synchronizeDeviceList(ctx context.Context) {
	// Send reconnection indication to the devices already known
	for _, vpc := range vpa.clientMap {
		vpc.ConnectInd(context.TODO(), intf.DeviceReDisc)
	}

	// Refresh once to get everything started
	vpa.refreshDeviceList(ctx)

	tick := time.NewTicker(vpa.DeviceListRefreshInterval)
loop:
	for {
		select {
		case <-ctx.Done():
			logger.Errorw(ctx, "Context Done", log.Fields{"Context": ctx})
			break loop
		case <-tick.C:
			vpa.refreshDeviceList(ctx)
		}
	}
	tick.Stop()
}

func (vpa *VPAgent) refreshDeviceList(cntx context.Context) {
	// If we exit, assume disconnected
	if vpa.volthaClient == nil {
		logger.Error(ctx, "no-voltha-connection")
		vpa.events <- vpaEventVolthaDisconnected
		return
	}
	deviceList, err := vpa.volthaClient.Get().ListLogicalDevices(context.Background(), &empty.Empty{})
	if err != nil {
		logger.Errorw(ctx, "vpagent failed to query device list from voltha",
			log.Fields{"error": err})
		vpa.events <- vpaEventVolthaDisconnected
		return
	}

	var toAdd []int
	var toDel []string
	var deviceIDMap = make(map[string]string)
	for index, d := range deviceList.Items {
		deviceID := d.Id
		deviceIDMap[deviceID] = deviceID
		if vpa.clientMap[deviceID] == nil {
			toAdd = append(toAdd, index)
		}
	}
	for key := range vpa.clientMap {
		deviceID, ok := deviceIDMap[key]
		if !ok || (ok && deviceID == "") {
			toDel = append(toDel, key)
		}
	}
	logger.Debugw(ctx, "Device Refresh", log.Fields{"ToAdd": toAdd, "ToDel": toDel})
	for i := 0; i < len(toAdd); i++ {
		device := deviceList.Items[toAdd[i]]
		serialNum := device.Desc.SerialNum
		// If the blocked device list contain device serial number, do not add VPClient.
		if vpa.VPClientAgent.IsBlockedDevice(serialNum) {
			logger.Debugw(ctx, "Device Serial Number is present in the blocked device list", log.Fields{"device-serial-number": serialNum})
		} else {
			vpa.addVPClient(device) // client is started in addVPClient
		}
	}

	for i := 0; i < len(toDel); i++ {
		vpa.VPClientAgent.DelDevice(cntx, toDel[i])
		vpa.mapLock.Lock()
		delete(vpa.clientMap, toDel[i])
		vpa.mapLock.Unlock()
	}
}

func (vpa *VPAgent) addVPClient(device *voltha.LogicalDevice) intf.IVPClient {
	logger.Warnw(ctx, "GrpcClient addClient called ", log.Fields{"device-id": device.Id})
	vpa.mapLock.Lock()
	defer vpa.mapLock.Unlock()
	var serialNum = "Unknown"
	var mfrDesc = "Unknown"
	var hwDesc = "Unknown"
	var swDesc = "Unknown"
	if device.Desc != nil {
		serialNum = device.Desc.SerialNum
		mfrDesc = device.Desc.MfrDesc
		hwDesc = device.Desc.HwDesc
		swDesc = device.Desc.SwDesc
	}
	vpc := vpa.clientMap[device.Id]
	if vpc == nil {
		vpa.VPClientAgent.AddNewDevice(&intf.VPClientCfg{
			DeviceID:         device.Id,
			SerialNum:        serialNum,
			MfrDesc:          mfrDesc,
			HwDesc:           hwDesc,
			SwDesc:           swDesc,
			SouthBoundID:     device.RootDeviceId,
			TimeStamp:        time.Now(),
			VolthaClient:     vpa.volthaClient,
			PacketOutChannel: vpa.packetOutChannel,
		})

	}
	logger.Debugw(ctx, "Finished with addClient", log.Fields{"deviceID": device.Id})
	return vpc
}

//AddClientToClientMap - called by controller once device obj is created
func (vpa *VPAgent) AddClientToClientMap(deviceID string, vpc intf.IVPClient) {
	vpa.mapLock.Lock()
	defer vpa.mapLock.Unlock()

	if vpc != nil {
		vpa.clientMap[deviceID] = vpc
	}
}

func (vpa *VPAgent) getVPClient(deviceID string) intf.IVPClient {
	if vpc, ok := vpa.clientMap[deviceID]; ok {
		return vpc
	}
	return nil
}
