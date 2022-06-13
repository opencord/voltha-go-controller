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

package controller

import (
	"context"
	"time"

	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/ofagent"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

// AddDeviceTask structure
type AddDeviceTask struct {
	taskID    uint8
	ctx       context.Context
	config    *intf.OFClientCfg
	timestamp string
}

// NewAddDeviceTask is the constructor for AddDeviceTask
func NewAddDeviceTask(config *intf.OFClientCfg) *AddDeviceTask {
	var adt AddDeviceTask
	adt.config = config
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	adt.timestamp = tstamp
	return &adt
}

// Name returns name of the task
func (adt *AddDeviceTask) Name() string {
	return "Add Device Task"
}

// TaskID returns task Id of the task
func (adt *AddDeviceTask) TaskID() uint8 {
	return adt.taskID
}

// Timestamp returns time stamp for the task
func (adt *AddDeviceTask) Timestamp() string {
	return adt.timestamp
}

// Stop to stop the task
func (adt *AddDeviceTask) Stop() {
}

// Start to start the task
func (adt *AddDeviceTask) Start(ctx context.Context, taskID uint8) error {
	adt.taskID = taskID
	adt.ctx = ctx

	logger.Warnw(ctx, "Add Device Task Triggered", log.Fields{"Device": adt.config.DeviceID, "SerialNum": adt.config.SerialNum})

	device := GetController().AddDevice(adt.config)
	ofagent.GetOFAgent().AddClientToClientMap(adt.config.DeviceID, device)
	logger.Warnw(ctx, "Add Device Task Completed", log.Fields{"Device": adt.config.DeviceID, "SerialNum": adt.config.SerialNum})

	return nil
}

// // DeviceRebootedTask structure
// type DeviceRebootedTask struct {
// 	taskID       uint8
// 	ctx          context.Context
// 	deviceID     string
// 	serialNum    string
// 	southBoundID string
// 	timestamp    string
// }

// // NewDeviceRebootedTask is the constructor for DeviceRebootedTask
// func NewDeviceRebootedTask(deviceID string, serialNum string, southBoundID string) *DeviceRebootedTask {
// 	var drt DeviceRebootedTask
// 	drt.deviceID = deviceID
// 	drt.serialNum = serialNum
// 	drt.southBoundID = southBoundID
// 	tstamp := (time.Now()).Format(time.RFC3339Nano)
// 	drt.timestamp = tstamp
// 	return &drt
// }

// // Name returns name of the task
// func (drt *DeviceRebootedTask) Name() string {
// 	return "Device Rebooted Task"
// }

// // TaskID returns task Id of the task
// func (drt *DeviceRebootedTask) TaskID() uint8 {
// 	return drt.taskID
// }

// // Timestamp returns time stamp for the task
// func (drt *DeviceRebootedTask) Timestamp() string {
// 	return drt.timestamp
// }

// // Stop to stop the task
// func (drt *DeviceRebootedTask) Stop() {
// }

// // Start to start the task
// func (drt *DeviceRebootedTask) Start(ctx context.Context, taskID uint8) error {
// 	drt.taskID = taskID
// 	drt.ctx = ctx

// 	logger.Warnw(ctx, "Device Rebooted Task Triggered", log.Fields{"Device": drt.deviceID, "SerialNum": drt.serialNum})

// 	if d, _ := GetController().GetDevice(drt.deviceID); d != nil {
// 		dst := NewDeviceStateIndTask(d.ctx, d, common.OltState_REBOOTED)
// 		d.AddTask(dst)
// 	} else {
// 		logger.Warnw(ctx, "OLT Device Obj is absent. Trigger reboot indication to directly to app", log.Fields{"Device": drt.deviceID, "SerialNo": drt.serialNum})
// 		GetController().SetRebootInProgressForDevice(drt.deviceID)
// 		GetController().DeviceRebootInd(drt.deviceID, drt.serialNum, drt.southBoundID)
// 	}
// 	logger.Warnw(ctx, "Device Rebooted Task Completed", log.Fields{"Device": drt.deviceID, "SerialNum": drt.serialNum})

// 	return nil
// }
