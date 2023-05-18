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
	"voltha-go-controller/internal/pkg/vpagent"

	"voltha-go-controller/log"
)

// AddDeviceTask structure
type AddDeviceTask struct {
	ctx       context.Context
	config    *intf.VPClientCfg
	timestamp string
	taskID    uint8
}

// NewAddDeviceTask is the constructor for AddDeviceTask
func NewAddDeviceTask(config *intf.VPClientCfg) *AddDeviceTask {
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

	logger.Infow(ctx, "Add Device Task Triggered", log.Fields{"Device": adt.config.DeviceID, "SerialNum": adt.config.SerialNum})

	device := GetController().AddDevice(ctx, adt.config)
	vpagent.GetVPAgent().AddClientToClientMap(adt.config.DeviceID, device)
	logger.Infow(ctx, "Add Device Task Completed", log.Fields{"Device": adt.config.DeviceID, "SerialNum": adt.config.SerialNum, "SouthBoundId": adt.config.SouthBoundID})

	return nil
}
