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
	"errors"
	"time"

	"voltha-go-controller/log"

	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
)

// ChangeEventTask structure
type ChangeEventTask struct {
	ctx       context.Context
	event     *ofp.ChangeEvent
	device    *Device
	timestamp string
	taskID    uint8
}

// NewChangeEventTask is constructor for ChangeEventTask
func NewChangeEventTask(ctx context.Context, event *ofp.ChangeEvent, device *Device) *ChangeEventTask {
	var cet ChangeEventTask
	cet.device = device
	cet.event = event
	cet.ctx = ctx
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	cet.timestamp = tstamp
	return &cet
}

// Name returns the name of the task
func (cet *ChangeEventTask) Name() string {
	return "Change Event Task"
}

// TaskID to return task id of the task
func (cet *ChangeEventTask) TaskID() uint8 {
	return cet.taskID
}

// Timestamp to return timestamp for the task
func (cet *ChangeEventTask) Timestamp() string {
	return cet.timestamp
}

// Stop to stop the task
func (cet *ChangeEventTask) Stop() {
}

// Start to start the Change event task
func (cet *ChangeEventTask) Start(ctx context.Context, taskID uint8) error {
	cet.taskID = taskID
	cet.ctx = ctx
	if status, ok := cet.event.Event.(*ofp.ChangeEvent_PortStatus); ok {
		portNo := status.PortStatus.Desc.PortNo
		portName := status.PortStatus.Desc.Name
		state := status.PortStatus.Desc.State
		logger.Infow(ctx, "Process Port Change Event", log.Fields{"Port No": portNo, "Port Name": portName, "State": state, "Reason": status.PortStatus.Reason})
		switch status.PortStatus.Reason {
		case ofp.OfpPortReason_OFPPR_ADD:
			_ = cet.device.AddPort(ctx, status.PortStatus.Desc)
			if state == uint32(ofp.OfpPortState_OFPPS_LIVE) {
				cet.device.ProcessPortState(ctx, portNo, state, portName, false)
			}
		case ofp.OfpPortReason_OFPPR_DELETE:
			cet.device.CheckAndDeletePort(ctx, portNo, portName)
		case ofp.OfpPortReason_OFPPR_MODIFY:
			cet.device.ProcessPortUpdate(ctx, portName, portNo, state)
		}
		logger.Debugw(ctx, "Processed Port Change Event", log.Fields{"Port No": portNo, "Port Name": portName, "State": state, "Reason": status.PortStatus.Reason})
		return nil
	}
	return errors.New("invalid message received")
}
