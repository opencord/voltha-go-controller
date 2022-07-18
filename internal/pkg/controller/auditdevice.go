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

	"voltha-go-controller/internal/pkg/tasks"
	"voltha-go-controller/log"
	"github.com/opencord/voltha-protos/v5/go/common"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
)

// AuditEventType type
type AuditEventType uint8

const (
	// AuditEventDeviceDisc constant
	AuditEventDeviceDisc AuditEventType = 0
	// AuditEventDeviceStateChange constant
	AuditEventDeviceStateChange AuditEventType = 1
)

const (
	// NNIPortID NNI port id
	NNIPortID uint32 = 0x1000000
)

// AuditDevice structure
type AuditDevice struct {
	taskID    uint8
	ctx       context.Context
	device    *Device
	stop      bool
	timestamp string
	event     AuditEventType
}

// NewAuditDevice is constructor for AuditDevice
func NewAuditDevice(device *Device, event AuditEventType) *AuditDevice {
	var ad AuditDevice
	ad.device = device
	ad.stop = false
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	ad.timestamp = tstamp
	ad.event = event
	return &ad
}

// Name returns the task name
func (ad *AuditDevice) Name() string {
	return "Device Audit Task"
}

// TaskID returns the task id
func (ad *AuditDevice) TaskID() uint8 {
	return ad.taskID
}

// Timestamp returns the timestamp for the task
func (ad *AuditDevice) Timestamp() string {
	return ad.timestamp
}

// Stop to stop the task
func (ad *AuditDevice) Stop() {
	ad.stop = true
}

// Start to start the task
func (ad *AuditDevice) Start(ctx context.Context, taskID uint8) error {
	logger.Warnw(ctx, "Audit Device Task Triggered", log.Fields{"Context": ctx, "taskId": taskID, "Device": ad.device.ID})
	ad.taskID = taskID
	ad.ctx = ctx

	if ad.stop {
		logger.Errorw(ctx, "Audit Device Task Cancelled", log.Fields{"Context": ad.ctx, "Task": ad.taskID})
		return tasks.ErrTaskCancelError
	}

	ofpps, err := ad.device.VolthaClient().ListLogicalDevicePorts(ad.ctx, &common.ID{Id: ad.device.ID})
	if err != nil {
		return err
	}

	// Compute the difference between the ports received and ports at VGC
	// First build a map of all the received ports under missing ports. We
	// will eliminate the ports that are in the device from the missing ports
	// so that the elements remaining are missing ports. The ones that are
	// not in missing ports are added to excess ports which should be deleted
	// from the VGC.
	missingPorts := make(map[uint32]*ofp.OfpPort)
	for _, ofpp := range ofpps.Items {
		missingPorts[ofpp.OfpPort.PortNo] = ofpp.OfpPort
	}

	var excessPorts []uint32
	GetController().SetAuditFlags(ad.device)

	processPortState := func(id uint32, vgcPort *DevicePort) {
		logger.Debugw(ctx, "Process Port State Ind", log.Fields{"Port No": vgcPort.ID, "Port Name": vgcPort.Name})

		if ofpPort, ok := missingPorts[id]; ok {
			if ((vgcPort.State == PortStateDown) && (ofpPort.State == uint32(ofp.OfpPortState_OFPPS_LIVE))) || ((vgcPort.State == PortStateUp) && (ofpPort.State != uint32(ofp.OfpPortState_OFPPS_LIVE))) {
				// This port exists in the received list and the map at
				// VGC. This is common so delete it
				logger.Infow(ctx, "Port State Mismatch", log.Fields{"Port": vgcPort.ID, "OfpPort": ofpPort.PortNo, "ReceivedState": ofpPort.State, "CurrentState": vgcPort.State})
				ad.device.ProcessPortState(ctx, ofpPort.PortNo, ofpPort.State)
			} else {
				//To ensure the flows are in sync with port status and no mismatch due to reboot,
				// repush/delete flows based on current port status
				logger.Infow(ctx, "Port State Processing", log.Fields{"Port": vgcPort.ID, "OfpPort": ofpPort.PortNo, "ReceivedState": ofpPort.State, "CurrentState": vgcPort.State})
				ad.device.ProcessPortStateAfterReboot(ctx, ofpPort.PortNo, ofpPort.State)
			}
			delete(missingPorts, id)
		} else {
			// This port is missing from the received list. This is an
			// excess port at VGC. This must be added to excess ports
			excessPorts = append(excessPorts, id)
		}
		logger.Debugw(ctx, "Processed Port State Ind", log.Fields{"Port No": vgcPort.ID, "Port Name": vgcPort.Name})

	}

	// 1st process the NNI port before all other ports so that the device state can be updated.
	if vgcPort, ok := ad.device.PortsByID[NNIPortID]; ok {
		logger.Info(ctx, "Processing NNI port state")
		processPortState(NNIPortID, vgcPort)
	}

	for id, vgcPort := range ad.device.PortsByID {
		if id == NNIPortID {
			//NNI port already processed
			continue
		}
		if ad.stop {
			break
		}
		processPortState(id, vgcPort)
	}
	GetController().ResetAuditFlags(ad.device)

	if ad.stop {
		logger.Errorw(ctx, "Audit Device Task Cancelled", log.Fields{"Context": ad.ctx, "Task": ad.taskID})
		return tasks.ErrTaskCancelError
	}
	ad.AddMissingPorts(ctx, missingPorts)
	ad.DelExcessPorts(ctx, excessPorts)
	ad.device.deviceAuditInProgress = false
	logger.Warnw(ctx, "Audit Device Task Completed", log.Fields{"Context": ctx, "taskId": taskID, "Device": ad.device.ID})
	return nil
}

// AddMissingPorts to add the missing ports
func (ad *AuditDevice) AddMissingPorts(cntx context.Context, mps map[uint32]*ofp.OfpPort) {
	logger.Debugw(ctx, "Device Audit - Add Missing Ports", log.Fields{"NumPorts": len(mps)})

	addMissingPort := func(mp *ofp.OfpPort) {
		logger.Debugw(ctx, "Process Port Add Ind", log.Fields{"Port No": mp.PortNo, "Port Name": mp.Name})

		// Error is ignored as it only drops duplicate ports
		logger.Infow(ctx, "Calling AddPort", log.Fields{"No": mp.PortNo, "Name": mp.Name})
		if err := ad.device.AddPort(cntx, mp.PortNo, mp.Name); err != nil {
			logger.Warnw(ctx, "AddPort Failed", log.Fields{"No": mp.PortNo, "Name": mp.Name, "Reason": err})
		}
		if mp.State == uint32(ofp.OfpPortState_OFPPS_LIVE) {
			ad.device.ProcessPortState(cntx, mp.PortNo, mp.State)
		}
		logger.Debugw(ctx, "Processed Port Add Ind", log.Fields{"Port No": mp.PortNo, "Port Name": mp.Name})

	}

	// 1st process the NNI port before all other ports so that the flow provisioning for UNIs can be enabled
	if mp, ok := mps[NNIPortID]; ok {
		logger.Info(ctx, "Adding Missing NNI port")
		addMissingPort(mp)
	}

	for portNo, mp := range mps {
		if portNo != NNIPortID {
			addMissingPort(mp)
		}
	}
}

// DelExcessPorts to delete the excess ports
func (ad *AuditDevice) DelExcessPorts(cntx context.Context, eps []uint32) {
	logger.Debugw(ctx, "Device Audit - Delete Excess Ports", log.Fields{"NumPorts": len(eps)})
	for _, id := range eps {
		// Now delete the port from the device @ VGC
		logger.Infow(ctx, "Device Audit - Deleting Port", log.Fields{"PortId": id})
		if err := ad.device.DelPort(cntx, id); err != nil {
			logger.Warnw(ctx, "DelPort Failed", log.Fields{"PortId": id, "Reason": err})
		}
	}
}
