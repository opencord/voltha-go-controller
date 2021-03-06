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
	"strconv"
	"time"

	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/tasks"
	"voltha-go-controller/internal/pkg/util"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
	"github.com/opencord/voltha-protos/v5/go/common"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/opencord/voltha-protos/v5/go/voltha"
)

var (
	rcvdGroups  map[uint32]*ofp.OfpGroupDesc
	groupsToAdd []*of.Group
	groupsToMod []*of.Group
)

// AuditTablesTask structure
type AuditTablesTask struct {
	taskID    uint8
	ctx       context.Context
	device    *Device
	stop      bool
	timestamp string
}

// NewAuditTablesTask is constructor for AuditTablesTask
func NewAuditTablesTask(device *Device) *AuditTablesTask {
	var att AuditTablesTask
	att.device = device
	att.stop = false
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	att.timestamp = tstamp
	return &att
}

// Name returns name of the task
func (att *AuditTablesTask) Name() string {
	return "Audit Table Task"
}

// TaskID to return task id of the task
func (att *AuditTablesTask) TaskID() uint8 {
	return att.taskID
}

// Timestamp to return timestamp for the task
func (att *AuditTablesTask) Timestamp() string {
	return att.timestamp
}

// Stop to stop the task
func (att *AuditTablesTask) Stop() {
	att.stop = true
}

// Start is called by the framework and is responsible for implementing
// the actual task.
func (att *AuditTablesTask) Start(ctx context.Context, taskID uint8) error {
	logger.Warnw(ctx, "Audit Table Task Triggered", log.Fields{"Context": ctx, "taskId": taskID, "Device": att.device.ID})
	att.taskID = taskID
	att.ctx = ctx
	var errInfo error
	var err error

	// Audit the meters
	if err = att.AuditMeters(); err != nil {
		logger.Errorw(ctx, "Audit Meters Failed", log.Fields{"Reason": err.Error()})
		errInfo = err
	}

	// Audit the Groups
	if rcvdGroups, err = att.AuditGroups(); err != nil {
		logger.Errorw(ctx, "Audit Groups Failed", log.Fields{"Reason": err.Error()})
		errInfo = err
	}

	// Audit the flows
	if err = att.AuditFlows(); err != nil {
		logger.Errorw(ctx, "Audit Flows Failed", log.Fields{"Reason": err.Error()})
		errInfo = err
	}

	// Triggering deletion of excess groups from device after the corresponding flows are removed
	// to avoid flow dependency error during group deletion
	logger.Infow(ctx, "Excess Groups", log.Fields{"Groups": rcvdGroups})
	att.DelExcessGroups(rcvdGroups)
	logger.Warnw(ctx, "Audit Table Task Completed", log.Fields{"Context": ctx, "taskId": taskID, "Device": att.device.ID})
	return errInfo

}

// AuditMeters : Audit the meters which includes fetching the existing meters at the
// voltha and identifying the delta between the ones held here and the
// ones held at VOLTHA. The delta must be cleaned up to keep both the
// components in sync
func (att *AuditTablesTask) AuditMeters() error {

	if att.stop {
		return tasks.ErrTaskCancelError
	}
	var vc voltha.VolthaServiceClient
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Fetch Device Meters Failed: Voltha Client Unavailable")
		return nil
	}

	//-----------------------------
	// Perform the audit of meters
	// Fetch the meters
	ms, err := vc.ListLogicalDeviceMeters(att.ctx, &voltha.ID{Id: att.device.ID})
	if err != nil {
		logger.Warnw(ctx, "Audit of flows failed", log.Fields{"Reason": err.Error()})
		return err
	}

	// Build the map for easy and faster processing
	rcvdMeters := make(map[uint32]*ofp.OfpMeterStats)
	for _, m := range ms.Items {
		rcvdMeters[m.Stats.MeterId] = m.Stats
	}

	// Verify all meters that are in the controller but not in the device
	missingMeters := []*of.Meter{}
	for _, meter := range att.device.meters {

		if att.stop {
			break
		}
		logger.Debugw(ctx, "Auditing Meter", log.Fields{"Id": meter.ID})

		if _, ok := rcvdMeters[meter.ID]; ok {
			// The meter exists in the device too. Just remove it from
			// the received meters
			delete(rcvdMeters, meter.ID)
		} else {
			// The flow exists at the controller but not at the device
			// Push the flow to the device
			logger.Debugw(ctx, "Adding Meter To Missing Meters", log.Fields{"Id": meter.ID})
			missingMeters = append(missingMeters, meter)
		}
	}
	if !att.stop {
		att.AddMissingMeters(missingMeters)
		att.DelExcessMeters(rcvdMeters)
	} else {
		err = tasks.ErrTaskCancelError
	}
	return err
}

// AddMissingMeters adds the missing meters detected by AuditMeters
func (att *AuditTablesTask) AddMissingMeters(meters []*of.Meter) {
	logger.Debugw(ctx, "Adding missing meters", log.Fields{"Number": len(meters)})
	for _, meter := range meters {
		meterMod, err := of.MeterUpdate(att.device.ID, of.MeterCommandAdd, meter)
		if err != nil {
			logger.Errorw(ctx, "Update Meter Table Failed", log.Fields{"Reason": err.Error()})
			continue
		}
		if vc := att.device.VolthaClient(); vc != nil {
			if _, err = vc.UpdateLogicalDeviceMeterTable(att.ctx, meterMod); err != nil {
				logger.Errorw(ctx, "Update Meter Table Failed", log.Fields{"Reason": err.Error()})
			}
		} else {
			logger.Error(ctx, "Update Meter Table Failed: Voltha Client Unavailable")
		}
	}
}

// DelExcessMeters to delete excess meters
func (att *AuditTablesTask) DelExcessMeters(meters map[uint32]*ofp.OfpMeterStats) {
	logger.Debugw(ctx, "Deleting Excess Meters", log.Fields{"Number": len(meters)})
	for _, meter := range meters {
		meterMod := &ofp.OfpMeterMod{}
		meterMod.Command = ofp.OfpMeterModCommand_OFPMC_DELETE
		meterMod.MeterId = meter.MeterId
		meterUpd := &ofp.MeterModUpdate{Id: att.device.ID, MeterMod: meterMod}
		if vc := att.device.VolthaClient(); vc != nil {
			if _, err := vc.UpdateLogicalDeviceMeterTable(att.ctx, meterUpd); err != nil {
				logger.Errorw(ctx, "Update Meter Table Failed", log.Fields{"Reason": err.Error()})
			}
		} else {
			logger.Error(ctx, "Update Meter Table Failed: Voltha Client Unavailable")
		}
	}
}

// AuditFlows audit the flows which includes fetching the existing meters at the
// voltha and identifying the delta between the ones held here and the
// ones held at VOLTHA. The delta must be cleaned up to keep both the
// components in sync
func (att *AuditTablesTask) AuditFlows() error {

	if att.stop {
		return tasks.ErrTaskCancelError
	}

	var vc voltha.VolthaServiceClient
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Flow Audit Failed: Voltha Client Unavailable")
		return nil
	}

	// ---------------------------------
	// Perform the audit of flows first
	// Retrieve the flows from the device
	f, err := vc.ListLogicalDeviceFlows(att.ctx, &common.ID{Id: att.device.ID})
	if err != nil {
		logger.Warnw(ctx, "Audit of flows failed", log.Fields{"Reason": err.Error()})
		return err
	}

	defaultSuccessFlowStatus := intf.FlowStatus{
		Device:      att.device.ID,
		FlowModType: of.CommandAdd,
		Status:      0,
		Reason:      "",
	}

	// Build the map for easy and faster processing
	rcvdFlows := make(map[uint64]*ofp.OfpFlowStats)
	flowsToAdd := &of.VoltFlow{}
	flowsToAdd.SubFlows = make(map[uint64]*of.VoltSubFlow)
	for _, flow := range f.Items {
		rcvdFlows[flow.Cookie] = flow
	}

	att.device.flowLock.Lock()
	// Verify all flows that are in the controller but not in the device
	for _, flow := range att.device.flows {

		if att.stop {
			break
		}

		logger.Debugw(ctx, "Auditing Flow", log.Fields{"Cookie": flow.Cookie})
		if _, ok := rcvdFlows[flow.Cookie]; ok {
			// The flow exists in the device too. Just remove it from
			// the received flows & trigger flow success indication unless
			// the flow in del failure/pending state

			if flow.State != of.FlowDelFailure && flow.State != of.FlowDelPending {
				delete(rcvdFlows, flow.Cookie)
			}
			defaultSuccessFlowStatus.Cookie = strconv.FormatUint(flow.Cookie, 10)

			logger.Infow(ctx, "Triggering Internal Flow Notification", log.Fields{"Flow Status": defaultSuccessFlowStatus})
			GetController().ProcessFlowModResultIndication(defaultSuccessFlowStatus)
		} else {
			// The flow exists at the controller but not at the device
			// Push the flow to the device
			logger.Debugw(ctx, "Adding Flow To Missing Flows", log.Fields{"Cookie": flow.Cookie})
			flowsToAdd.SubFlows[flow.Cookie] = flow
		}
	}
	att.device.flowLock.Unlock()

	if !att.stop {
		//  The flows remaining in the received flows are the excess flows at
		// the device. Delete those flows
		att.DelExcessFlows(rcvdFlows)
		// Add the flows missing at the device
		att.AddMissingFlows(flowsToAdd)
	} else {
		err = tasks.ErrTaskCancelError
	}
	return err
}

// AddMissingFlows : The flows missing from the device are reinstalled att the audit
// The flows are added into a VoltFlow structure.
func (att *AuditTablesTask) AddMissingFlows(mflow *of.VoltFlow) {
	logger.Debugw(ctx, "Add Missing Flows", log.Fields{"Number": len(mflow.SubFlows)})
	mflow.Command = of.CommandAdd
	ofFlows := of.ProcessVoltFlow(att.device.ID, mflow.Command, mflow.SubFlows)
	var vc voltha.VolthaServiceClient
	var bwConsumedInfo of.BwAvailDetails
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Update Flow Table Failed: Voltha Client Unavailable")
		return
	}
	for _, flow := range ofFlows {
		var dbFlow *of.VoltSubFlow
		var present bool
		if flow.FlowMod != nil {
			if dbFlow, present = att.device.GetFlow(flow.FlowMod.Cookie); !present {
				logger.Warn(ctx, "Flow Removed from DB. Ignoring Add Missing Flow", log.Fields{"Device": att.device.ID, "Cookie": flow.FlowMod.Cookie})
				continue
			}
		}
		var err error
		if _, err = vc.UpdateLogicalDeviceFlowTable(att.ctx, flow); err != nil {
			logger.Errorw(ctx, "Update Flow Table Failed", log.Fields{"Reason": err.Error()})
		}
		att.device.triggerFlowResultNotification(flow.FlowMod.Cookie, dbFlow, of.CommandAdd, bwConsumedInfo, err)
	}
}

// DelExcessFlows delete the excess flows held at the VOLTHA
func (att *AuditTablesTask) DelExcessFlows(flows map[uint64]*ofp.OfpFlowStats) {
	logger.Debugw(ctx, "Deleting Excess Flows", log.Fields{"Number of Flows": len(flows)})

	var vc voltha.VolthaServiceClient
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Delete Excess Flows Failed: Voltha Client Unavailable")
		return
	}

	// Let's cycle through the flows to delete the excess flows
	for _, flow := range flows {

		if _, present := att.device.GetFlow(flow.Cookie); present {
			logger.Warn(ctx, "Flow Present in DB. Ignoring Delete Excess Flow", log.Fields{"Device": att.device.ID, "Cookie": flow.Cookie})
			continue
		}

		logger.Debugw(ctx, "Deleting Flow", log.Fields{"Cookie": flow.Cookie})
		// Create the flowMod structure and fill it out
		flowMod := &ofp.OfpFlowMod{}
		flowMod.Cookie = flow.Cookie
		flowMod.TableId = flow.TableId
		flowMod.Command = ofp.OfpFlowModCommand_OFPFC_DELETE_STRICT
		flowMod.IdleTimeout = flow.IdleTimeout
		flowMod.HardTimeout = flow.HardTimeout
		flowMod.Priority = flow.Priority
		flowMod.BufferId = of.DefaultBufferID
		flowMod.OutPort = of.DefaultOutPort
		flowMod.OutGroup = of.DefaultOutGroup
		flowMod.Flags = flow.Flags
		flowMod.Match = flow.Match
		flowMod.Instructions = flow.Instructions

		// Create FlowTableUpdate
		flowUpdate := &ofp.FlowTableUpdate{
			Id:      att.device.ID,
			FlowMod: flowMod,
		}

		var err error
		if _, err = vc.UpdateLogicalDeviceFlowTable(att.ctx, flowUpdate); err != nil {
			logger.Errorw(ctx, "Flow Audit Delete Failed", log.Fields{"Reason": err.Error()})
		}
		att.device.triggerFlowResultNotification(flow.Cookie, nil, of.CommandDel, of.BwAvailDetails{}, err)
	}
}

// AuditGroups audit the groups which includes fetching the existing groups at the
// voltha and identifying the delta between the ones held here and the
// ones held at VOLTHA. The delta must be cleaned up to keep both the
// components in sync
func (att *AuditTablesTask) AuditGroups() (map[uint32]*ofp.OfpGroupDesc, error) {

	// Build the map for easy and faster processing
	rcvdGroups = make(map[uint32]*ofp.OfpGroupDesc)

	if att.stop {
		return rcvdGroups, tasks.ErrTaskCancelError
	}

	var vc voltha.VolthaServiceClient
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Group Audit Failed: Voltha Client Unavailable")
		return rcvdGroups, nil
	}

	// ---------------------------------
	// Perform the audit of groups first
	// Retrieve the groups from the device
	g, err := vc.ListLogicalDeviceFlowGroups(att.ctx, &common.ID{Id: att.device.ID})
	if err != nil {
		logger.Warnw(ctx, "Audit of groups failed", log.Fields{"Reason": err.Error()})
		return rcvdGroups, err
	}

	groupsToAdd = []*of.Group{}
	groupsToMod = []*of.Group{}
	for _, group := range g.Items {
		rcvdGroups[group.Desc.GroupId] = group.Desc
	}
	logger.Infow(ctx, "Received Groups", log.Fields{"Groups": rcvdGroups})

	// Verify all groups that are in the controller but not in the device
	att.device.groups.Range(att.compareGroupEntries)

	if !att.stop {
		// Add the groups missing at the device
		logger.Infow(ctx, "Missing Groups", log.Fields{"Groups": groupsToAdd})
		att.AddMissingGroups(groupsToAdd)

		// Update groups with group member mismatch
		logger.Infow(ctx, "Modify Groups", log.Fields{"Groups": groupsToMod})
		att.UpdateMismatchGroups(groupsToMod)

		// Note: Excess groups will be deleted after ensuring the connected
		// flows are also removed as part fo audit flows
	} else {
		err = tasks.ErrTaskCancelError
	}
	// The groups remaining in the received groups are the excess groups at
	// the device
	return rcvdGroups, err
}

// compareGroupEntries to compare the group entries
func (att *AuditTablesTask) compareGroupEntries(key, value interface{}) bool {

	if att.stop {
		return false
	}

	groupID := key.(uint32)
	dbGroup := value.(*of.Group)
	logger.Debugw(ctx, "Auditing Group", log.Fields{"Groupid": groupID})
	if rcvdGrp, ok := rcvdGroups[groupID]; ok {
		// The group exists in the device too.
		// Compare the group members and add to modify list if required
		compareGroupMembers(dbGroup, rcvdGrp)
		delete(rcvdGroups, groupID)
	} else {
		// The group exists at the controller but not at the device
		// Push the group to the device
		logger.Debugw(ctx, "Adding Group To Missing Groups", log.Fields{"GroupId": groupID})
		groupsToAdd = append(groupsToAdd, value.(*of.Group))
	}
	return true
}

func compareGroupMembers(refGroup *of.Group, rcvdGroup *ofp.OfpGroupDesc) {

	portList := []uint32{}
	refPortList := []uint32{}

	//Collect port list from response Group Mod structure
	//If PON is configured even for one group, then only PON shall be considered for compared for all groups
	for _, bucket := range rcvdGroup.Buckets {
		for _, actionBucket := range bucket.Actions {
			if actionBucket.Type == ofp.OfpActionType_OFPAT_OUTPUT {
				action := actionBucket.GetOutput()
				portList = append(portList, action.Port)
			}
		}
	}

	refPortList = append(refPortList, refGroup.Buckets...)

	//Is port list differs, trigger group update
	if !util.IsSliceSame(refPortList, portList) {
		groupsToMod = append(groupsToMod, refGroup)
	}
}

//AddMissingGroups - addmissing groups to Voltha
func (att *AuditTablesTask) AddMissingGroups(groupList []*of.Group) {
	att.PushGroups(groupList, of.GroupCommandAdd)
}

//UpdateMismatchGroups - updates mismatched groups to Voltha
func (att *AuditTablesTask) UpdateMismatchGroups(groupList []*of.Group) {
	att.PushGroups(groupList, of.GroupCommandMod)
}

// PushGroups - The groups missing/to be updated in the device are reinstalled att the audit
func (att *AuditTablesTask) PushGroups(groupList []*of.Group, grpCommand of.GroupCommand) {
	logger.Debugw(ctx, "Pushing Groups", log.Fields{"Number": len(groupList), "Command": grpCommand})

	var vc voltha.VolthaServiceClient
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Update Group Table Failed: Voltha Client Unavailable")
		return
	}
	for _, group := range groupList {
		group.Command = grpCommand
		groupUpdate := of.CreateGroupTableUpdate(group)
		if _, err := vc.UpdateLogicalDeviceFlowGroupTable(att.ctx, groupUpdate); err != nil {
			logger.Errorw(ctx, "Update Group Table Failed", log.Fields{"Reason": err.Error()})
		}
	}
}

// DelExcessGroups - Delete the excess groups held at the VOLTHA
func (att *AuditTablesTask) DelExcessGroups(groups map[uint32]*ofp.OfpGroupDesc) {
	logger.Debugw(ctx, "Deleting Excess Groups", log.Fields{"Number of Groups": len(groups)})

	var vc voltha.VolthaServiceClient
	if vc = att.device.VolthaClient(); vc == nil {
		logger.Error(ctx, "Delete Excess Groups Failed: Voltha Client Unavailable")
		return
	}

	// Let's cycle through the groups to delete the excess groups
	for _, groupDesc := range groups {
		logger.Debugw(ctx, "Deleting Group", log.Fields{"GroupId": groupDesc.GroupId})
		group := &of.Group{}
		group.Device = att.device.ID
		group.GroupID = groupDesc.GroupId

		//Group Members should be deleted before triggered group delete
		group.Command = of.GroupCommandMod
		groupUpdate := of.CreateGroupTableUpdate(group)
		if _, err := vc.UpdateLogicalDeviceFlowGroupTable(att.ctx, groupUpdate); err != nil {
			logger.Errorw(ctx, "Update Group Table Failed", log.Fields{"Reason": err.Error()})
		}

		group.Command = of.GroupCommandDel
		groupUpdate = of.CreateGroupTableUpdate(group)
		if _, err := vc.UpdateLogicalDeviceFlowGroupTable(att.ctx, groupUpdate); err != nil {
			logger.Errorw(ctx, "Update Group Table Failed", log.Fields{"Reason": err.Error()})
		}
	}
}
