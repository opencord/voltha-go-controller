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

package application

import (
	"context"

	infraerrorcode "voltha-go-controller/internal/pkg/errorcodes/service"

	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/log"
)

// Generic Framework to enabling all flow based event trigger and handling.
// The eventMapper can be updated for dynamic func caller for future events

// FlowEventType - Type of event enumeration
type FlowEventType string

// FlowEventHandler - Func prototype for flow event handling funcs
type FlowEventHandler func(context.Context, *FlowEvent, intf.FlowStatus)

var eventMapper map[FlowEventType]FlowEventHandler

const (
	// EventTypeUsIgmpFlowAdded - Event type for IGMP US flow add
	EventTypeUsIgmpFlowAdded FlowEventType = "USIgmpFlowAdded"
	// EventTypeServiceFlowAdded - Event type for Service flow add
	EventTypeServiceFlowAdded FlowEventType = "ServiceFlowAdded"
	// EventTypeControlFlowAdded - Event type for Control flow add
	EventTypeControlFlowAdded FlowEventType = "ControlFlowAdded"

	// EventTypeDeviceFlowRemoved - Event type for Device flow del
	EventTypeDeviceFlowRemoved FlowEventType = "DeviceFlowRemoved"
	// EventTypeMcastFlowRemoved - Event type for Mcast flow del
	EventTypeMcastFlowRemoved FlowEventType = "McastFlowRemoved"

	// EventTypeServiceFlowRemoved - Event type for Service flow del
	EventTypeServiceFlowRemoved FlowEventType = "ServiceFlowRemoved"
	// EventTypeControlFlowRemoved - Event type for Control flow del
	EventTypeControlFlowRemoved FlowEventType = "ControlFlowRemoved"
)

// FlowEvent - Event info for Flow event processing
type FlowEvent struct {
	eventData interface{}
	device    string
	cookie    string
	eType     FlowEventType
}

// InitEventFuncMapper - Initialization of flow event mapper
func InitEventFuncMapper() {
	eventMapper = map[FlowEventType]FlowEventHandler{
		EventTypeUsIgmpFlowAdded:    ProcessUsIgmpFlowAddEvent,
		EventTypeControlFlowAdded:   ProcessControlFlowAddEvent,
		EventTypeServiceFlowAdded:   ProcessServiceFlowAddEvent,
		EventTypeControlFlowRemoved: ProcessControlFlowDelEvent,
		EventTypeServiceFlowRemoved: ProcessServiceFlowDelEvent,
		EventTypeDeviceFlowRemoved:  ProcessDeviceFlowDelEvent,
		EventTypeMcastFlowRemoved:   ProcessMcastFlowDelEvent,
	}
}

// ExecuteFlowEvent - Process flow based event triggers
func ExecuteFlowEvent(cntx context.Context, vd *VoltDevice, cookie string, flowStatus intf.FlowStatus) bool {
	logger.Infow(ctx, "Execute Flow event", log.Fields{"Cookie": cookie, "flowMod": flowStatus.FlowModType})
	var event interface{}

	flowEventMap, err := vd.GetFlowEventRegister(flowStatus.FlowModType)
	if err != nil {
		logger.Warnw(ctx, "Flow event map does not exists", log.Fields{"flowMod": flowStatus.FlowModType, "Error": err})
		return false
	}
	flowEventMap.MapLock.Lock()

	if event, _ = flowEventMap.Get(cookie); event == nil {
		logger.Debugw(ctx, "Event already processed or event not registered for the cookie", log.Fields{"Cookie": cookie})
		flowEventMap.MapLock.Unlock()
		return false
	}
	flowEventMap.Remove(cookie)
	flowEventMap.MapLock.Unlock()
	flowEvent := event.(*FlowEvent)
	eventMapper[flowEvent.eType](cntx, flowEvent, flowStatus)
	return true
}

// ProcessUsIgmpFlowAddEvent - Process Us Igmp Flow event trigger
func ProcessUsIgmpFlowAddEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Add Event for US Igmp", log.Fields{"Cookie": event.cookie, "event": event})
	vpv := event.eventData.(*VoltPortVnet)
	if isFlowStatusSuccess(flowStatus.Status, true) {
		vpv.services.Range(ReceiverUpInd)
	} else {
		vpv.IgmpFlowInstallFailure(event.cookie, flowStatus.Status, flowStatus.Reason)
	}
}

// ProcessServiceFlowAddEvent - Process Service Flow event trigger
func ProcessServiceFlowAddEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Add Event for Service", log.Fields{"Cookie": event.cookie, "event": event})
	vs := event.eventData.(*VoltService)
	if isFlowStatusSuccess(flowStatus.Status, true) {
		vs.FlowInstallSuccess(cntx, event.cookie, flowStatus.AdditionalData)
	} else {
		vs.FlowInstallFailure(event.cookie, flowStatus.Status, flowStatus.Reason)
	}
}

// ProcessControlFlowAddEvent - Process Control Flow event trigger
func ProcessControlFlowAddEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Add Event for VPV", log.Fields{"Cookie": event.cookie, "event": event})
	vpv := event.eventData.(*VoltPortVnet)
	if !isFlowStatusSuccess(flowStatus.Status, true) {
		vpv.FlowInstallFailure(event.cookie, flowStatus.Status, flowStatus.Reason)
	}
}

// ProcessServiceFlowDelEvent - Process Service Flow event trigger
func ProcessServiceFlowDelEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Remove Event for Service", log.Fields{"Cookie": event.cookie, "event": event})
	vs := event.eventData.(*VoltService)
	if isFlowStatusSuccess(flowStatus.Status, false) {
		vs.FlowRemoveSuccess(cntx, event.cookie)
	} else {
		vs.FlowRemoveFailure(cntx, event.cookie, flowStatus.Status, flowStatus.Reason)
	}
}

// ProcessControlFlowDelEvent - Process Control Flow event trigger
func ProcessControlFlowDelEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Remove Event for VPV", log.Fields{"Cookie": event.cookie, "event": event})
	vpv := event.eventData.(*VoltPortVnet)
	if isFlowStatusSuccess(flowStatus.Status, false) {
		vpv.FlowRemoveSuccess(cntx, event.cookie, event.device)
	} else {
		vpv.FlowRemoveFailure(cntx, event.cookie, event.device, flowStatus.Status, flowStatus.Reason)
	}
}

// ProcessMcastFlowDelEvent - Process Control Flow event trigger
func ProcessMcastFlowDelEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Remove Event for Mcast/Igmp", log.Fields{"Cookie": event.cookie, "event": event})
	mvp := event.eventData.(*MvlanProfile)
	if isFlowStatusSuccess(flowStatus.Status, false) {
		mvp.FlowRemoveSuccess(cntx, event.cookie, event.device)
	} else {
		mvp.FlowRemoveFailure(event.cookie, event.device, flowStatus.Status, flowStatus.Reason)
	}
}

// ProcessDeviceFlowDelEvent - Process Control Flow event trigger
func ProcessDeviceFlowDelEvent(cntx context.Context, event *FlowEvent, flowStatus intf.FlowStatus) {
	logger.Infow(ctx, "Processing Post Flow Remove Event for VNET", log.Fields{"Cookie": event.cookie, "event": event})
	vnet := event.eventData.(*VoltVnet)
	if isFlowStatusSuccess(flowStatus.Status, false) {
		vnet.FlowRemoveSuccess(cntx, event.cookie, event.device)
	} else {
		vnet.FlowRemoveFailure(cntx, event.cookie, event.device, flowStatus.Status, flowStatus.Reason)
	}
}

// TODO: Update the func or flowStatus struct once all flow status are based on NB error code
func isFlowStatusSuccess(status uint32, flowAdd bool) bool {
	logger.Infow(ctx, "Processing isFlowStatusSuccess", log.Fields{"Status": status, "FlowAdd": flowAdd})
	result := false
	errorCode := infraerrorcode.ErrorCode(status)

	if errorCode == infraerrorcode.ErrOk {
		result = true
	} else if !flowAdd && errorCode == infraerrorcode.ErrNotExists {
		result = true
	}
	return result
}
