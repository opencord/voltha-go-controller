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
	infraerror "voltha-go-controller/internal/pkg/errorcodes"
	infraerrorcode "voltha-go-controller/internal/pkg/errorcodes/service"

	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"
)

const (
	// MaxRetryCount - Maximum retry attempts on failure
	MaxRetryCount int = 1
)

// AddFlowsTask structure
type AddFlowsTask struct {
	ctx       context.Context
	flow      *of.VoltFlow
	device    *Device
	timestamp string
	taskID    uint8
}

// NewAddFlowsTask is constructor for AddFlowsTask
func NewAddFlowsTask(ctx context.Context, flow *of.VoltFlow, device *Device) *AddFlowsTask {
	var aft AddFlowsTask
	aft.device = device
	aft.flow = flow
	aft.ctx = ctx
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	aft.timestamp = tstamp
	return &aft
}

// Name to add flow task
func (aft *AddFlowsTask) Name() string {
	for _, flow := range aft.flow.SubFlows {
		logger.Debugw(ctx, "Flow Cookies", log.Fields{"Cookie": flow.Cookie})
	}
	return "Add Flows Task"
}

// TaskID to return task ID
func (aft *AddFlowsTask) TaskID() uint8 {
	return aft.taskID
}

// Timestamp to return timestamp
func (aft *AddFlowsTask) Timestamp() string {
	return aft.timestamp
}

// Stop to stop the add flow task
func (aft *AddFlowsTask) Stop() {
}

// Start to start adding flow task
func (aft *AddFlowsTask) Start(ctx context.Context, taskID uint8) error {
	var err error
	aft.taskID = taskID
	aft.ctx = ctx
	flowsToProcess := make(map[uint64]*of.VoltSubFlow)
	flowsPresent := 0
	// First add/delete the flows first locally before passing them to actual device
	for _, flow := range aft.flow.SubFlows {
		logger.Debugw(ctx, "Flow Mod Request", log.Fields{"Cookie": flow.Cookie, "Oper": aft.flow.Command, "Port": aft.flow.PortID})
		if aft.flow.Command == of.CommandAdd {
			flow.State = of.FlowAddPending
			if err = aft.device.AddFlow(ctx, flow); err != nil {
				logger.Warnw(ctx, "Add Flow Error", log.Fields{"Cookie": flow.Cookie, "Reason": err.Error()})

				// If flow already exists in cache, check for flow state
				// If Success: Trigger success FLow Indication
				// if Failure: Continue process, so add-retry happens
				if err.Error() == ErrDuplicateFlow {
					dbFlow, _ := aft.device.GetFlow(flow.Cookie)
					if dbFlow.State == of.FlowAddSuccess {
						aft.device.triggerFlowNotification(ctx, flow.Cookie, aft.flow.Command, of.BwAvailDetails{}, nil, true)
						flowsPresent++
						continue
					}
				}
			}
			flowsToProcess[flow.Cookie] = flow
		} else {
			dbFlow, ok := aft.device.GetFlow(flow.Cookie)
			if !ok {
				logger.Warnw(ctx, "Delete Flow Error: Flow Does not Exist", log.Fields{"Cookie": flow.Cookie, "Device": aft.device.ID})
			} else {
				// dbFlow.State = of.FlowDelPending
				// aft.device.AddFlowToDb(dbFlow)
				flowsToProcess[flow.Cookie] = dbFlow
			}
			aft.device.triggerFlowNotification(ctx, flow.Cookie, aft.flow.Command, of.BwAvailDetails{}, nil, false)
		}
	}

	if flowsPresent == len(aft.flow.SubFlows) {
		logger.Warn(ctx, "All Flows already present in database. Skipping Flow Push to SB")
		return nil
	}

	// PortName and PortID are used for validation of PortID, whether it is still valid and associated with old PortName or
	// PortID got assigned to another PortName. If the condition met, skip these flow update to voltha core
	if aft.flow.PortName != "" && aft.flow.PortID != 0 {
		portName, _ := aft.device.GetPortName(aft.flow.PortID)
		if aft.flow.PortName != portName && portName != "" {
			for _, flow := range aft.flow.SubFlows {
				logger.Warnw(ctx, "Skip Flow Update", log.Fields{"Reason": "Port Deleted", "PortName": aft.flow.PortName, "PortNo": aft.flow.PortID, "Cookie": flow.Cookie, "Operation": aft.flow.Command})
				if aft.flow.Command == of.CommandDel {
					aft.device.triggerFlowNotification(ctx, flow.Cookie, aft.flow.Command, of.BwAvailDetails{}, nil, true)
				}
			}
			return nil
		}
	}

	if !aft.device.isSBOperAllowed(aft.flow.ForceAction) {
		for _, flow := range aft.flow.SubFlows {
			logger.Warnw(ctx, "Skipping Flow Table Update", log.Fields{"Reason": "Device State not UP", "State": aft.device.State, "Cookie": flow.Cookie, "Operation": aft.flow.Command})
		}
		return nil
	}

	flows := of.ProcessVoltFlow(aft.device.ID, aft.flow.Command, flowsToProcess)
	for _, flow := range flows {
		attempt := 0
		if vc := aft.device.VolthaClient(); vc != nil {
			for {
				if _, err = vc.UpdateLogicalDeviceFlowTable(aft.ctx, flow); err != nil {
					logger.Errorw(ctx, "Update Flow Table Failed", log.Fields{"Cookie": flow.GetFlowMod().Cookie, "Reason": err.Error(), "Operation": aft.flow.Command})
					statusCode, _ := infraerror.GetErrorInfo(err)

					// Retry on flow delete failure once.
					// Do NOT retry incase of failure with reason: Entry Not Found
					if aft.flow.Command == of.CommandDel && statusCode != uint32(infraerrorcode.ErrNotExists) {
						if attempt != MaxRetryCount {
							logger.Warnw(ctx, "Retrying Flow Delete", log.Fields{"Cookie": flow.GetFlowMod().Cookie, "Attempt": attempt})
							attempt++
							continue
						}
						logger.Errorw(ctx, "Flow Delete failed even aft max retries", log.Fields{"Flow": flow, "Attempt": attempt})
					}
				}
				break
			}
			aft.device.triggerFlowNotification(ctx, flow.FlowMod.Cookie, aft.flow.Command, of.BwAvailDetails{}, err, true)
		} else {
			logger.Errorw(ctx, "Update Flow Table Failed: Voltha Client Unavailable", log.Fields{"Flow": flow})
		}
	}
	return nil
}

func isFlowOperSuccess(statusCode uint32, oper of.Command) bool {
	volthaErrorCode := infraerrorcode.ErrorCode(statusCode)

	if volthaErrorCode == infraerrorcode.ErrOk {
		return true
	}

	if oper == of.CommandAdd && volthaErrorCode == infraerrorcode.ErrAlreadyExists {
		return true
	} else if oper == of.CommandDel && volthaErrorCode == infraerrorcode.ErrNotExists {
		return true
	}
	return false
}

// func getBwAvailInfo(bwAvailInfo []*voltha.ResponseMsg) of.BwAvailDetails {
// 	var bwInfo of.BwAvailDetails
// 	// convert the bw details sent from olt to a struct
// 	// received msg format:
// 	// additional_data[Data{ResponseMsg
// 	//{"key":"prevBW","value":"111111"},
// 	//{"key":"presentBW","value":"10000"}]
// 	if len(bwAvailInfo) > 1 {
// 		prevBwResp := bwAvailInfo[0]
// 		if prevBwResp.Key == of.PrevBwInfo {
// 			_, err := strconv.Atoi(prevBwResp.Val)
// 			if err == nil {
// 				bwInfo.PrevBw = prevBwResp.Val
// 			}
// 		}

// 		presentBwResp := bwAvailInfo[1]
// 		if presentBwResp.Key == of.PresentBwInfo {
// 			_, err := strconv.Atoi(prevBwResp.Val)
// 			if err == nil {
// 				bwInfo.PresentBw = presentBwResp.Val
// 			}
// 		}
// 		if bwInfo.PresentBw == bwInfo.PrevBw {
// 			return of.BwAvailDetails{}
// 		}
// 		logger.Infow(ctx, "Bandwidth-consumed-info", log.Fields{"BwConsumed": bwInfo})
// 	}
// 	return bwInfo
// }
