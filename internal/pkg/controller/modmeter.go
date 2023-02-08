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

	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"
)

// ModMeterTask structure
type ModMeterTask struct {
	taskID    uint8
	ctx       context.Context
	command   of.MeterCommand
	meter     *of.Meter
	device    *Device
	timestamp string
}

// NewModMeterTask is the constructor for ModMeterTask
func NewModMeterTask(ctx context.Context, command of.MeterCommand, meter *of.Meter, device *Device) *ModMeterTask {
	var mmt ModMeterTask
	mmt.device = device
	mmt.meter = meter
	mmt.ctx = ctx
	mmt.command = command
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	mmt.timestamp = tstamp
	return &mmt
}

// Name returns name of the task
func (mmt *ModMeterTask) Name() string {
	return "Add Flows Task"
}

// TaskID returns task Id of the task
func (mmt *ModMeterTask) TaskID() uint8 {
	return mmt.taskID
}

// Timestamp returns time stamp for the task
func (mmt *ModMeterTask) Timestamp() string {
	return mmt.timestamp
}

// Stop to stop the task
func (mmt *ModMeterTask) Stop() {
}

// Start to start the task
func (mmt *ModMeterTask) Start(ctx context.Context, taskID uint8) error {
	mmt.taskID = taskID
	mmt.ctx = ctx

	//Temp commenting Sync response handling
	//triggerMeterNotification := func(err error) {

	// 	statusCode, statusMsg := infraerror.GetErrorInfo(err)

	// 	if mmt.command == of.MeterCommandAdd && infraerrorcode.ErrorCode(statusCode) != infraerrorcode.ErrOk {
	// 		mmt.meter.State = of.MeterOperFailure
	// 		mmt.meter.ErrorReason = statusMsg

	// 		logger.Errorw(ctx, "Update Meter Table Failed",
	// 			log.Fields{"meterId": mmt.meter.ID, "meterOp": mmt.command, "Status": statusCode, "errorReason": statusMsg})
	// 		go mmt.device.AddMeterToDb(mmt.meter)
	// 	} else {
	// 		logger.Infow("Meter Mod Result", log.Fields{"meterID": mmt.meter.ID, "Error Code": statusCode})
	// 	}
	// }

	// First add/delete the flows first locally before passing them to actual device
	if mmt.command == of.MeterCommandAdd {
		mmt.meter.State = of.MeterOperPending
		if err := mmt.device.AddMeter(ctx, mmt.meter); err != nil {
			// Meter already exists so we dont have to do anything here
			return nil
		}
		logger.Infow(ctx, "Updated meter state to pending", log.Fields{"Meter": mmt.meter.ID})
	} else {
		if !mmt.device.DelMeter(ctx, mmt.meter) {
			// Meter doesn't exist so we dont have to do anything here
			return nil
		}
	}

	if mmt.device.State != DeviceStateUP {
		logger.Errorw(ctx, "Update Meter Table Failed: Device State DOWN", log.Fields{"Reason": "Device State DOWN", "Meter": mmt.meter.ID})
		return nil
	}
	meterMod, err := of.MeterUpdate(mmt.device.ID, mmt.command, mmt.meter)
	if err != nil {
		logger.Errorw(ctx, "Update Meter Table Failed", log.Fields{"Reason": err.Error()})
		return err
	}

	if vc := mmt.device.VolthaClient(); vc != nil {

		if _, err = vc.UpdateLogicalDeviceMeterTable(mmt.ctx, meterMod); err != nil {
			logger.Errorw(ctx, "Update Meter Table Failed", log.Fields{"Reason": err.Error()})
		} else {
			mmt.meter.State = of.MeterOperSuccess
			if err := mmt.device.UpdateMeter(ctx, mmt.meter); err != nil {
				// Meter does not exist, update failed
				logger.Error(ctx, "Update meter to DB failed")
			}
			logger.Infow(ctx, "Updated meter state to success", log.Fields{"Meter": mmt.meter.ID})
		}
		//triggerMeterNotification(err)
		return err
	}

	logger.Error(ctx, "Update Meter Table Failed: Voltha Client Unavailable")
	return nil
}
