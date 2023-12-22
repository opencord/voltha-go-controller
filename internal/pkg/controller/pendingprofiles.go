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

	"voltha-go-controller/log"
)

// PendingProfilesTask structure
type PendingProfilesTask struct {
	ctx    context.Context
	device *Device
	ts     string
	taskID uint8
}

// NewPendingProfilesTask is constructor for PendingProfilesTask
func NewPendingProfilesTask(device *Device) *PendingProfilesTask {
	var ppt PendingProfilesTask
	ppt.device = device
	ppt.ts = (time.Now()).Format(time.RFC3339Nano)
	return &ppt
}

// Name returns name of the task
func (ppt *PendingProfilesTask) Name() string {
	return "Pending Profiles Task"
}

// TaskID returns task id of the task
func (ppt *PendingProfilesTask) TaskID() uint8 {
	return ppt.taskID
}

// Timestamp returns timestamp of the task
func (ppt *PendingProfilesTask) Timestamp() string {
	return ppt.ts
}

// Stop to stop the task
func (ppt *PendingProfilesTask) Stop() {
}

// Start is called by the framework and is responsible for implementing
// the actual task.
func (ppt *PendingProfilesTask) Start(ctx context.Context, taskID uint8) error {
	logger.Warnw(ctx, "Pending Profiles Task Triggered", log.Fields{"Context": ctx, "taskID": taskID, "Device": ppt.device.ID})
	ppt.taskID = taskID
	ppt.ctx = ctx
	var errInfo error

	GetController().SetAuditFlags(ppt.device)

	//Trigger Pending Service Delete Tasks
	logger.Warnw(ctx, "Pending Service Delete Task Triggered", log.Fields{"Device": ppt.device.ID})
	GetController().TriggerPendingProfileDeleteReq(ctx, ppt.device.ID)
	logger.Warnw(ctx, "Pending Service Delete Task Completed", log.Fields{"Device": ppt.device.ID})

	//Trigger Pending Migrate Services Tasks
	logger.Warnw(ctx, "Pending Migrate Services Task Triggered", log.Fields{"Device": ppt.device.ID})
	GetController().TriggerPendingMigrateServicesReq(ctx, ppt.device.ID)
	logger.Warnw(ctx, "Pending Migrate Services Task Completed", log.Fields{"Device": ppt.device.ID})

	GetController().ResetAuditFlags(ppt.device)

	// Updating Mvlan Profile
	logger.Warnw(ctx, "Pending Update Mvlan Task Triggered", log.Fields{"Device": ppt.device.ID})
	if err := ppt.UpdateMvlanProfiles(ctx); err != nil {
		logger.Errorw(ctx, "Update Mvlan Profile Failed", log.Fields{"Reason": err.Error()})
		errInfo = err
	}
	logger.Warnw(ctx, "Pending Update Mvlan Task Completed", log.Fields{"Device": ppt.device.ID})

	logger.Warnw(ctx, "Pending Profiles Task Completed", log.Fields{"Context": ctx, "taskID": taskID, "Device": ppt.device.ID})
	return errInfo
}

// UpdateMvlanProfiles to update the mvlan profiles
func (ppt *PendingProfilesTask) UpdateMvlanProfiles(cntx context.Context) error {
	GetController().UpdateMvlanProfiles(cntx, ppt.device.ID)
	return nil
}
# [EOF] - delta:force
