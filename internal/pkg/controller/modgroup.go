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
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
	"google.golang.org/grpc/codes"
)

//ModGroupTask - Group Modification Task
type ModGroupTask struct {
	taskID    uint8
	ctx       context.Context
	group     *of.Group
	device    *Device
	timestamp string
}

//NewModGroupTask - Initializes new group task
func NewModGroupTask(ctx context.Context, group *of.Group, device *Device) *ModGroupTask {
	var grp ModGroupTask
	grp.device = device
	grp.group = group
	grp.ctx = ctx
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	grp.timestamp = tstamp
	return &grp
}

//Name - Name of task
func (grp *ModGroupTask) Name() string {
	return "Group Mod Task"
}

//TaskID - Task id
func (grp *ModGroupTask) TaskID() uint8 {
	return grp.taskID
}

// Timestamp to return timestamp of the task
func (grp *ModGroupTask) Timestamp() string {
	return grp.timestamp
}

//Stop - task stop
func (grp *ModGroupTask) Stop() {
}

//Start - task start
func (grp *ModGroupTask) Start(ctx context.Context, taskID uint8) error {
	var err error
	grp.taskID = taskID
	grp.ctx = ctx
	i := 0

	processGroupModResult := func(err error) bool {

		statusCode, statusMsg := infraerror.GetErrorInfo(err)

		if infraerrorcode.ErrorCode(statusCode) != infraerrorcode.ErrOk {

			if grp.group.Command == of.GroupCommandAdd && (codes.Code(statusCode) == codes.AlreadyExists) {
				logger.Warnw(ctx, "Update Group Table Failed - Ignoring since Group Already exists",
					log.Fields{"groupId": grp.group.GroupID, "groupOp": grp.group.Command, "Status": statusCode, "errorReason": statusMsg})
				return true
			}
			logger.Errorw(ctx, "Update Group Table Failed",
				log.Fields{"groupId": grp.group.GroupID, "groupOp": grp.group.Command, "Status": statusCode, "errorReason": statusMsg})
			return false
		}
		logger.Infow(ctx, "Group Mod Result", log.Fields{"groupID": grp.group.GroupID, "Error Code": statusCode})
		return true

	}

	if grp.group.Command != of.GroupCommandDel {
		grp.group.State = of.GroupOperPending
		grp.device.UpdateGroupEntry(grp.group)
	} else {
		grp.device.DelGroupEntry(grp.group)
	}

	if !grp.device.isSBOperAllowed(grp.group.ForceAction) {
		logger.Errorw(ctx, "Skipping Group Table Update", log.Fields{"Reason": "Device State not UP", "State": grp.device.State, "GroupID": grp.group.GroupID, "Operation": grp.group.Command})
		return nil
	}

	groupUpdate := of.CreateGroupTableUpdate(grp.group)
	if vc := grp.device.VolthaClient(); vc != nil {

		//Retry on group mod failure
		//Retry attempts = 3
		//Delay between retry = 100ms. Total Possible Delay = 200ms
		for {
			logger.Infow(ctx, "Group Mod Triggered", log.Fields{"GroupId": grp.group.GroupID, "Attempt": i})
			_, err = vc.UpdateLogicalDeviceFlowGroupTable(grp.ctx, groupUpdate)
			if isSuccess := processGroupModResult(err); isSuccess {
				break
			}
			i++
			if i < 3 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			logger.Errorw(ctx, "Update Group Table Failed on all 3 attempts. Dropping request", log.Fields{"GroupId": grp.group.GroupID, "Bucket": grp.group.Buckets})
			break

		}
		return err
	}
	logger.Error(ctx, "Update Group Flow Table Failed: Voltha Client Unavailable")
	return nil
}
