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
	"time"

	"github.com/google/gopacket"
)

// ------------------------------------------------------------------
// ********** Tasks
//
// IGMP related tasks which essentially process packets and the ticks
// This is to serailize access to data structures and this also limits
// the amount of CPU consumed. We can bring more capacity by running
// more groups in parallel as we need to add parallelism

// -----------------------------------------------------------------
// ** Timer Task **
//
// Timer processing - Tick is a poke that the IGMP processing receives
// from the timer thread. The entire IGMP processing receives a single
// tick.

// TickTask structure
type TickTask struct {
	ctx    context.Context
	taskID uint8
	ts     string
}

// NewTickTask is constructor for TickTask
func NewTickTask() *TickTask {
	return &TickTask{}
}

// Name to return the name of the task
func (tt *TickTask) Name() string {
	return "Process Tick"
}

// TaskID to return the task id
func (tt *TickTask) TaskID() uint8 {
	return tt.taskID
}

// Timestamp to return the timestamp of task
func (tt *TickTask) Timestamp() string {
	return tt.ts
}

// Stop to stop the task
func (tt *TickTask) Stop() {
}

// Start to start the task
func (tt *TickTask) Start(ctx context.Context, taskID uint8) error {
	tt.taskID = taskID
	tt.ctx = ctx
	GetApplication().IgmpTick()
	return nil
}

// ---------------------------------------------------------------
// ** Packet processing Task **
//
//

// IgmpPacketTask structure
type IgmpPacketTask struct {
	ctx    context.Context
	taskID uint8
	Device string
	Port   string
	Pkt    gopacket.Packet
	ts     string
}

// NewIgmpPacketTask is the constructor for IgmpPacketTask
func NewIgmpPacketTask(device string, port string, pkt gopacket.Packet) *IgmpPacketTask {
	var pt IgmpPacketTask
	pt.Device = device
	pt.Port = port
	pt.Pkt = pkt
	pt.ts = (time.Now()).Format(time.RFC3339Nano)
	return &pt
}

// Name to return name of the task
func (pt *IgmpPacketTask) Name() string {
	return "Igmp Packet Task"
}

// TaskID to return the task id
func (pt *IgmpPacketTask) TaskID() uint8 {
	return pt.taskID
}

// Timestamp to return the timestamp for the task
func (pt *IgmpPacketTask) Timestamp() string {
	return pt.ts
}

// Stop to stop the task
func (pt *IgmpPacketTask) Stop() {
}

// Start to start the task
func (pt *IgmpPacketTask) Start(ctx context.Context, taskID uint8) error {
	pt.taskID = taskID
	pt.ctx = ctx
	GetApplication().IgmpProcessPkt(pt.Device, pt.Port, pt.Pkt)
	return nil
}

// UpdateMvlanTask structure
type UpdateMvlanTask struct {
	ctx      context.Context
	taskID   uint8
	DeviceID string
	mvp      *MvlanProfile
	ts       string
}

// NewUpdateMvlanTask is the constructor for UpdateMvlanTask
func NewUpdateMvlanTask(mvp *MvlanProfile, deviceID string) *UpdateMvlanTask {
	var mt UpdateMvlanTask
	mt.mvp = mvp
	mt.DeviceID = deviceID
	mt.ts = (time.Now()).Format(time.RFC3339Nano)
	return &mt
}

// Name to retun the name of the task
func (mt *UpdateMvlanTask) Name() string {
	return "Update Mvlan Task"
}

// TaskID to return the task id of the task
func (mt *UpdateMvlanTask) TaskID() uint8 {
	return mt.taskID
}

// Timestamp to return the timestamp of the task
func (mt *UpdateMvlanTask) Timestamp() string {
	return mt.ts
}

// Stop to stop the task
func (mt *UpdateMvlanTask) Stop() {
}

// Start to start the task
func (mt *UpdateMvlanTask) Start(ctx context.Context, taskID uint8) error {
	mt.taskID = taskID
	mt.ctx = ctx
	mvp := mt.mvp
	mvp.UpdateProfile(mt.DeviceID)
	return nil
}
