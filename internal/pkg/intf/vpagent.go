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

package intf

import (
	"context"

	"voltha-go-controller/internal/pkg/holder"

	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
)

// VPClientCfg structure
type VPClientCfg struct {
	DeviceID         string
	SerialNum        string
	SouthBoundID     string
	VolthaClient     *holder.VolthaServiceClientHolder
	PacketOutChannel chan *ofp.PacketOut
}

// DiscoveryType type
type DiscoveryType uint8

const (
	// DeviceDisc constant
	DeviceDisc DiscoveryType = 0
	// DeviceReDisc constant
	DeviceReDisc DiscoveryType = 1
)

// IVPClient interface
type IVPClient interface {
	ChangeEvent(*ofp.ChangeEvent) error
	PacketIn(context.Context, *ofp.PacketIn)
	ConnectInd(cxt context.Context, DiscType DiscoveryType)
	Stop()
}

// VPAgent interface
type VPAgent interface {
	receiveOltRebootNoti(ctx context.Context)
	handleOltRebootNoti(ctx context.Context)
}

// IVPClientAgent interface
type IVPClientAgent interface {
	AddNewDevice(cfg *VPClientCfg)
	DelDevice(cntx context.Context, id string)
	IsRebootInProgressForDevice(device string) bool
	// RebootInd(string, string, string)
	IsBlockedDevice(string) bool
	AddBlockedDevices(string)
	DelBlockedDevices(string)
}
