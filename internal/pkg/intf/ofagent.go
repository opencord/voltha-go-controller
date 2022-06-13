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

// OFClientCfg structure
type OFClientCfg struct {
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

// IOFClient interface
type IOFClient interface {
	ChangeEvent(*ofp.ChangeEvent) error
	PacketIn(*ofp.PacketIn)
	ConnectInd(cxt context.Context, DiscType DiscoveryType)
	Stop()
}

// OFAgent interface
type OFAgent interface {
	receiveOltRebootNoti(ctx context.Context)
	handleOltRebootNoti(ctx context.Context)
}

// IOFClientAgent interface
type IOFClientAgent interface {
	AddNewDevice(cfg *OFClientCfg)
	DelDevice(id string)
	IsRebootInProgressForDevice(device string) bool
	// RebootInd(string, string, string)
	IsBlockedDevice(string) bool
	AddBlockedDevices(string)
	DelBlockedDevices(string)
}
