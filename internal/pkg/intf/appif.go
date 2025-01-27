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
	"voltha-go-controller/internal/pkg/of"
)

// App Interface
type App interface {
	PortAddInd(context.Context, string, uint32, string)
	PortDelInd(context.Context, string, string)
	PortUpdateInd(string, string, uint32)
	PacketInInd(context.Context, string, string, []byte)
	PortUpInd(context.Context, string, string)
	PortDownInd(context.Context, string, string)
	AddDevice(context.Context, string, string, string)
	DeviceUpInd(string)
	DeviceDownInd(string)
	DelDevice(context.Context, string)
	SetRebootFlag(bool)
	ProcessFlowModResultIndication(context.Context, FlowStatus)
	CheckAndDeactivateService(context.Context, *of.VoltSubFlow, string, string)
	DeviceRebootInd(context.Context, string, string, string)
	DeviceDisableInd(context.Context, string)
	UpdateMvlanProfilesForDevice(context.Context, string)
	TriggerPendingProfileDeleteReq(context.Context, string)
	TriggerPendingMigrateServicesReq(context.Context, string)
}
