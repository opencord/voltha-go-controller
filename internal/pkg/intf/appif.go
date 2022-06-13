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

// App Interface
type App interface {
	PortAddInd(string, uint32, string)
	PortDelInd(string, string)
	PortUpdateInd(string, string, uint32)
	PacketInInd(string, string, []byte)
	PortUpInd(string, string)
	PortDownInd(string, string)
	AddDevice(string, string, string)
	DeviceUpInd(string)
	DeviceDownInd(string)
	DelDevice(string)
	SetRebootFlag(bool)
	ProcessFlowModResultIndication(FlowStatus)
	DeviceRebootInd(string, string, string)
	DeviceDisableInd(string)
	UpdateMvlanProfilesForDevice(string)
	TriggerPendingProfileDeleteReq(string)
	TriggerPendingMigrateServicesReq(string)
}
