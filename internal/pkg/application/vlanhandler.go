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
	"voltha-go-controller/internal/pkg/of"
)

//UpdateVlanStatus - updates vlan state to status map
func (d *VoltDevice) UpdateVlanStatus(vlan uint16, status bool) {
	logger.Error(ctx, "UpdateVlanStatus - Func Unimplemented")
}

//sendGetVlanStatusReq sends query request for a given olt device to netcfg-mgr
// to obtain the status of VLANs configured on vlan on a pOLT Device
func sendGetVlanStatusReq(oltSerialNumber string, vlans []of.VlanType) {
}

func (d *VoltDevice) checkVlanReqAssociation(vlan of.VlanType, profileName string, success bool) bool {
	return false
}

//TriggerPendingVlanDisableReq - trigger pending vlan disable request
func (va *VoltApplication) TriggerPendingVlanDisableReq(device string) {
}

//collectAllVlanStatus - queries vlan status for all configured svlans and mvlans
func (va *VoltApplication) collectAllVlanStatus(d *VoltDevice) {
}
