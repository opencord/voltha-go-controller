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
	"fmt"
	"strings"
	"sync"

	"github.com/donNewtonAlpha/goloxi"
	ofp "github.com/donNewtonAlpha/goloxi/of13"
	"github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/opencord/voltha-protos/v5/go/voltha"
)

var mu sync.Mutex
var xid uint32 = 1

// GetXid to get xid
func GetXid() uint32 {
	mu.Lock()
	defer mu.Unlock()
	xid++
	return xid
}

// PadString for padding of string
func PadString(value string, padSize int) string {
	size := len(value)
	nullsNeeded := padSize - size
	null := fmt.Sprintf("%c", '\000')
	padded := strings.Repeat(null, nullsNeeded)
	return fmt.Sprintf("%s%s", value, padded)
}

// extractAction for extract action
func extractAction(action ofp.IAction) *openflow_13.OfpAction {
	var ofpAction openflow_13.OfpAction
	switch action.GetType() {
	case ofp.OFPATOutput:
		var outputAction openflow_13.OfpAction_Output
		loxiOutputAction := action.(*ofp.ActionOutput)
		var output openflow_13.OfpActionOutput
		output.Port = uint32(loxiOutputAction.GetPort())
		/*
			var maxLen uint16
			maxLen = loxiOutputAction.GetMaxLen()
			output.MaxLen = uint32(maxLen)

		*/
		output.MaxLen = 0
		outputAction.Output = &output
		ofpAction.Action = &outputAction
		ofpAction.Type = openflow_13.OfpActionType_OFPAT_OUTPUT
	case ofp.OFPATCopyTtlOut: //CopyTtltOut
	case ofp.OFPATCopyTtlIn: //CopyTtlIn
	case ofp.OFPATSetMplsTtl: //SetMplsTtl
	case ofp.OFPATDecMplsTtl: //DecMplsTtl
	case ofp.OFPATPushVLAN: //PushVlan
		var pushVlan openflow_13.OfpAction_Push
		loxiPushAction := action.(*ofp.ActionPushVlan)
		var push openflow_13.OfpActionPush
		push.Ethertype = uint32(loxiPushAction.Ethertype) //TODO This should be available in the fields
		pushVlan.Push = &push
		ofpAction.Type = openflow_13.OfpActionType_OFPAT_PUSH_VLAN
		ofpAction.Action = &pushVlan
	case ofp.OFPATPopVLAN: //PopVlan
		ofpAction.Type = openflow_13.OfpActionType_OFPAT_POP_VLAN
	case ofp.OFPATPushMpls: //PushMpls
	case ofp.OFPATPopMpls: //PopMpls
	case ofp.OFPATSetQueue: //SetQueue
	case ofp.OFPATGroup: //ActionGroup
	case ofp.OFPATSetNwTtl: //SetNwTtl
	case ofp.OFPATDecNwTtl: //DecNwTtl
	case ofp.OFPATSetField: //SetField
		ofpAction.Type = openflow_13.OfpActionType_OFPAT_SET_FIELD
		var ofpActionForSetField openflow_13.OfpAction_SetField
		var ofpActionSetField openflow_13.OfpActionSetField
		var ofpOxmField openflow_13.OfpOxmField
		ofpOxmField.OxmClass = openflow_13.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
		var ofpOxmFieldForOfbField openflow_13.OfpOxmField_OfbField
		var ofpOxmOfbField openflow_13.OfpOxmOfbField
		loxiSetField := action.(*ofp.ActionSetField)
		oxmName := loxiSetField.Field.GetOXMName()
		switch oxmName {
		//TODO handle set field sith other fields
		case "vlan_vid":
			ofpOxmOfbField.Type = openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID
			var vlanVid openflow_13.OfpOxmOfbField_VlanVid
			var VlanVid = loxiSetField.Field.GetOXMValue().(uint16)
			vlanVid.VlanVid = uint32(VlanVid)

			ofpOxmOfbField.Value = &vlanVid
		}
		ofpOxmFieldForOfbField.OfbField = &ofpOxmOfbField
		ofpOxmField.Field = &ofpOxmFieldForOfbField
		ofpActionSetField.Field = &ofpOxmField
		ofpActionForSetField.SetField = &ofpActionSetField
		ofpAction.Action = &ofpActionForSetField

	case ofp.OFPATPushPbb: //PushPbb
	case ofp.OFPATPopPbb: //PopPbb
	case ofp.OFPATExperimenter: //Experimenter

	}
	return &ofpAction

}

// parseOxm for parsing OxmOfb field
func parseOxm(ofbField *openflow_13.OfpOxmOfbField, DeviceID string) (goloxi.IOxm, uint16) {
	switch ofbField.Type {
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_IN_PORT:
		ofpInPort := ofp.NewOxmInPort()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_Port)
		ofpInPort.Value = ofp.Port(val.Port)
		return ofpInPort, 4
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_ETH_TYPE:
		ofpEthType := ofp.NewOxmEthType()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_EthType)
		ofpEthType.Value = ofp.EthernetType(val.EthType)
		return ofpEthType, 2
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_IN_PHY_PORT:
		ofpInPhyPort := ofp.NewOxmInPhyPort()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_PhysicalPort)
		ofpInPhyPort.Value = ofp.Port(val.PhysicalPort)
		return ofpInPhyPort, 4
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_IP_PROTO:
		ofpIPProto := ofp.NewOxmIpProto()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_IpProto)
		ofpIPProto.Value = ofp.IpPrototype(val.IpProto)
		return ofpIPProto, 1
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_UDP_SRC:
		ofpUDPSrc := ofp.NewOxmUdpSrc()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_UdpSrc)
		ofpUDPSrc.Value = uint16(val.UdpSrc)
		return ofpUDPSrc, 2
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_UDP_DST:
		ofpUDPDst := ofp.NewOxmUdpDst()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_UdpDst)
		ofpUDPDst.Value = uint16(val.UdpDst)
		return ofpUDPDst, 2
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID:
		ofpVlanVid := ofp.NewOxmVlanVid()
		val := ofbField.GetValue()
		if val == nil {
			ofpVlanVid.Value = uint16(0)
			return ofpVlanVid, 2
		}
		vlanID := val.(*openflow_13.OfpOxmOfbField_VlanVid)
		if ofbField.HasMask {
			ofpVlanVidMasked := ofp.NewOxmVlanVidMasked()
			valMask := ofbField.GetMask()
			vlanMask := valMask.(*openflow_13.OfpOxmOfbField_VlanVidMask)
			if vlanID.VlanVid == 4096 && vlanMask.VlanVidMask == 4096 {
				ofpVlanVidMasked.Value = uint16(vlanID.VlanVid)
				ofpVlanVidMasked.ValueMask = uint16(vlanMask.VlanVidMask)
			} else {
				ofpVlanVidMasked.Value = uint16(vlanID.VlanVid) | 0x1000
				ofpVlanVidMasked.ValueMask = uint16(vlanMask.VlanVidMask)

			}
			return ofpVlanVidMasked, 4
		}
		ofpVlanVid.Value = uint16(vlanID.VlanVid) | 0x1000
		return ofpVlanVid, 2
	case openflow_13.OxmOfbFieldTypes_OFPXMT_OFB_METADATA:
		ofpMetadata := ofp.NewOxmMetadata()
		val := ofbField.GetValue().(*openflow_13.OfpOxmOfbField_TableMetadata)
		ofpMetadata.Value = val.TableMetadata
		return ofpMetadata, 8
	default:
	}
	return nil, 0
}

// parseInstructions for parsing of instructions
func parseInstructions(ofpInstruction *openflow_13.OfpInstruction, DeviceID string) (ofp.IInstruction, uint16) {
	instType := ofpInstruction.Type
	data := ofpInstruction.GetData()
	switch instType {
	case ofp.OFPITWriteMetadata:
		instruction := ofp.NewInstructionWriteMetadata()
		instruction.Len = 24
		metadata := data.(*openflow_13.OfpInstruction_WriteMetadata).WriteMetadata
		instruction.Metadata = uint64(metadata.Metadata)
		return instruction, 24
	case ofp.OFPITMeter:
		instruction := ofp.NewInstructionMeter()
		instruction.Len = 8
		meter := data.(*openflow_13.OfpInstruction_Meter).Meter
		instruction.MeterId = meter.MeterId
		return instruction, 8
	case ofp.OFPITGotoTable:
		instruction := ofp.NewInstructionGotoTable()
		instruction.Len = 8
		gotoTable := data.(*openflow_13.OfpInstruction_GotoTable).GotoTable
		instruction.TableId = uint8(gotoTable.TableId)
		return instruction, 8
	case ofp.OFPITApplyActions:
		instruction := ofp.NewInstructionApplyActions()
		var instructionSize uint16
		instructionSize = 8
		//ofpActions := ofpInstruction.GetActions().Actions
		var actions []goloxi.IAction
		for _, ofpAction := range ofpInstruction.GetActions().Actions {
			action, actionSize := parseAction(ofpAction, DeviceID)
			actions = append(actions, action)
			instructionSize += actionSize

		}
		instruction.Actions = actions
		instruction.SetLen(instructionSize)
		return instruction, instructionSize
	}
	//shouldn't have reached here :<
	return nil, 0
}

// parseAction for parsing of actions
func parseAction(ofpAction *openflow_13.OfpAction, DeviceID string) (goloxi.IAction, uint16) {
	switch ofpAction.Type {
	case openflow_13.OfpActionType_OFPAT_OUTPUT:
		ofpOutputAction := ofpAction.GetOutput()
		outputAction := ofp.NewActionOutput()
		outputAction.Port = ofp.Port(ofpOutputAction.Port)
		outputAction.MaxLen = uint16(ofpOutputAction.MaxLen)
		outputAction.Len = 16
		return outputAction, 16
	case openflow_13.OfpActionType_OFPAT_PUSH_VLAN:
		ofpPushVlanAction := ofp.NewActionPushVlan()
		ofpPushVlanAction.Ethertype = uint16(ofpAction.GetPush().Ethertype)
		ofpPushVlanAction.Len = 8
		return ofpPushVlanAction, 8
	case openflow_13.OfpActionType_OFPAT_POP_VLAN:
		ofpPopVlanAction := ofp.NewActionPopVlan()
		ofpPopVlanAction.Len = 8
		return ofpPopVlanAction, 8
	case openflow_13.OfpActionType_OFPAT_SET_FIELD:
		ofpActionSetField := ofpAction.GetSetField()
		setFieldAction := ofp.NewActionSetField()

		iOxm, _ := parseOxm(ofpActionSetField.GetField().GetOfbField(), DeviceID)
		setFieldAction.Field = iOxm
		setFieldAction.Len = 16
		return setFieldAction, 16
	default:
	}
	return nil, 0
}

// parsePortStats for parsing of port stats
func parsePortStats(port *voltha.LogicalPort) *ofp.PortStatsEntry {
	stats := port.OfpPortStats
	port.OfpPort.GetPortNo()
	var entry ofp.PortStatsEntry
	entry.SetPortNo(ofp.Port(port.OfpPort.GetPortNo()))
	entry.SetRxPackets(stats.GetRxPackets())
	entry.SetTxPackets(stats.GetTxPackets())
	entry.SetRxBytes(stats.GetRxBytes())
	entry.SetTxBytes(stats.GetTxBytes())
	entry.SetRxDropped(stats.GetRxDropped())
	entry.SetTxDropped(stats.GetTxDropped())
	entry.SetRxErrors(stats.GetRxErrors())
	entry.SetTxErrors(stats.GetTxErrors())
	entry.SetRxFrameErr(stats.GetRxFrameErr())
	entry.SetRxOverErr(stats.GetRxOverErr())
	entry.SetRxCrcErr(stats.GetRxCrcErr())
	entry.SetCollisions(stats.GetCollisions())
	entry.SetDurationSec(stats.GetDurationSec())
	entry.SetDurationNsec(stats.GetDurationNsec())
	return &entry
}
