/*

* Copyright 2022-2024present Open Networking Foundation
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

package onosnbi

import (
	"fmt"
	"strconv"
	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/controller"

	"voltha-go-controller/internal/pkg/of"
)

const (
	/** Switch input port. */
	InPort string = "IN_PORT"

	/** Switch physical input port. */
	InPhyPort string = "IN_PHY_PORT"

	/** Metadata passed between tables. */
	MetaData string = "METADATA"

	/** Ethernet destination address. */
	EthDst string = "ETH_DST"

	/** Ethernet destination address with masking. */
	EthDstMasked = "ETH_DST_MASKED"

	/** Ethernet source address. */
	EthSrc string = "ETH_SRC"

	/** Ethernet source address with masking. */
	EthSrcMasked string = "ETH_SRC_MASKED"

	/** Ethernet frame type. */
	EthType string = "ETH_TYPE"

	/** VLAN id. */
	VlanVID string = "VLAN_VID"

	/** VLAN priority. */
	VlanPcp string = "VLAN_PCP"
	/**
	 * Inner VLAN id.
	 *
	 * Note: Some drivers may not support this.
	 */
	InnerVlanVID string = "INNER_VLAN_VID"

	/**
	 * Inner VLAN pcp.
	 *
	 * Note: Some drivers may not support this.
	 */
	InnerVlanPcp string = "INNER_VLAN_PCP"

	/** IP DSCP (6 bits in ToS field). */
	IPDscp string = "IP_DSCP"

	/** IP ECN (2 bits in ToS field). */
	IPEcn string = "IP_ECN"

	/** IP protocol. */
	IPProto string = "IP_PROTO"

	/** IPv4 source address. */
	Ipv4Src string = "IPV4_SRC"

	/** IPv4 destination address. */
	Ipv4Dst string = "IPV4_DST"

	/** TCP source port. */
	TCPSrc string = "TCP_SRC"

	/** TCP source port with masking. */
	TCPSrcMasked string = "TCP_SRC_MASKED"

	/** TCP destination port. */
	TCPDst string = "TCP_DST"

	/** TCP destination port with masking. */
	TCPDstMasked string = "TCP_DST"

	/** UDP source port. */
	UDPSrc string = "UDP_SRC"

	/** UDP source port with masking. */
	UDPSrcMasked string = "UDP_SRC_MASKED"

	/** UDP destination port. */
	UDPDst string = "UDP_DST"

	/** UDP destination port with masking. */
	UDPDstMasked string = "UDP_DST_MASKED"

	/** SCTP source port. */
	SctpSrc string = "SCTP_SRC"

	/** SCTP source port with masking. */
	SctpSrcMasked string = "SCTP_SRC_MASKED"

	/** SCTP destination port. */
	SctpDst string = "SCTP_DST"

	/** SCTP destination port with masking. */
	SctpDstMasked string = "SCTP_DST_MASKED"

	/** ICMP type. */
	Icmpv4Type string = "ICMPV4_TYPE"

	/** ICMP code. */
	Icmpv4Code string = "ICMPV4_CODE"

	/** ARP opcode. */
	ArpOp string = "ARP_OP"

	/** ARP source IPv4 address. */
	ArpSpa string = "ARP_SPA"

	/** ARP target IPv4 address. */
	ArpTpa string = "ARP_TPA"

	/** ARP source hardware address. */
	ArpTha string = "ARP_THA"

	/** IPv6 source address. */
	Ipv6Src string = "IPV6_SRC"

	/** IPv6 destination address. */
	Ipv6Dst string = "IPV6_DST"

	/** IPv6 Flow Label. */
	Ipv6Flabel string = "IPV6_FLABEL"

	/** ICMPv6 type. */
	Icmpv6Type string = "ICMPV6_TYPE"

	/** ICMPv6 code. */
	Icmpv6Code string = "ICMPV6_CODE"

	/** Target address for ND. */
	Ipv6NdTarget string = "IPV6_ND_TARGET"

	/** Source link-layer for ND. */
	Ipv6NdSll string = "IPV6_ND_SLL"

	/** Target link-layer for ND. */
	Ipv6NdTll string = "IPV6_ND_TLL"

	/** MPLS label. */
	MplsLabel string = "MPLS_LABEL"

	/** MPLS TC. */
	MplsTc string = "MPLS_TC"

	/**  MPLS BoS bit. */
	MplsBos string = "MPLS_BOS"

	/** PBB I-SID. */
	PbbIsID string = "PBB_ISID"

	/** Logical Port Metadata. */
	TunnelID string = "TUNNEL_ID"

	/** IPv6 Extension Header pseudo-field. */
	Ipv6Exthdr string = "IPV6_EXTHDR"

	/** Unassigned value: 40. */
	Unassigned40 string = "UNASSIGNED_40"

	/** PBB UCA header field. */
	PbbUca string = "PBB_UCA"

	/** TCP flags. */
	TCPFlags string = "TCP_FLAGS"

	/** Output port from action set metadata. */
	ActsetOutput string = "ACTSET_OUTPUT"

	/** Packet type value. */
	PacketType string = "PACKET_TYPE"

	//
	// NOTE: Everything below is defined elsewhere: ONOS-specific,
	// extensions, etc.
	//
	/** Optical channel signal ID (lambda). */
	OchSigID string = "OCH_SIGID"

	/** Optical channel signal type (fixed or flexible). */
	OchSigType string = "OCH_SIGTYPE"

	/** ODU (Optical channel Data Unit) signal ID. */
	OduSigID string = "ODU_SIGID"

	/** ODU (Optical channel Data Unit) signal type. */
	OduSigType string = "ODU_SIGTYPE"

	/** Protocol-independent. */
	ProtocolIndependent string = "PROTOCOL_INDEPENDENT"

	/** Extension criterion. */
	Extension string = "EXTENSION"

	/** An empty criterion. */
	Dummy string = "DUMMY"

	/* OUTPUT instruction */
	Output string = "OUTPUT"

	/* METER instruction */
	Meter string = "METER"

	/* L2MODIFICATION instruction type */
	L2Modification string = "L2MODIFICATION"

	/* VLAN_PUSH operation */
	VlanPush string = "VLAN_PUSH"

	/* VLAN_ID instruction */
	VlanID string = "VLAN_ID"

	/* VLAN_POP operation */
	VlanPop string = "VLAN_POP"

	/* VLAN_SET operation */
	VlanSet string = "VLAN_SET"

	All string = "ALL"

	Added string = "ADDED"

	Failed string = "FAILED"

	FailedAdd string = "FAILED_ADD"

	PendingAdd string = "PENDING_ADD"

	PendingRemove string = "PENDING_REMOVE"

	Pending string = "PENDING"
)

// Selector Critrtion structs
type Criterion interface {
	GetType() string
}

type PortSelector struct {
	Type string `json:"type"`
	Port int    `json:"port,omitempty"`
}

func (s PortSelector) GetType() string {
	return s.Type
}

type EthTypeSelector struct {
	Type    string `json:"type"`
	EthType string `json:"ethType,omitempty"`
}

func (s EthTypeSelector) GetType() string {
	return s.Type
}

type ProtocolSelector struct {
	Type     string `json:"type"`
	Protocol int    `json:"protocol,omitempty"`
}

func (s ProtocolSelector) GetType() string {
	return s.Type
}

type UDPPortSelector struct {
	Type    string `json:"type"`
	UDPPort int    `json:"udpPort,omitempty"`
}

func (s UDPPortSelector) GetType() string {
	return s.Type
}

type VlanSelector struct {
	Type   string `json:"type"`
	VlanID int    `json:"vlanId,omitempty"`
}

func (s VlanSelector) GetType() string {
	return s.Type
}

type EthSrcSelector struct {
	Type   string `json:"type"`
	EthSrc string `json:"ethsrc,omitempty"`
}

func (s EthSrcSelector) GetType() string {
	return s.Type
}

type EthDstSelector struct {
	Type   string `json:"type"`
	DstSrc string `json:"ethdst,omitempty"`
}

func (s EthDstSelector) GetType() string {
	return s.Type
}

type MetaDataSelector struct {
	Type     string `json:"type"`
	Metadata uint64 `json:"metadata,omitempty"`
}

func (s MetaDataSelector) GetType() string {
	return s.Type
}

///////// END of selector interfaces

type SelectorInfo struct {
	Criteria []Criterion `json:"criteria"`
}

// Instruction structs are defined here
type Instruction interface {
	GetInstructionType() string
}

type PortInstruction struct {
	Type string `json:"type"`
	Port string `json:"port"`
}

func (i PortInstruction) GetInstructionType() string {
	return i.Type
}

type PushVlanInstruction struct {
	Type         string `json:"type"`
	SubType      string `json:"subtype"`
	EthernetType string `json:"ethernetType"`
}

func (i PushVlanInstruction) GetInstructionType() string {
	return i.Type
}

type VlanInstruction struct {
	Type    string `json:"type"`
	SubType string `json:"subtype"`
	VlanID  int    `json:"vlanId"`
}

func (i VlanInstruction) GetInstructionType() string {
	return i.Type
}

type PopVlanInstruction struct {
	Type    string `json:"type"`
	SubType string `json:"subtype"`
}

func (i PopVlanInstruction) GetInstructionType() string {
	return i.Type
}

type MeterInstruction struct {
	Type    string `json:"type"`
	MeterID string `json:"meterId"`
}

func (i MeterInstruction) GetInstructionType() string {
	return i.Type
}

type TreatmentInfo struct {
	Instructions []Instruction `json:"instructions"`
	Deferred     []interface{} `json:"deferred"`
}
type Flow struct {
	State       string        `json:"state"`
	LiveType    string        `json:"liveType"`
	ID          string        `json:"id"`
	AppID       string        `json:"appId"`
	DeviceID    string        `json:"deviceId"`
	TableName   string        `json:"tableName"`
	Treatment   TreatmentInfo `json:"treatment"`
	Selector    SelectorInfo  `json:"selector"`
	LastSeen    int64         `json:"lastSeen"`
	TableID     int           `json:"tableId"`
	Priority    int           `json:"priority"`
	Timeout     int           `json:"timeout"`
	GroupID     int           `json:"groupId"`
	Life        int           `json:"life"`
	Packets     int           `json:"packets"`
	Bytes       int           `json:"bytes"`
	IsPermanent bool          `json:"isPermanent"`
}

type FlowEntry struct {
	Flows []Flow `json:"flows"`
}

// Meter struct
type Meters struct {
	ID             string  `json:"id"`
	Unit           string  `json:"unit"`
	DeviceID       string  `json:"deviceId"`
	AppID          string  `json:"appId"`
	State          string  `json:"state"`
	MeterBands     []Bands `json:"bands"`
	Life           int     `json:"life"`
	Packets        int     `json:"packets"`
	Bytes          int     `json:"bytes"`
	ReferenceCount int     `json:"referenceCount"`
	Burst          bool    `json:"burst"`
}

type Bands struct {
	Type      string `json:"type"`
	Rate      int    `json:"rate"`
	Packets   int    `json:"packets"`
	Bytes     int    `json:"bytes"`
	BurstSize int    `json:"burstSize"`
	Prec      int    `json:"prec,omitempty"`
}

type GroupsInfo struct {
	Type           string   `json:"type"`
	DeviceID       string   `json:"deviceId"`
	AppID          string   `json:"appId"`
	AppCookie      string   `json:"appCookie"`
	State          string   `json:"state"`
	Buckets        []Bucket `json:"buckets"`
	ID             int      `json:"id"`
	Life           int      `json:"life"`
	Packets        int      `json:"packets"`
	Bytes          int      `json:"bytes"`
	ReferenceCount int      `json:"referenceCount"`
}

type Bucket struct {
	Type      string    `json:"type"`
	Treatment Treatment `json:"treatment"`
	Weight    int       `json:"weight"`
	Packets   int       `json:"packets"`
	Bytes     int       `json:"bytes"`
	BucketID  int       `json:"bucketId"`
}

type Treatment struct {
	Instructions []Instructions `json:"instructions"`
	Deferred     []interface{}  `json:"deferred"`
}

type Instructions struct {
	Type string `json:"type"`
	Port string `json:"port"`
}

type MeterList struct {
	Meters []Meters `json:"meters"`
}

type GroupList struct {
	Groups []*GroupsInfo `json:"groups"`
}

type SubscribersList struct {
	Subscribers []SubscriberInfo `json:"subscribers"`
}

type OltFlowServiceConfig struct {
	OltFlowService app.OltFlowService `json:"oltFlowService"`
}

type DeviceConfigPayload struct {
	DeviceConfig *app.DeviceConfig `json:"deviceConfig"`
}

func ConvertFlowToFlowEntry(subFlow *of.VoltSubFlow) FlowEntry {
	var flowEntry FlowEntry
	flowEntry.Flows = []Flow{}
	flow := ConvertVoltSubFlowToOnosFlow(subFlow)
	flowEntry.Flows = append(flowEntry.Flows, flow)
	return flowEntry
}

func ConvertFlowsToFlowEntry(subFlows []*of.VoltSubFlow) FlowEntry {
	var flowEntry FlowEntry
	flowEntry.Flows = []Flow{}
	for _, subFlow := range subFlows {
		flow := ConvertVoltSubFlowToOnosFlow(subFlow)
		flowEntry.Flows = append(flowEntry.Flows, flow)
	}
	return flowEntry
}

func FlowStateMapping(state uint8) string {
	var flowState string
	if state == of.FlowAddSuccess {
		flowState = Added
	} else if state == of.FlowAddFailure {
		flowState = FailedAdd
	} else if state == of.FlowAddPending {
		flowState = PendingAdd
	} else if state == of.FlowDelPending {
		flowState = PendingRemove
	}
	return flowState
}

func ConvertVoltSubFlowToOnosFlow(subFlow *of.VoltSubFlow) Flow {
	var flow Flow
	flow.ID = strconv.FormatUint(subFlow.Cookie, 10)
	flow.TableID = int(subFlow.TableID)
	flow.Priority = int(subFlow.Priority)
	state := FlowStateMapping(subFlow.State)
	flow.State = state
	// Fill Match criteria
	if subFlow.InPort != 0 {
		portSelector := PortSelector{
			Type: InPort,
			Port: int(subFlow.InPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(portSelector))
	}
	if subFlow.MatchVlan != of.VlanNone {
		vlanSelector := VlanSelector{
			Type:   VlanVID,
			VlanID: int(subFlow.MatchVlan),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(vlanSelector))
	}
	if subFlow.SrcMacMatch {
		ethSrcSelector := EthSrcSelector{
			Type:   EthSrc,
			EthSrc: subFlow.SrcMacAddr.String(),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethSrcSelector))
	}
	if subFlow.DstMacMatch {
		ethDstSelector := EthDstSelector{
			Type:   EthDst,
			DstSrc: subFlow.DstMacAddr.String(),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethDstSelector))
	}
	if subFlow.L3Protocol != of.EtherTypeAny {
		ethTypeSelector := EthTypeSelector{
			Type:    EthType,
			EthType: strconv.FormatUint(uint64(subFlow.L3Protocol), 16),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethTypeSelector))
	}
	if subFlow.L4Protocol != of.IPProtocolIgnore {
		protocolSelector := ProtocolSelector{
			Type:     IPProto,
			Protocol: int(subFlow.L4Protocol),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(protocolSelector))
	}
	if subFlow.SrcPort != 0 {
		udpPortSelector := UDPPortSelector{
			Type:    UDPSrc,
			UDPPort: int(subFlow.SrcPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(udpPortSelector))
	}
	if subFlow.DstPort != 0 {
		udpPortSelector := UDPPortSelector{
			Type:    UDPDst,
			UDPPort: int(subFlow.DstPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(udpPortSelector))
	}
	if subFlow.TableMetadata != 0 {
		metaDataSelector := MetaDataSelector{
			Type:     MetaData,
			Metadata: subFlow.TableMetadata,
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(metaDataSelector))
	}

	// Fill actions
	if subFlow.Output != 0 {
		portInstruction := PortInstruction{
			Type: Output,
		}
		switch subFlow.Output {
		case of.OutputTypeToController:
			portInstruction.Port = "CONTROLLER"
		case of.OutputTypeToNetwork:
			portInstruction.Port = strconv.FormatUint(uint64(subFlow.OutPort), 10)
		case of.OutputTypeGoToTable:
			portInstruction.Port = strconv.FormatUint(uint64(subFlow.GoToTableID), 10)
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(portInstruction))
	}
	if len(subFlow.PushVlan) != 0 {
		for _, vlan := range subFlow.PushVlan {
			if vlan == of.VlanNone {
				continue
			}
			pushVlanInstruction := PushVlanInstruction{
				Type:         L2Modification,
				SubType:      VlanPush,
				EthernetType: "0x8100",
			}
			flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(pushVlanInstruction))
			vlanInstruction := VlanInstruction{
				Type:    L2Modification,
				SubType: VlanID,
				VlanID:  int(vlan),
			}
			flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(vlanInstruction))
		}
	}
	if subFlow.SetVlan != of.VlanNone {
		vlanInstruction := VlanInstruction{
			Type:    L2Modification,
			SubType: VlanSet,
			VlanID:  int(subFlow.SetVlan),
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(vlanInstruction))
	}
	if subFlow.RemoveVlan != 0 {
		popVlanInstruction := PopVlanInstruction{
			Type:    L2Modification,
			SubType: VlanPop,
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(popVlanInstruction))
	}
	if subFlow.MeterID != 0 {
		meterInstruction := MeterInstruction{
			Type:    Meter,
			MeterID: strconv.FormatUint(uint64(subFlow.MeterID), 10),
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(meterInstruction))
	}
	return flow
}

func convertServiceToSubscriberInfo(svcs []*app.VoltService) []SubscriberInfo {
	subs := []SubscriberInfo{}
	for _, vs := range svcs {
		pbit := vs.GetServicePbit()
		sub := SubscriberInfo{
			Location: vs.Device,
			TagInfo: UniTagInformation{
				UniTagMatch:                   int(vs.UniVlan),
				PonCTag:                       int(vs.CVlan),
				PonSTag:                       int(vs.SVlan),
				UsPonCTagPriority:             pbit,
				UsPonSTagPriority:             pbit,
				DsPonCTagPriority:             pbit,
				DsPonSTagPriority:             pbit,
				TechnologyProfileID:           int(vs.TechProfileID),
				UpstreamBandwidthProfile:      vs.UsMeterProfile,
				DownstreamBandwidthProfile:    vs.DsMeterProfile,
				UpstreamOltBandwidthProfile:   vs.UsMeterProfile,
				DownstreamOltBandwidthProfile: vs.DsMeterProfile,
				ServiceName:                   vs.ServiceType,
				EnableMacLearning:             vs.MacLearning == app.Learn,
				ConfiguredMacAddress:          vs.MacAddr.String(),
				IsDhcpRequired:                vs.MacLearning == app.Learn,
				IsIgmpRequired:                vs.IgmpEnabled,
				IsPppoeRequired:               false,
			},
		}
		subs = append(subs, sub)
	}
	return subs
}

type DeviceEntry struct {
	Devices []Device `json:"devices"`
}

type Device struct {
	ID                      string            `json:"id"`
	Type                    string            `json:"type"`
	Role                    string            `json:"role"`
	Mfr                     string            `json:"mfr"`
	Hw                      string            `json:"hw"`
	Sw                      string            `json:"sw"`
	Serial                  string            `json:"serial"`
	Driver                  string            `json:"driver"`
	ChassisID               string            `json:"chassisId"`
	LastUpdate              string            `json:"lastUpdate"`
	HumanReadableLastUpdate string            `json:"humanReadableLastUpdate"`
	Annotations             DeviceAnnotations `json:"annotations"`
	Available               bool              `json:"available"`
}
type DeviceAnnotations struct {
	ChannelID         string `json:"channelId"`
	ManagementAddress string `json:"managementAddress"`
	Protocol          string `json:"protocol"`
}

func convertVoltDeviceToDevice(voltDevice *app.VoltDevice) Device {
	var device Device

	d, err := controller.GetController().GetDevice(voltDevice.Name)
	if err != nil {
		device.ID = voltDevice.Name
		return device
	}
	device.ID = d.ID
	if d.State == controller.DeviceStateUP {
		device.Available = true
	} else {
		device.Available = false
	}
	device.Serial = d.SerialNum
	device.Mfr = d.MfrDesc
	device.Hw = d.HwDesc
	device.Sw = d.SwDesc
	device.LastUpdate = d.TimeStamp.String()
	device.HumanReadableLastUpdate = d.TimeStamp.String()
	return device
}

type PortEntry struct {
	Ports []Port `json:"ports"`
}

type DevicePortEntry struct {
	Device Device `json:"device"`
	Ports  []Port `json:"ports"`
}

type Port struct {
	Element     string          `json:"element"`
	Port        string          `json:"port"`
	Type        string          `json:"type"`
	Annotations PortAnnotations `json:"annotations"`
	PortSpeed   int             `json:"portSpeed"`
	IsEnabled   bool            `json:"isEnabled"`
}
type PortAnnotations struct {
	AdminState string `json:"adminState"`
	PortMac    string `json:"portMac"`
	PortName   string `json:"portName"`
}

func convertVoltPortToPort(voltPort *app.VoltPort) Port {
	var port Port
	port.Port = strconv.Itoa(int(voltPort.ID))
	port.Element = voltPort.Device
	if voltPort.State == app.PortStateUp {
		port.IsEnabled = true
	} else {
		port.IsEnabled = false
	}
	if voltPort.Type == app.VoltPortTypeNni {
		port.Type = "fiber"
	} else {
		port.Type = "copper"
	}
	port.Annotations.AdminState = "enabled"
	port.Annotations.PortName = voltPort.Name

	device, err := controller.GetController().GetDevice(voltPort.Device)
	if err != nil {
		return port
	}

	devicePort := device.GetPortByName(voltPort.Name)
	if devicePort != nil {
		port.PortSpeed = int(devicePort.MaxSpeed)
		port.Annotations.PortMac = devicePort.HwAddr
	}
	return port
}
func (gh *GroupsHandle) convertGroupsToOnosGroup(groupsInfo *of.Group) *GroupsInfo {
	logger.Debug(ctx, "Entering into convertGroupsToOnosGroup")
	var groups *GroupsInfo
	var bucket []Bucket
	Instruction := []Instructions{}
	if groupsInfo != nil {
		for _, buckets := range groupsInfo.Buckets {
			inst := Instructions{
				Type: All,
				Port: fmt.Sprint(buckets),
			}
			Instruction = append(Instruction, inst)
			trtmt := Treatment{
				Instructions: Instruction,
			}
			bkt := Bucket{
				Type:      All,
				Treatment: trtmt,
			}
			bucket = append(bucket, bkt)
		}
		if groupsInfo.State == of.GroupOperSuccess {
			groups.State = Added
		} else if groupsInfo.State == of.GroupOperFailure {
			groups.State = Failed
		} else if groupsInfo.State == of.GroupOperPending {
			groups.State = Pending
		}
		groups = &GroupsInfo{
			DeviceID: groupsInfo.Device,
			ID:       int(groupsInfo.GroupID),
			State:    groups.State,
			Type:     All,
			Buckets:  bucket,
		}
	}
	return groups
}

func (mh *MetersHandle) MeterObjectMapping(meterInfo *of.Meter, deviceID string) Meters {
	var meter Meters
	var bd []Bands
	for _, band := range meterInfo.Bands {
		bnd := Bands{
			Type:      fmt.Sprint(band.Type),
			Rate:      int(band.Rate),
			BurstSize: int(band.BurstSize),
		}
		bd = append(bd, bnd)
	}
	if meterInfo.State == of.MeterOperSuccess {
		meter.State = Added
	} else if meterInfo.State == of.MeterOperFailure {
		meter.State = Failed
	} else if meterInfo.State == of.MeterOperPending {
		meter.State = Pending
	}
	meter = Meters{
		ID:         fmt.Sprint(meterInfo.ID),
		State:      meter.State,
		DeviceID:   deviceID,
		MeterBands: bd,
	}
	return meter
}
