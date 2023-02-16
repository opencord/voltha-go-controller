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

package onos_nbi

import (
	"fmt"
	"strconv"
	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/controller"

	"voltha-go-controller/internal/pkg/of"
)

const (
	/** Switch input port. */
	IN_PORT string = "IN_PORT"

	/** Switch physical input port. */
	IN_PHY_PORT string = "IN_PHY_PORT"

	/** Metadata passed between tables. */
	METADATA string = "METADATA"

	/** Ethernet destination address. */
	ETH_DST string = "ETH_DST"

	/** Ethernet destination address with masking. */
	ETH_DST_MASKED = "ETH_DST_MASKED"

	/** Ethernet source address. */
	ETH_SRC string = "ETH_SRC"

	/** Ethernet source address with masking. */
	ETH_SRC_MASKED string = "ETH_SRC_MASKED"

	/** Ethernet frame type. */
	ETH_TYPE string = "ETH_TYPE"

	/** VLAN id. */
	VLAN_VID string = "VLAN_VID"

	/** VLAN priority. */
	VLAN_PCP string = "VLAN_PCP"
	/**
	 * Inner VLAN id.
	 *
	 * Note: Some drivers may not support this.
	 */
	INNER_VLAN_VID string = "INNER_VLAN_VID"

	/**
	 * Inner VLAN pcp.
	 *
	 * Note: Some drivers may not support this.
	 */
	INNER_VLAN_PCP string = "INNER_VLAN_PCP"

	/** IP DSCP (6 bits in ToS field). */
	IP_DSCP string = "IP_DSCP"

	/** IP ECN (2 bits in ToS field). */
	IP_ECN string = "IP_ECN"

	/** IP protocol. */
	IP_PROTO string = "IP_PROTO"

	/** IPv4 source address. */
	IPV4_SRC string = "IPV4_SRC"

	/** IPv4 destination address. */
	IPV4_DST string = "IPV4_DST"

	/** TCP source port. */
	TCP_SRC string = "TCP_SRC"

	/** TCP source port with masking. */
	TCP_SRC_MASKED string = "TCP_SRC_MASKED"

	/** TCP destination port. */
	TCP_DST string = "TCP_DST"

	/** TCP destination port with masking. */
	TCP_DST_MASKED string = "TCP_DST"

	/** UDP source port. */
	UDP_SRC string = "UDP_SRC"

	/** UDP source port with masking. */
	UDP_SRC_MASKED string = "UDP_SRC_MASKED"

	/** UDP destination port. */
	UDP_DST string = "UDP_DST"

	/** UDP destination port with masking. */
	UDP_DST_MASKED string = "UDP_DST_MASKED"

	/** SCTP source port. */
	SCTP_SRC string = "SCTP_SRC"

	/** SCTP source port with masking. */
	SCTP_SRC_MASKED string = "SCTP_SRC_MASKED"

	/** SCTP destination port. */
	SCTP_DST string = "SCTP_DST"

	/** SCTP destination port with masking. */
	SCTP_DST_MASKED string = "SCTP_DST_MASKED"

	/** ICMP type. */
	ICMPV4_TYPE string = "ICMPV4_TYPE"

	/** ICMP code. */
	ICMPV4_CODE string = "ICMPV4_CODE"

	/** ARP opcode. */
	ARP_OP string = "ARP_OP"

	/** ARP source IPv4 address. */
	ARP_SPA string = "ARP_SPA"

	/** ARP target IPv4 address. */
	ARP_TPA string = "ARP_TPA"

	/** ARP source hardware address. */
	ARP_THA string = "ARP_THA"

	/** IPv6 source address. */
	IPV6_SRC string = "IPV6_SRC"

	/** IPv6 destination address. */
	IPV6_DST string = "IPV6_DST"

	/** IPv6 Flow Label. */
	IPV6_FLABEL string = "IPV6_FLABEL"

	/** ICMPv6 type. */
	ICMPV6_TYPE string = "ICMPV6_TYPE"

	/** ICMPv6 code. */
	ICMPV6_CODE string = "ICMPV6_CODE"

	/** Target address for ND. */
	IPV6_ND_TARGET string = "IPV6_ND_TARGET"

	/** Source link-layer for ND. */
	IPV6_ND_SLL string = "IPV6_ND_SLL"

	/** Target link-layer for ND. */
	IPV6_ND_TLL string = "IPV6_ND_TLL"

	/** MPLS label. */
	MPLS_LABEL string = "MPLS_LABEL"

	/** MPLS TC. */
	MPLS_TC string = "MPLS_TC"

	/**  MPLS BoS bit. */
	MPLS_BOS string = "MPLS_BOS"

	/** PBB I-SID. */
	PBB_ISID string = "PBB_ISID"

	/** Logical Port Metadata. */
	TUNNEL_ID string = "TUNNEL_ID"

	/** IPv6 Extension Header pseudo-field. */
	IPV6_EXTHDR string = "IPV6_EXTHDR"

	/** Unassigned value: 40. */
	UNASSIGNED_40 string = "UNASSIGNED_40"

	/** PBB UCA header field. */
	PBB_UCA string = "PBB_UCA"

	/** TCP flags. */
	TCP_FLAGS string = "TCP_FLAGS"

	/** Output port from action set metadata. */
	ACTSET_OUTPUT string = "ACTSET_OUTPUT"

	/** Packet type value. */
	PACKET_TYPE string = "PACKET_TYPE"

	//
	// NOTE: Everything below is defined elsewhere: ONOS-specific,
	// extensions, etc.
	//
	/** Optical channel signal ID (lambda). */
	OCH_SIGID string = "OCH_SIGID"

	/** Optical channel signal type (fixed or flexible). */
	OCH_SIGTYPE string = "OCH_SIGTYPE"

	/** ODU (Optical channel Data Unit) signal ID. */
	ODU_SIGID string = "ODU_SIGID"

	/** ODU (Optical channel Data Unit) signal type. */
	ODU_SIGTYPE string = "ODU_SIGTYPE"

	/** Protocol-independent. */
	PROTOCOL_INDEPENDENT string = "PROTOCOL_INDEPENDENT"

	/** Extension criterion. */
	EXTENSION string = "EXTENSION"

	/** An empty criterion. */
	DUMMY string = "DUMMY"

	/* OUTPUT instruction */
	OUTPUT string = "OUTPUT"

	/* METER instruction */
	METER string = "METER"

	/* L2MODIFICATION instruction type */
	L2MODIFICATION string = "L2MODIFICATION"

	/* VLAN_PUSH operation */
	VLAN_PUSH string = "VLAN_PUSH"

	/* VLAN_ID instruction */
	VLAN_ID string = "VLAN_ID"

	/* VLAN_POP operation */
	VLAN_POP string = "VLAN_POP"

	/* VLAN_SET operation */
	VLAN_SET string = "VLAN_SET"

	ALL string = "ALL"

	ADDED string = "ADDED"

	FAILED string = "FAILED"

	PENDING string = "PENDING"
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
	GroupID     int           `json:"groupId"`
	State       string        `json:"state"`
	Life        int           `json:"life"`
	LiveType    string        `json:"liveType"`
	LastSeen    int64         `json:"lastSeen"`
	Packets     int           `json:"packets"`
	Bytes       int           `json:"bytes"`
	ID          string        `json:"id"`
	AppID       string        `json:"appId"`
	Priority    int           `json:"priority"`
	Timeout     int           `json:"timeout"`
	IsPermanent bool          `json:"isPermanent"`
	DeviceID    string        `json:"deviceId"`
	TableID     int           `json:"tableId"`
	TableName   string        `json:"tableName"`
	Treatment   TreatmentInfo `json:"treatment"`
	Selector    SelectorInfo  `json:"selector"`
}

type FlowEntry struct {
	Flows []Flow `json:"flows"`
}

//Meter struct
type Meters struct {
	ID             string  `json:"id"`
	Life           int     `json:"life"`
	Packets        int     `json:"packets"`
	Bytes          int     `json:"bytes"`
	ReferenceCount int     `json:"referenceCount"`
	Unit           string  `json:"unit"`
	Burst          bool    `json:"burst"`
	DeviceID       string  `json:"deviceId"`
	AppID          string  `json:"appId"`
	State          string  `json:"state"`
	MeterBands     []Bands `json:"bands"`
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
	ID             int      `json:"id"`
	State          string   `json:"state"`
	Life           int      `json:"life"`
	Packets        int      `json:"packets"`
	Bytes          int      `json:"bytes"`
	ReferenceCount int      `json:"referenceCount"`
	Type           string   `json:"type"`
	DeviceID       string   `json:"deviceId"`
	AppID          string   `json:"appId"`
	AppCookie      string   `json:"appCookie"`
	Buckets        []Bucket `json:"buckets"`
}

type Bucket struct {
	Type      string    `json:"type"`
	Weight    int       `json:"weight"`
	Packets   int       `json:"packets"`
	Bytes     int       `json:"bytes"`
	BucketID  int       `json:"bucketId"`
	Treatment Treatment `json:"treatment"`
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

func ConvertVoltSubFlowToOnosFlow(subFlow *of.VoltSubFlow) Flow {
	var flow Flow
	flow.ID = strconv.FormatUint(subFlow.Cookie, 10)
	flow.TableID = int(subFlow.TableID)
	flow.Priority = int(subFlow.Priority)
	//flow.State = subFlow.State

	// Fill Match criteria
	if subFlow.InPort != 0 {
		portSelector := PortSelector{
			Type: IN_PORT,
			Port: int(subFlow.InPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(portSelector))
	}
	if subFlow.MatchVlan != of.VlanNone {
		vlanSelector := VlanSelector{
			Type:   VLAN_VID,
			VlanID: int(subFlow.MatchVlan),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(vlanSelector))
	}
	if subFlow.SrcMacMatch {
		ethSrcSelector := EthSrcSelector{
			Type:   ETH_SRC,
			EthSrc: subFlow.SrcMacAddr.String(),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethSrcSelector))
	}
	if subFlow.DstMacMatch {
		ethDstSelector := EthDstSelector{
			Type:   ETH_DST,
			DstSrc: subFlow.DstMacAddr.String(),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethDstSelector))
	}
	if subFlow.L3Protocol != of.EtherTypeAny {
		ethTypeSelector := EthTypeSelector{
			Type:    ETH_TYPE,
			EthType: strconv.FormatUint(uint64(subFlow.L3Protocol), 16),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethTypeSelector))
	}
	if subFlow.L4Protocol != of.IPProtocolIgnore {
		protocolSelector := ProtocolSelector{
			Type:     IP_PROTO,
			Protocol: int(subFlow.L4Protocol),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(protocolSelector))
	}
	if subFlow.SrcPort != 0 {
		udpPortSelector := UDPPortSelector{
			Type:    UDP_SRC,
			UDPPort: int(subFlow.SrcPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(udpPortSelector))
	}
	if subFlow.DstPort != 0 {
		udpPortSelector := UDPPortSelector{
			Type:    UDP_DST,
			UDPPort: int(subFlow.DstPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(udpPortSelector))
	}
	if subFlow.TableMetadata != 0 {
		metaDataSelector := MetaDataSelector{
			Type:     METADATA,
			Metadata: subFlow.TableMetadata,
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(metaDataSelector))
	}

	// Fill actions
	if subFlow.Output != 0 {
		portInstruction := PortInstruction{
			Type: OUTPUT,
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
				Type:         L2MODIFICATION,
				SubType:      VLAN_PUSH,
				EthernetType: "0x8100",
			}
			flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(pushVlanInstruction))
			vlanInstruction := VlanInstruction{
				Type:    L2MODIFICATION,
				SubType: VLAN_ID,
				VlanID:  int(vlan),
			}
			flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(vlanInstruction))
		}
	}
	if subFlow.SetVlan != of.VlanNone {
		vlanInstruction := VlanInstruction{
			Type:    L2MODIFICATION,
			SubType: VLAN_SET,
			VlanID:  int(subFlow.SetVlan),
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(vlanInstruction))
	}
	if subFlow.RemoveVlan != 0 {
		popVlanInstruction := PopVlanInstruction{
			Type:    L2MODIFICATION,
			SubType: VLAN_POP,
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(popVlanInstruction))
	}
	if subFlow.MeterID != 0 {
		meterInstruction := MeterInstruction{
			Type:    METER,
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
				ServiceName:                   vs.Name,
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
	Available               bool              `json:"available"`
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
}
type DeviceAnnotations struct {
	ChannelID         string `json:"channelId"`
	ManagementAddress string `json:"managementAddress"`
	Protocol          string `json:"protocol"`
}

type OltFlowServiceConfig struct {
	OltFlowService app.OltFlowService `json:"org.opencord.olt.impl.OltFlowService"`
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

type Port struct {
	Element     string          `json:"element"`
	Port        string          `json:"port"`
	IsEnabled   bool            `json:"isEnabled"`
	Type        string          `json:"type"`
	PortSpeed   int             `json:"portSpeed"`
	Annotations PortAnnotations `json:"annotations"`
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
	logger.Info(ctx, "Entering into convertGroupsToOnosGroup")
	var groups *GroupsInfo
	var bucket []Bucket
	Instruction := []Instructions{}
	if groupsInfo != nil {
		for _, buckets := range groupsInfo.Buckets {
			inst := Instructions{
				Type: ALL,
				Port: fmt.Sprint(buckets),
			}
			Instruction = append(Instruction, inst)
			trtmt := Treatment{
				Instructions: Instruction,
			}
			bkt := Bucket{
				Type:      ALL,
				Treatment: trtmt,
			}
			bucket = append(bucket, bkt)
		}
		if groupsInfo.State == of.GroupOperSuccess {
			groups.State = ADDED
		} else if groupsInfo.State == of.GroupOperFailure {
			groups.State = FAILED
		} else if groupsInfo.State == of.GroupOperPending {
			groups.State = PENDING
		}
		groups = &GroupsInfo{
			DeviceID: groupsInfo.Device,
			ID:       int(groupsInfo.GroupID),
			State:    groups.State,
			Type:     ALL,
			Buckets:  bucket,
		}
	}
	return groups
}

func (mh *MetersHandle) MeterObjectMapping(meterInfo *of.Meter, deviceId string) Meters {
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
		meter.State = ADDED
	} else if meterInfo.State == of.MeterOperFailure {
		meter.State = FAILED
	} else if meterInfo.State == of.MeterOperPending {
		meter.State = PENDING
	}
	meter = Meters{
		ID:         fmt.Sprint(meterInfo.ID),
		State:      meter.State,
		DeviceID:   deviceId,
		MeterBands: bd,
	}
	return meter

}
