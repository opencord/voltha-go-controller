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
	"strconv"
	"voltha-go-controller/internal/pkg/of"
)

const (
        /** Switch input port. */
        IN_PORT string = "IN_PORT"

        /** Switch physical input port. */
        IN_PHY_PORT

        /** Metadata passed between tables. */
        METADATA string = "METADATA"

        /** Ethernet destination address. */
        ETH_DST string = "ETH_DST"

        /** Ethernet destination address with masking. */
        ETH_DST_MASKED

        /** Ethernet source address. */
        ETH_SRC string = "ETH_SRC"

        /** Ethernet source address with masking. */
        ETH_SRC_MASKED

        /** Ethernet frame type. */
        ETH_TYPE string = "ETH_TYPE"

        /** VLAN id. */
        VLAN_VID string = "VLAN_VID"

        /** VLAN priority. */
        VLAN_PCP
        /**
         * Inner VLAN id.
         *
         * Note: Some drivers may not support this.
         */
        INNER_VLAN_VID

        /**
         * Inner VLAN pcp.
         *
         * Note: Some drivers may not support this.
         */
        INNER_VLAN_PCP

        /** IP DSCP (6 bits in ToS field). */
        IP_DSCP

        /** IP ECN (2 bits in ToS field). */
        IP_ECN

        /** IP protocol. */
        IP_PROTO string = "IP_PROTO"

        /** IPv4 source address. */
        IPV4_SRC

        /** IPv4 destination address. */
        IPV4_DST

        /** TCP source port. */
        TCP_SRC

        /** TCP source port with masking. */
        TCP_SRC_MASKED

        /** TCP destination port. */
        TCP_DST

        /** TCP destination port with masking. */
        TCP_DST_MASKED

        /** UDP source port. */
        UDP_SRC string = "UDP_SRC"

        /** UDP source port with masking. */
        UDP_SRC_MASKED

        /** UDP destination port. */
        UDP_DST string = "UDP_DST"

        /** UDP destination port with masking. */
        UDP_DST_MASKED

        /** SCTP source port. */
        SCTP_SRC

        /** SCTP source port with masking. */
        SCTP_SRC_MASKED

        /** SCTP destination port. */
        SCTP_DST

        /** SCTP destination port with masking. */
        SCTP_DST_MASKED

        /** ICMP type. */
        ICMPV4_TYPE

        /** ICMP code. */
        ICMPV4_CODE

        /** ARP opcode. */
        ARP_OP

        /** ARP source IPv4 address. */
        ARP_SPA

        /** ARP target IPv4 address. */
        ARP_TPA

        /** ARP source hardware address. */
        ARP_THA

        /** IPv6 source address. */
        IPV6_SRC

        /** IPv6 destination address. */
        IPV6_DST

        /** IPv6 Flow Label. */
        IPV6_FLABEL

        /** ICMPv6 type. */
        ICMPV6_TYPE

        /** ICMPv6 code. */
        ICMPV6_CODE

        /** Target address for ND. */
        IPV6_ND_TARGET

        /** Source link-layer for ND. */
        IPV6_ND_SLL

        /** Target link-layer for ND. */
        IPV6_ND_TLL

        /** MPLS label. */
        MPLS_LABEL

        /** MPLS TC. */
        MPLS_TC

        /**  MPLS BoS bit. */
        MPLS_BOS

        /** PBB I-SID. */
        PBB_ISID

        /** Logical Port Metadata. */
        TUNNEL_ID

        /** IPv6 Extension Header pseudo-field. */
        IPV6_EXTHDR

        /** Unassigned value: 40. */
        UNASSIGNED_40

        /** PBB UCA header field. */
        PBB_UCA

        /** TCP flags. */
        TCP_FLAGS

        /** Output port from action set metadata. */
        ACTSET_OUTPUT

        /** Packet type value. */
        PACKET_TYPE

        //
        // NOTE: Everything below is defined elsewhere: ONOS-specific,
        // extensions, etc.
        //
        /** Optical channel signal ID (lambda). */
        OCH_SIGID

        /** Optical channel signal type (fixed or flexible). */
        OCH_SIGTYPE

        /** ODU (Optical channel Data Unit) signal ID. */
        ODU_SIGID

        /** ODU (Optical channel Data Unit) signal type. */
        ODU_SIGTYPE

        /** Protocol-independent. */
        PROTOCOL_INDEPENDENT

        /** Extension criterion. */
        EXTENSION

        /** An empty criterion. */
        DUMMY

	/* OUTPUT instruction */
	OUTPUT string = "OUTPUT"

	METER string = "METER"

	L2MODIFICATION string = "L2MODIFICATION"

	VLAN_PUSH string = "VLAN_PUSH"

	VLAN_ID string = "VLAN_ID"

	VLAN_POP string = "VLAN_POP"

	VLAN_SET string = "VLAN_SET"
)

// Selector Critrtion structs
type Criterion interface{
	GetType() string
}

type PortSelector struct {
	Type     string `json:"type"`
	Port     int    `json:"port,omitempty"`
}

func (s PortSelector) GetType() string {
	return s.Type
}
type EthTypeSelector struct {
	Type     string `json:"type"`
	EthType  string `json:"ethType,omitempty"`
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
	Type     string `json:"type"`
	UDPPort  int    `json:"udpPort,omitempty"`
}
func (s UDPPortSelector) GetType() string {
	return s.Type
}

type VlanSelector struct {
	Type     string `json:"type"`
	VlanID   int    `json:"vlanId,omitempty"`
}
func (s VlanSelector) GetType() string {
	return s.Type
}

type EthSrcSelector struct {
	Type     string `json:"type"`
	EthSrc   string `json:"ethsrc,omitempty"`
}

func (s EthSrcSelector) GetType() string {
	return s.Type
}

type EthDstSelector struct {
	Type     string `json:"type"`
	DstSrc   string `json:"ethdst,omitempty"`
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
	Criteria []Criterion  `json:"criteria"`
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
	Type string `json:"type"`
	SubType string `json:"subtype"`
	EthernetType string `json:"ethernetType"`
}

func (i PushVlanInstruction) GetInstructionType() string {
	return i.Type
}

type VlanInstruction struct {
	Type string `json:"type"`
	SubType string `json:"subtype"`
	VlanID int `json:"vlanId"`
}

func (i VlanInstruction) GetInstructionType() string {
	return i.Type
}

type PopVlanInstruction struct {
	Type string `json:"type"`
	SubType string `json:"subtype"`
}

func (i PopVlanInstruction) GetInstructionType() string {
	return i.Type
}

type MeterInstruction struct {
	Type string `json:"type"`
	MeterID string `json:"meterId"`
}

func (i MeterInstruction) GetInstructionType() string {
	return i.Type
}

type TreatmentInfo struct {
	Instructions []Instruction `json:"instructions"`
	Deferred []interface{} `json:"deferred"`
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

func ConvertFlowToFlowEntry (subFlow *of.VoltSubFlow) FlowEntry {
	var flowEntry FlowEntry
	flow := ConvertVoltSubFlowToOnosFlow(subFlow)
	flowEntry.Flows = append(flowEntry.Flows, flow)
	return flowEntry
}

func ConvertFlowsToFlowEntry (subFlows []*of.VoltSubFlow) FlowEntry {
	var flowEntry FlowEntry
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
		portSelector := PortSelector {
			Type: IN_PORT,
			Port: int(subFlow.InPort),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(portSelector))
	}
	if subFlow.MatchVlan != of.VlanNone {
		vlanSelector := VlanSelector {
			Type: VLAN_VID,
			VlanID: int(subFlow.MatchVlan),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(vlanSelector))
	}
	if subFlow.SrcMacMatch {
		ethSrcSelector := EthSrcSelector {
			Type: ETH_SRC,
			EthSrc: subFlow.SrcMacAddr.String(),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethSrcSelector))
	}
	if subFlow.DstMacMatch {
		ethDstSelector := EthDstSelector {
			Type: ETH_DST,
			DstSrc: subFlow.DstMacAddr.String(),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethDstSelector))
	}
	if subFlow.L3Protocol != of.EtherTypeAny {
		ethTypeSelector := EthTypeSelector {
			Type: ETH_TYPE,
			EthType : strconv.FormatUint(uint64(subFlow.L3Protocol), 16) ,
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(ethTypeSelector))
	}
	if subFlow.L4Protocol != of.IPProtocolIgnore {
		protocolSelector := ProtocolSelector {
			Type: IP_PROTO,
			Protocol : int(subFlow.L4Protocol),
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(protocolSelector))
	}
	if subFlow.SrcPort != 0 {
		udpPortSelector := UDPPortSelector {
			Type: UDP_SRC,
			UDPPort : int(subFlow.SrcPort) ,
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(udpPortSelector))
	}
	if subFlow.DstPort != 0 {
		udpPortSelector := UDPPortSelector {
			Type: UDP_DST,
			UDPPort : int(subFlow.DstPort) ,
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(udpPortSelector))
	}
	if subFlow.TableMetadata != 0 {
		metaDataSelector := MetaDataSelector {
			Type: METADATA,
			Metadata : subFlow.TableMetadata,
		}
		flow.Selector.Criteria = append(flow.Selector.Criteria, Criterion(metaDataSelector))
	}

	// Fill actions
	if subFlow.Output != 0 {
		portInstruction := PortInstruction {
			Type: OUTPUT,
		}
		switch subFlow.Output {
		case of.OutputTypeToController:
			portInstruction.Port = "CONTROLLER"
		case of.OutputTypeToNetwork:
			portInstruction.Port = strconv.FormatUint(uint64(subFlow.OutPort) , 10)
		case of.OutputTypeGoToTable:
			portInstruction.Port = strconv.FormatUint(uint64(subFlow.GoToTableID) , 10)
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(portInstruction))
	}
	if len(subFlow.PushVlan) != 0 {
		for _, vlan := range subFlow.PushVlan {
			if vlan == of.VlanNone {
				continue
			}
			pushVlanInstruction := PushVlanInstruction {
				Type: L2MODIFICATION,
				SubType: VLAN_PUSH,
				EthernetType: "0x8100" ,
			}
			flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(pushVlanInstruction))
			vlanInstruction := VlanInstruction {
				Type: L2MODIFICATION,
				SubType: VLAN_ID,
				VlanID: int(vlan),
			}
			flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(vlanInstruction))
		}
	}
	if subFlow.SetVlan != of.VlanNone {
		vlanInstruction := VlanInstruction {
			Type: L2MODIFICATION,
			SubType: VLAN_SET,
			VlanID: int(subFlow.SetVlan) ,
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(vlanInstruction))
	}
	if subFlow.RemoveVlan != 0 {
		popVlanInstruction := PopVlanInstruction {
			Type: L2MODIFICATION,
			SubType: VLAN_POP,
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(popVlanInstruction))
	}
	if subFlow.MeterID != 0 {
		meterInstruction := MeterInstruction {
			Type: METER,
			MeterID: strconv.FormatUint(uint64(subFlow.MeterID), 10),
		}
		flow.Treatment.Instructions = append(flow.Treatment.Instructions, Instruction(meterInstruction))
	}
	return flow
}
