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

package of

import (
	"context"
	"net"
	"strconv"

	"github.com/google/gopacket/layers"

	"voltha-go-controller/log"

	"github.com/opencord/voltha-lib-go/v7/pkg/flows"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	//"github.com/opencord/voltha-protos/v5/go/voltha"
)

// PbitType type
type PbitType uint8

// TODO: Port related constants - OF specifies a different value
// for controller. Need to make sure this is correct
const (
	ControllerPort uint32   = 0xfffffffd
	PbitMatchNone  PbitType = 8
	PbitMatchAll   PbitType = 0xFF
)

var logger log.CLogger
var ctx = context.TODO()

// ----------------------------------------------------------
// Cookie related specifications and utilities
// ----------------------------------------------------------
// Though the openflow does not utilize cookies as unique identities of
// flows, we use cookies as identities in the application. The same
// may also be used in the VOLTHA if so desired to reduce the complexity
// of management of flows. In terms of how the cookie is set and is
// ensured to be unique is:
// Cookie is a 64 bit value. The first 32 bits are set to the port-id
// All rules set at the device level are associated with NNI. All other
// flows, both ingress and egress are associated with the access port.
// The last 32 bits are used to uniquely identifies flows of a port.
const (
	// The flow masks are used to set the MSB of the lower
	// 32 bits of cookie

	// UsFlowMask constant
	UsFlowMask uint64 = 0x8000
	// DsFlowMask constant
	DsFlowMask uint64 = 0x0000

	// Flow types used to divide the available cookie value range
	// Each type is allocated 256 flow identities which are plenty
	// for the known use cases.

	// DhcpArpFlowMask constant
	DhcpArpFlowMask uint64 = 0x0100
	// PppoeFlowMask constant
	PppoeFlowMask uint64 = 0x0100
	// HsiaFlowMask constant
	HsiaFlowMask uint64 = 0x0200
	// DsArpFlowMask constant
	DsArpFlowMask uint64 = 0x0300
	// IgmpFlowMask constant
	IgmpFlowMask uint64 = 0x0400
	// Dhcpv6FlowMask constant
	Dhcpv6FlowMask uint64 = 0x0800

	// Flow priorities - Higher the value, higher the priority

	// DhcpFlowPriority constant
	DhcpFlowPriority uint32 = 5000
	// ArpFlowPriority constant
	ArpFlowPriority uint32 = 5000
	// IgmpFlowPriority constant
	IgmpFlowPriority uint32 = 5000
	// McFlowPriority constant
	McFlowPriority uint32 = 5000
	// PppoeFlowPriority constant
	PppoeFlowPriority uint32 = 5000
	// HsiaFlowPriority constant
	HsiaFlowPriority uint32 = 100
)

// CookieSetPort to set port
func CookieSetPort(cookie uint64, port uint32) uint64 {
	return cookie | (uint64(port) << 32)
}

// CookieGetPort to get port
func CookieGetPort(cookie uint64) uint32 {
	return uint32(cookie >> 32)
}

// -------------------------------------------------------
// The flow match and action related definitions follow
// -------------------------------------------------------
// The Ethernet types listed below serve our requirement. We may extend
// the list as we identify more use cases to be supported.

// EtherType type
type EtherType uint16

const (
	// EtherTypeAny constant
	EtherTypeAny EtherType = 0x0000 // Needs assertion
	// EtherTypeIpv4 constant
	EtherTypeIpv4 EtherType = 0x0800
	// EtherTypeIpv6 constant
	EtherTypeIpv6 EtherType = 0x86DD
	// EtherTypePppoeDiscovery constant
	EtherTypePppoeDiscovery EtherType = 0x8863
	// EtherTypePppoeSession constant
	EtherTypePppoeSession EtherType = 0x8864
	// EtherTypeArp constant
	EtherTypeArp EtherType = 0x0806
)

// VLAN related definitions
// VLANs can take a value between 1 and 4095. VLAN 0 is used to set just
// the PCP bytes. VLAN 4097 is being used to represent "no VLAN"
// 4096 is being used to represent "any vlan"

// VlanType type
type VlanType uint16

const (
	// VlanAny constant
	VlanAny VlanType = 0x1000
	// VlanNone constant
	VlanNone VlanType = 0x1001
)

func (vlan *VlanType) String() string {
	return strconv.Itoa(int(*vlan))
}

// IP Protocol defintions
// IP protocol 0xff is reserved and we are using the reserved value to
// represent that match is not needed.

// IPProtocol type
type IPProtocol uint8

const (
	// IPProtocolIgnore constant
	IPProtocolIgnore IPProtocol = 0xff
	// IPProtocolTCP constant
	IPProtocolTCP IPProtocol = 0x06
	// IPProtocolUDP constant
	IPProtocolUDP IPProtocol = 0x11
	// IPProtocolIgmp constant
	IPProtocolIgmp IPProtocol = 0x02
	// IPProtocolIcmpv6 constant
	IPProtocolIcmpv6 IPProtocol = 0x3A
)

// The following structure is included in each flow which further is
// used to create a flow. The match structure is used to specify the
// match rules encoded into the flow.

// Match structure
type Match struct {
	SrcMacAddr    net.HardwareAddr
	SrcMacMask    net.HardwareAddr
	DstMacAddr    net.HardwareAddr
	DstMacMask    net.HardwareAddr
	SrcIpv4Addr   net.IP
	DstIpv4Addr   net.IP
	TableMetadata uint64
	InPort        uint32
	MatchVlan     VlanType
	Pbits         PbitType
	L3Protocol    EtherType
	SrcPort       uint16
	DstPort       uint16
	L4Protocol    IPProtocol
	DstIpv4Match  bool
	SrcIpv4Match  bool
	SrcMacMatch   bool
	DstMacMatch   bool
	MatchPbits    bool
}

// Reset to be used when a Match is created. It sets the values to
// defaults which results is no match rules at all and thus when
// applied on a port, match all packets. The match rules must be
// set before use.
func (m *Match) Reset() {
	m.MatchVlan = VlanNone
	m.SrcMacMatch = false
	m.DstMacMatch = false
	m.MatchPbits = false
	m.L3Protocol = EtherTypeAny
	m.L4Protocol = IPProtocolIgnore
	m.SrcPort = 0
	m.DstPort = 0
	m.TableMetadata = 0
}

// SetInPort to set in port
func (m *Match) SetInPort(port uint32) {
	m.InPort = port
}

// SetMatchVlan to set match vlan
func (m *Match) SetMatchVlan(vlan VlanType) {
	m.MatchVlan = vlan
}

// SetPppoeDiscoveryMatch to set L3 protocol
func (m *Match) SetPppoeDiscoveryMatch() {
	m.L3Protocol = EtherTypePppoeDiscovery
}

// SetTableMetadata to set table metadata
func (m *Match) SetTableMetadata(metadata uint64) {
	m.TableMetadata = metadata
}

// SetMatchSrcMac to set source mac address
func (m *Match) SetMatchSrcMac(mac net.HardwareAddr) {
	m.SrcMacMatch = true
	m.SrcMacAddr = mac
}

// SetMatchDstMac to set destination mac address
func (m *Match) SetMatchDstMac(mac net.HardwareAddr) {
	m.DstMacMatch = true
	m.DstMacAddr = mac
}

// SetMatchPbit to set pbits
func (m *Match) SetMatchPbit(pbit PbitType) {
	m.MatchPbits = true
	m.Pbits = pbit
}

// SetMatchSrcIpv4 to set source ipv4 address
func (m *Match) SetMatchSrcIpv4(ip net.IP) {
	m.SrcIpv4Match = true
	m.SrcIpv4Addr = ip
}

// SetMatchDstIpv4 to set destination ipv4 address
func (m *Match) SetMatchDstIpv4(ip net.IP) {
	m.DstIpv4Match = true
	m.DstIpv4Addr = ip
}

// SetArpMatch to set L3 protocol as Arp
func (m *Match) SetArpMatch() {
	m.L3Protocol = EtherTypeArp
}

// SetICMPv6Match to set L3 and L4 protocol as IPV6 and ICMPv6
func (m *Match) SetICMPv6Match() {
	m.L3Protocol = EtherTypeIpv6
	m.L4Protocol = IPProtocolIcmpv6
}

// SetUdpv4Match to set L3 and L4 protocol as IPv4 and UDP
func (m *Match) SetUdpv4Match() {
	m.L3Protocol = EtherTypeIpv4
	m.L4Protocol = IPProtocolUDP
}

// SetIgmpMatch to set L3 and L4 protocol as IPv4 and Igmp
func (m *Match) SetIgmpMatch() {
	m.L3Protocol = EtherTypeIpv4
	m.L4Protocol = IPProtocolIgmp
}

// SetUdpv6Match to set L3 and L4 protocol as IPv6 and UDP
func (m *Match) SetUdpv6Match() {
	m.L3Protocol = EtherTypeIpv6
	m.L4Protocol = IPProtocolUDP
}

// SetIpv4Match to set L3 as IPv4
func (m *Match) SetIpv4Match() {
	m.L3Protocol = EtherTypeIpv4
}

// OutputType type
type OutputType uint8

const (
	// OutputTypeDrop constant
	OutputTypeDrop OutputType = 1
	// OutputTypeToController constant
	OutputTypeToController OutputType = 2
	// OutputTypeToNetwork constant
	OutputTypeToNetwork OutputType = 3
	// OutputTypeGoToTable constant
	OutputTypeGoToTable OutputType = 4
	// OutputTypeToGroup constant
	OutputTypeToGroup OutputType = 5
)

const (
	// FlowAddSuccess constant
	FlowAddSuccess = 0
	// FlowAddFailure constant
	FlowAddFailure = 1
	// FlowAddPending constant
	FlowAddPending = 2
	// FlowDelPending constant
	FlowDelPending = 3
	// FlowDelFailure constant
	FlowDelFailure = 4
)

// Action structure
type Action struct {
	PushVlan    []VlanType
	Metadata    uint64
	RemoveVlan  int
	OutPort     uint32
	GoToTableID uint32
	MeterID     uint32
	EtherType   layers.EthernetType
	SetVlan     VlanType
	Pcp         PbitType
	Output      OutputType
}

const (
	// PbitNone constant
	PbitNone PbitType = 8
)

// Reset the action structure
func (a *Action) Reset() {
	a.Output = OutputTypeDrop
	a.PushVlan = make([]VlanType, 0)
	a.SetVlan = VlanNone
	a.RemoveVlan = 0
	a.Metadata = 0
	a.MeterID = 0
	a.Pcp = PbitNone
}

// SetReportToController for set action to report to controller
func (a *Action) SetReportToController() {
	a.Output = OutputTypeToController
	a.OutPort = ControllerPort
}

// SetPushVlan for set action to push to vlan
func (a *Action) SetPushVlan(vlan VlanType, etherType layers.EthernetType) {
	a.PushVlan = append(a.PushVlan, vlan)
	a.EtherType = etherType
}

// SetSetVlan to set SetVlan
func (a *Action) SetSetVlan(vlan VlanType) {
	a.SetVlan = vlan
}

// SetPopVlan to set remove vlan counter
func (a *Action) SetPopVlan() {
	a.RemoveVlan++
}

// SetMeterID to set meter id
func (a *Action) SetMeterID(meterID uint32) {
	a.MeterID = meterID
}

// SetWriteMetadata to set metadata
func (a *Action) SetWriteMetadata(metadata uint64) {
	a.Metadata = metadata
}

// SetPcp to set pcp
func (a *Action) SetPcp(pcp PbitType) {
	a.Pcp = pcp
}

// GetWriteMetadata returns metadata
func (a *Action) GetWriteMetadata() uint64 {
	return a.Metadata
}

// SetOutPort to set output port
func (a *Action) SetOutPort(port uint32) {
	a.Output = OutputTypeToNetwork
	a.OutPort = port
}

// SetOutGroup to set output group
func (a *Action) SetOutGroup(group uint32) {
	a.Output = OutputTypeToGroup
	a.OutPort = group
}

// SetGoToTable to set GoToTableID
func (a *Action) SetGoToTable(table uint32) {
	a.Output = OutputTypeGoToTable
	a.GoToTableID = table
}

// VoltSubFlow structure
type VoltSubFlow struct {
	ErrorReason string
	Match
	Action
	Cookie     uint64
	CookieMask uint64
	// OldCookie is used in vgc upgrade when there is cookie generation logic change.
	OldCookie uint64
	TableID   uint32
	Priority  uint32
	State     uint8
	FlowCount uint32
}

// NewVoltSubFlow is constructor for VoltSubFlow
func NewVoltSubFlow() *VoltSubFlow {
	var sf VoltSubFlow
	sf.Match.Reset()
	sf.Action.Reset()
	return &sf
}

// SetTableID to set table id
func (sf *VoltSubFlow) SetTableID(tableID uint32) {
	sf.TableID = tableID
}

// Command type
type Command uint8

const (
	// CommandAdd constant
	CommandAdd Command = 0
	// CommandDel constant
	CommandDel Command = 1
)

// VoltFlow : Definition of a flow
type VoltFlow struct {
	SubFlows map[uint64]*VoltSubFlow
	// PortName and PortID to be used for validation of port before flow pushing
	PortName      string
	PortID        uint32
	Command       Command
	ForceAction   bool
	MigrateCookie bool
}

const (
	// PrevBwInfo indicates the string returned by core for bandwidth consumed before creating scheduler
	PrevBwInfo string = "prevBW"
	// PresentBwInfo indicates the string returned by core for bandwidth consumed after creating scheduler
	PresentBwInfo string = "presentBW"
)

// BwAvailDetails consists of bw consumtion details at olt
type BwAvailDetails struct {
	PrevBw    string
	PresentBw string
}

// -------------------------------------------------------------------
// OPENFLOW Implementation of flows
//
// The flows constructed using the above structures is translated to
// the VOLTHA OpenFlow GRPC structures. The code below is used to
// construct the VOLTHA OF GRPC structures.
const (
	// DefaultMeterID constant
	DefaultMeterID uint32 = 0x1
	// DefaultBufferID constant
	DefaultBufferID uint32 = 0xffffffff
	// DefaultOutPort constant
	DefaultOutPort uint32 = 0xffffffff
	// DefaultOutGroup constant
	DefaultOutGroup uint32 = 0xffffffff
	// DefaultFlags constant
	DefaultFlags uint32 = 0x1
)

// NewInportMatch for inport info
func NewInportMatch(port uint32) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_IN_PORT
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_Port{Port: port}
	return &entry
}

// NewTableMetadataMatch for table metadata
func NewTableMetadataMatch(metadata uint64) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_METADATA
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_TableMetadata{TableMetadata: metadata}
	return &entry
}

// NewSrcMacAddrMatch for source mac address info
func NewSrcMacAddrMatch(addr []byte) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_ETH_SRC
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_EthSrc{EthSrc: addr}
	return &entry
}

// NewDstMacAddrMatch for destination mac address info
func NewDstMacAddrMatch(addr []byte) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_ETH_DST
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_EthDst{EthDst: addr}
	return &entry
}

// NewVlanMatch for vlan info
func NewVlanMatch(vlan uint16) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_VlanVid{VlanVid: uint32(vlan&0x0fff + 0x1000)}
	mf.Mask = &ofp.OfpOxmOfbField_VlanVidMask{VlanVidMask: uint32(0x1000)}
	return &entry
}

// NewPcpMatch for pcp info
func NewPcpMatch(pbits PbitType) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_PCP
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_VlanPcp{VlanPcp: uint32(pbits)}
	return &entry
}

// NewEthTypeMatch for eth type info
func NewEthTypeMatch(l3proto uint16) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_ETH_TYPE
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_EthType{EthType: uint32(l3proto)}
	return &entry
}

// ipv4ToUint to convert ipv4 to uint
func ipv4ToUint(ip net.IP) uint32 {
	result := uint32(0)
	addr := ip.To4()
	if addr == nil {
		logger.Warnw(ctx, "Invalid Group Addr", log.Fields{"IP": ip})
		return 0
	}
	result = result + uint32(addr[0])<<24
	result = result + uint32(addr[1])<<16
	result = result + uint32(addr[2])<<8
	result = result + uint32(addr[3])
	return result
}

// NewIpv4SrcMatch for ipv4 source address
func NewIpv4SrcMatch(ip net.IP) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_IPV4_SRC
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_Ipv4Src{Ipv4Src: ipv4ToUint(ip)}
	return &entry
}

// NewIpv4DstMatch for ipv4 destination address
func NewIpv4DstMatch(ip net.IP) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_IPV4_DST
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_Ipv4Dst{Ipv4Dst: ipv4ToUint(ip)}
	return &entry
}

// NewIPProtoMatch for ip proto info
func NewIPProtoMatch(l4proto uint16) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_IP_PROTO
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_IpProto{IpProto: uint32(l4proto)}
	return &entry
}

// NewUDPSrcMatch for source udp info
func NewUDPSrcMatch(port uint16) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_UDP_SRC
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_UdpSrc{UdpSrc: uint32(port)}
	return &entry
}

// NewUDPDstMatch for destination udp info
func NewUDPDstMatch(port uint16) *ofp.OfpOxmField {
	var entry ofp.OfpOxmField
	var mf ofp.OfpOxmOfbField
	entry.OxmClass = ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC
	entry.Field = &ofp.OfpOxmField_OfbField{OfbField: &mf}
	mf.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_UDP_DST
	mf.HasMask = false
	mf.Value = &ofp.OfpOxmOfbField_UdpDst{UdpDst: uint32(port)}
	return &entry
}

// NewMeterIDInstruction for meter id instructions
func NewMeterIDInstruction(meterID uint32) *ofp.OfpInstruction {
	var meter ofp.OfpInstruction
	meter.Type = uint32(ofp.OfpInstructionType_OFPIT_METER)
	meter.Data = &ofp.OfpInstruction_Meter{
		Meter: &ofp.OfpInstructionMeter{
			MeterId: meterID,
		},
	}
	return &meter
}

// NewGoToTableInstruction for go to table instructions
func NewGoToTableInstruction(table uint32) *ofp.OfpInstruction {
	var gotoTable ofp.OfpInstruction
	gotoTable.Type = uint32(ofp.OfpInstructionType_OFPIT_GOTO_TABLE)
	gotoTable.Data = &ofp.OfpInstruction_GotoTable{
		GotoTable: &ofp.OfpInstructionGotoTable{
			TableId: table,
		},
	}
	return &gotoTable
}

// NewPopVlanInstruction for pop vlan instructions
func NewPopVlanInstruction() *ofp.OfpInstruction {
	var removeTag ofp.OfpInstruction
	var actions ofp.OfpInstructionActions
	removeTag.Type = uint32(ofp.OfpInstructionType_OFPIT_APPLY_ACTIONS)
	removeTag.Data = &ofp.OfpInstruction_Actions{
		Actions: &actions,
	}
	action := flows.PopVlan()
	actions.Actions = append(actions.Actions, action)
	return &removeTag
}

// NewWriteMetadataInstruction for write metadata instructions
func NewWriteMetadataInstruction(metadata uint64) *ofp.OfpInstruction {
	var md ofp.OfpInstruction
	md.Type = uint32(ofp.OfpInstructionType_OFPIT_WRITE_METADATA)
	md.Data = &ofp.OfpInstruction_WriteMetadata{WriteMetadata: &ofp.OfpInstructionWriteMetadata{Metadata: metadata}}
	return &md
}

// NewPopVlanAction for pop vlan action
func NewPopVlanAction() *ofp.OfpAction {
	return flows.PopVlan()
}

// NewPushVlanInstruction for push vlan instructions
func NewPushVlanInstruction(vlan uint16, etherType uint32) *ofp.OfpInstruction {
	var addTag ofp.OfpInstruction
	var actions ofp.OfpInstructionActions
	addTag.Type = uint32(ofp.OfpInstructionType_OFPIT_APPLY_ACTIONS)
	addTag.Data = &ofp.OfpInstruction_Actions{
		Actions: &actions,
	}
	pushAction := flows.PushVlan(etherType)
	actions.Actions = append(actions.Actions, pushAction)
	var setField ofp.OfpOxmOfbField
	setField.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID
	setField.HasMask = false
	setField.Value = &ofp.OfpOxmOfbField_VlanVid{
		VlanVid: uint32(vlan&0x0fff + 0x1000),
	}
	setAction := flows.SetField(&setField)
	actions.Actions = append(actions.Actions, setAction)
	return &addTag
}

// NewPushVlanAction for push vlan action
func NewPushVlanAction(etherType uint32) *ofp.OfpAction {
	pushAction := flows.PushVlan(etherType)
	return pushAction
}

// NewSetVlanAction for set vlan action
func NewSetVlanAction(vlan uint16) *ofp.OfpAction {
	var setField ofp.OfpOxmOfbField
	setField.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID
	setField.HasMask = false
	and := (vlan & 0xfff)
	or := and + 0x1000
	v := uint32(vlan&0x0fff + 0x1000)
	logger.Debugw(ctx, "Vlan Construction", log.Fields{"Vlan": vlan, "vlan&0x0fff": and, "OR": or, "final": v})
	setField.Value = &ofp.OfpOxmOfbField_VlanVid{
		VlanVid: uint32(vlan&0x0fff + 0x1000),
	}
	setAction := flows.SetField(&setField)
	return setAction
}

// NewSetPcpAction for set pcap action
func NewSetPcpAction(pbits PbitType) *ofp.OfpAction {
	var setField ofp.OfpOxmOfbField
	setField.Type = ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_PCP
	setField.HasMask = false
	setField.Value = &ofp.OfpOxmOfbField_VlanPcp{VlanPcp: uint32(pbits)}
	setAction := flows.SetField(&setField)
	return setAction
}

// NewOutputInstruction for output instructions
func NewOutputInstruction(port uint32) *ofp.OfpInstruction {
	var outport ofp.OfpInstruction
	var actions ofp.OfpInstructionActions
	outport.Type = uint32(ofp.OfpInstructionType_OFPIT_APPLY_ACTIONS)
	outport.Data = &ofp.OfpInstruction_Actions{
		Actions: &actions,
	}
	action := flows.Output(port, 65535)
	actions.Actions = append(actions.Actions, action)
	return &outport
}

// NewOutputAction for output action
func NewOutputAction(port uint32) *ofp.OfpAction {
	return flows.Output(port, 65535)
}

// NewGroupOutputInstruction for group output instructions
func NewGroupOutputInstruction(group uint32) *ofp.OfpInstruction {
	var outgroup ofp.OfpInstruction
	var actions ofp.OfpInstructionActions
	outgroup.Type = uint32(ofp.OfpInstructionType_OFPIT_APPLY_ACTIONS)
	outgroup.Data = &ofp.OfpInstruction_Actions{
		Actions: &actions,
	}
	action := flows.Group(group)
	actions.Actions = append(actions.Actions, action)
	return &outgroup
}

// NewGroupAction for group action
func NewGroupAction(group uint32) *ofp.OfpAction {
	return flows.Group(group)
}

// CreateMatchAndActions to create match list and action
func CreateMatchAndActions(f *VoltSubFlow) ([]*ofp.OfpOxmField, []*ofp.OfpInstruction) {
	logger.Debug(ctx, "Create Match and Action called")

	// Return values declared here
	var matchList []*ofp.OfpOxmField
	var instructions []*ofp.OfpInstruction

	// Construct the match rules
	// Add match in port
	if f.InPort != 0 {
		entry := NewInportMatch(uint32(f.InPort))
		matchList = append(matchList, entry)
	}

	// Add table metadata match
	if f.TableMetadata != 0 {
		entry := NewTableMetadataMatch(uint64(f.TableMetadata))
		matchList = append(matchList, entry)
	}

	// Add Src MAC address match
	if f.SrcMacMatch {
		entry := NewSrcMacAddrMatch(f.SrcMacAddr)
		matchList = append(matchList, entry)
	}

	// Add Src MAC address match
	if f.DstMacMatch {
		entry := NewDstMacAddrMatch(f.DstMacAddr)
		matchList = append(matchList, entry)
	}

	// Add VLAN tag match
	if f.MatchVlan != VlanNone {
		entry := NewVlanMatch(uint16(f.MatchVlan))
		matchList = append(matchList, entry)
	}

	if f.MatchPbits {
		entry := NewPcpMatch(f.Pbits)
		matchList = append(matchList, entry)
	}

	// Add EtherType match
	if f.L3Protocol != EtherTypeAny {
		entry := NewEthTypeMatch(uint16(f.L3Protocol))
		matchList = append(matchList, entry)
	}

	// Add the Src IPv4 addr match
	if f.SrcIpv4Match {
		entry := NewIpv4SrcMatch(f.SrcIpv4Addr)
		matchList = append(matchList, entry)
	}

	// Add the Dst IPv4 addr match
	if f.DstIpv4Match {
		entry := NewIpv4DstMatch(f.DstIpv4Addr)
		matchList = append(matchList, entry)
	}

	// Add IP protocol match
	if f.L4Protocol != IPProtocolIgnore {
		entry := NewIPProtoMatch(uint16(f.L4Protocol))
		matchList = append(matchList, entry)
	}

	// Add UDP Source port match
	if f.SrcPort != 0 {
		entry := NewUDPSrcMatch(uint16(f.SrcPort))
		matchList = append(matchList, entry)
	}

	// Add UDP Dest port match
	if f.DstPort != 0 {
		entry := NewUDPDstMatch(uint16(f.DstPort))
		matchList = append(matchList, entry)
	}

	// Construct the instructions
	// Add a GOTO table action
	if f.Output == OutputTypeGoToTable {
		instruction := NewGoToTableInstruction(f.GoToTableID)
		instructions = append(instructions, instruction)
	}

	// Add the meter instruction
	if f.MeterID != 0 {
		instruction := NewMeterIDInstruction(f.MeterID)
		instructions = append(instructions, instruction)
	}

	// Add the metadata instruction
	if f.Metadata != 0 {
		instruction := NewWriteMetadataInstruction(f.Metadata)
		instructions = append(instructions, instruction)
	}

	// The below are all apply actions. All of these could be combined into
	// a single instruction.
	{
		var instruction ofp.OfpInstruction
		var actions ofp.OfpInstructionActions
		instruction.Type = uint32(ofp.OfpInstructionType_OFPIT_APPLY_ACTIONS)
		instruction.Data = &ofp.OfpInstruction_Actions{
			Actions: &actions,
		}

		// Apply action of popping the VLAN
		if f.RemoveVlan != 0 {
			for i := 0; i < f.RemoveVlan; i++ {
				action := NewPopVlanAction()
				actions.Actions = append(actions.Actions, action)
			}
		}

		if f.SetVlan != VlanNone {
			action := NewSetVlanAction(uint16(f.SetVlan))
			actions.Actions = append(actions.Actions, action)
		}

		if f.Pcp != PbitNone {
			action := NewSetPcpAction(f.Pcp)
			actions.Actions = append(actions.Actions, action)
		}

		// Add the VLAN PUSH
		if len(f.PushVlan) != 0 {
			action := NewPushVlanAction(uint32(f.EtherType))
			actions.Actions = append(actions.Actions, action)
			for _, vlan := range f.PushVlan {
				action = NewSetVlanAction(uint16(vlan))
				actions.Actions = append(actions.Actions, action)
			}
		}

		switch f.Output {
		case OutputTypeToController:
			action := NewOutputAction(0xfffffffd)
			actions.Actions = append(actions.Actions, action)
		case OutputTypeToNetwork:
			action := NewOutputAction(f.OutPort)
			actions.Actions = append(actions.Actions, action)
		case OutputTypeToGroup:
			action := NewGroupAction(f.OutPort)
			actions.Actions = append(actions.Actions, action)
		}
		instructions = append(instructions, &instruction)
	}

	return matchList, instructions
}

// CreateFlow to create flow
func CreateFlow(device string, command ofp.OfpFlowModCommand, matches []*ofp.OfpOxmField,
	instructions []*ofp.OfpInstruction, sf *VoltSubFlow) *ofp.FlowTableUpdate {
	flowUpdate := ofp.FlowTableUpdate{
		Id: device,
		FlowMod: &ofp.OfpFlowMod{
			Cookie:      sf.Cookie,
			CookieMask:  sf.CookieMask,
			TableId:     sf.TableID,
			Command:     command,
			IdleTimeout: uint32(0),
			HardTimeout: uint32(0),
			Priority:    sf.Priority,
			BufferId:    DefaultBufferID,
			OutPort:     DefaultOutPort,
			OutGroup:    DefaultOutGroup,
			Flags:       DefaultFlags,
			Match: &ofp.OfpMatch{
				Type:      ofp.OfpMatchType_OFPMT_OXM,
				OxmFields: matches,
			},

			Instructions: instructions,
		},
	}
	return &flowUpdate
}

// Processing logic for the VOLT flows. The VOLT flows are different from
// the normal openflows. Each VOLT flow may break into multiple flows.
// The order of processing:
// 1. If the flow has to match more than one VLAN tag, it is broken into
//    more than one flow.
// 2. When more than one flow is creatd, the higher layer processing is
//    broken into the second flow. The first flow includes only the
//    the processing of first VLAN tag.
// 3. The a sinle flow is created, the first flow has all the match criteria
//    and action.

// ProcessVoltFlow to process volt flow
func ProcessVoltFlow(device string, operation Command, subFlow map[uint64]*VoltSubFlow) []*ofp.FlowTableUpdate {
	var flows []*ofp.FlowTableUpdate
	var command ofp.OfpFlowModCommand
	if operation == CommandAdd {
		command = ofp.OfpFlowModCommand_OFPFC_ADD
	} else {
		command = ofp.OfpFlowModCommand_OFPFC_DELETE_STRICT
	}
	for _, sf := range subFlow {
		logger.Debugw(ctx, "Flow Construction for", log.Fields{"Flow": sf})
		match, instruction := CreateMatchAndActions(sf)
		flow := CreateFlow(device, command, match, instruction, sf)
		logger.Debugw(ctx, "Flow Constructed", log.Fields{"Flow": flow})
		flows = append(flows, flow)
	}
	return flows
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}
