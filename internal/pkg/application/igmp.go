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
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"voltha-go-controller/internal/pkg/types"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

const (
	// IgmpVersion0 constant (Default init value)
	IgmpVersion0 uint8 = 0
	// IgmpVersion1 constant
	IgmpVersion1 uint8 = 1
	// IgmpVersion2 constant
	IgmpVersion2 uint8 = 2
	// IgmpVersion3 constant
	IgmpVersion3 uint8 = 3
	// MinKeepAliveInterval constant
	MinKeepAliveInterval uint32 = 10
	// MaxDiffKAIntervalResp constant
	MaxDiffKAIntervalResp uint32 = 5
	// StaticGroup constant
	StaticGroup string = "static"
	// DynamicGroup constant
	DynamicGroup string = "dynamic"
	// StaticPort constant
	StaticPort string = "static_port"
	// DefaultIgmpProfID constant
	DefaultIgmpProfID = ""
	//GroupExpiryTime - group expiry time in minutes
	GroupExpiryTime uint32 = 15
)

const (
	// JoinUnsuccessful constant
	JoinUnsuccessful string = "JOIN-UNSUCCESSFUL"
	// JoinUnsuccessfulExceededIGMPChanel constant
	JoinUnsuccessfulExceededIGMPChanel string = "Exceeded subscriber or PON port IGMP channels threshold"
	// JoinUnsuccessfulAddFlowGroupFailed constant
	JoinUnsuccessfulAddFlowGroupFailed string = "Failed to add flow or group for a channel"
	// JoinUnsuccessfulGroupNotConfigured constant
	JoinUnsuccessfulGroupNotConfigured string = "Join received from a subscriber on non-configured group"
	// JoinUnsuccessfulVlanDisabled constant
	JoinUnsuccessfulVlanDisabled string = "Vlan is disabled"
	// JoinUnsuccessfulDescription constant
	JoinUnsuccessfulDescription string = "igmp join unsuccessful"
	// QueryExpired constant
	QueryExpired string = "QUERY-EXPIRED"
	// QueryExpiredGroupSpecific constant
	QueryExpiredGroupSpecific string = "Group specific multicast query expired"
	// QueryExpiredDescription constant
	QueryExpiredDescription string = "igmp query expired"
)

// IgmpProfile structure
type IgmpProfile struct {
	ProfileID          string
	UnsolicitedTimeOut uint32 //In seconds
	MaxResp            uint32
	KeepAliveInterval  uint32
	KeepAliveCount     uint32
	LastQueryInterval  uint32
	LastQueryCount     uint32
	FastLeave          bool
	PeriodicQuery      bool
	IgmpCos            uint8
	WithRAUpLink       bool
	WithRADownLink     bool
	IgmpVerToServer    string
	IgmpSourceIP       net.IP
	Version            string
}

// McastConfig structure
type McastConfig struct {
	OltSerialNum   string
	MvlanProfileID string
	IgmpProfileID  string
	IgmpProxyIP    net.IP
	OperState      OperInProgress
	Version        string
	// This map will help in updating the igds whenever there is a igmp profile id update
	IgmpGroupDevices sync.Map `json:"-"` // Key is group id
}

var (
	// NullIPAddr is null ip address var
	NullIPAddr = net.ParseIP("0.0.0.0")
	// igmpSrcMac for the proxy
	igmpSrcMac string
)

func init() {
	RegisterPacketHandler(IGMP, ProcessIgmpPacket)
}

// ProcessIgmpPacket : CallBack function registered with application to handle IGMP packetIn
func ProcessIgmpPacket(device string, port string, pkt gopacket.Packet) {
	GetApplication().IgmpPacketInd(device, port, pkt)
}

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

func getPodMacAddr() (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var ipv4Addr net.IP
	for _, ifa := range ifas {
		addrs, err := ifa.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
				if ipv4Addr.IsGlobalUnicast() {
					logger.Infow(ctx, "Igmp Static config", log.Fields{"MacAddr": ifa.HardwareAddr.String(), "ipAddr": ipv4Addr})
					return ifa.HardwareAddr.String(), nil
				}
			}
		}

	}
	return "", errors.New("MAC Address not found,Setting default")
}

// IgmpUsEthLayer : Layers defined for upstream communication
// Ethernet layer for upstream communication
func IgmpUsEthLayer(mcip net.IP) *layers.Ethernet {
	eth := &layers.Ethernet{}
	// TODO: Set the source MAC properly and remove hardcoding
	eth.SrcMAC, _ = net.ParseMAC(igmpSrcMac)
	eth.DstMAC, _ = net.ParseMAC("01:00:5e:00:00:00")
	eth.DstMAC[3] = mcip[1] & 0x7f
	eth.DstMAC[4] = mcip[2]
	eth.DstMAC[5] = mcip[3]
	eth.EthernetType = layers.EthernetTypeDot1Q
	return eth
}

// IgmpUsDot1qLayer set US VLAN layer
func IgmpUsDot1qLayer(vlan of.VlanType, priority uint8) *layers.Dot1Q {
	dot1q := &layers.Dot1Q{}
	dot1q.Priority = priority
	dot1q.DropEligible = false
	dot1q.VLANIdentifier = uint16(vlan)
	dot1q.Type = layers.EthernetTypeIPv4
	return dot1q
}

// Igmpv2UsIpv4Layer : Set the IP layer for IGMPv2
// TODO - Identify correct way of obtaining source IP
// This should be the configured IGMP proxy address which should be per OLT
// We should probably be able to have a single function for both
// upstream and downstream
func Igmpv2UsIpv4Layer(src net.IP, mcip net.IP) *layers.IPv4 {
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolIGMP
	ip.TTL = 1
	ip.SrcIP = src
	ip.DstIP = mcip
	return ip
}

// Igmpv3UsIpv4Layer : Set the IP layer for IGMPv3
// TODO - Identify correct way of obtaining source IP
// This should be the configured IGMP proxy address which should be per OLT
// We should probably be able to have a single function for both
// upstream and downstream
func Igmpv3UsIpv4Layer(src net.IP) *layers.IPv4 {
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolIGMP
	ip.TTL = 1
	ip.SrcIP = src
	ip.DstIP = net.ParseIP("224.0.0.22")
	return ip
}

// IgmpDsEthLayer : Layers defined for downstream communication
// Ethernet layer for downstream communication
func IgmpDsEthLayer(mcip net.IP) *layers.Ethernet {
	eth := &layers.Ethernet{}
	// TODO: Set the source and dest MAC properly and remove hardcoding
	eth.SrcMAC, _ = net.ParseMAC(igmpSrcMac)
	eth.DstMAC, _ = net.ParseMAC("01:00:5e:00:00:00")
	eth.DstMAC[3] = mcip[1] & 0x7f
	eth.DstMAC[4] = mcip[2]
	eth.DstMAC[5] = mcip[3]
	eth.EthernetType = layers.EthernetTypeDot1Q
	return eth
}

// IgmpDsDot1qLayer set the DS VLAN layer
func IgmpDsDot1qLayer(vlan of.VlanType, priority uint8) *layers.Dot1Q {
	dot1q := &layers.Dot1Q{}
	dot1q.Priority = priority
	dot1q.DropEligible = false
	dot1q.VLANIdentifier = uint16(vlan)
	dot1q.Type = layers.EthernetTypeIPv4
	return dot1q
}

// IgmpDsIpv4Layer set the IP layer
func IgmpDsIpv4Layer(src net.IP, mcip net.IP) *layers.IPv4 {
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolIGMP
	ip.TTL = 1
	ip.SrcIP = src
	if mcip.Equal(net.ParseIP("0.0.0.0")) {
		mcip = net.ParseIP("224.0.0.1")
	}
	ip.DstIP = mcip
	return ip
}

// IgmpQueryv2Layer : IGMP Query Layer
func IgmpQueryv2Layer(mcip net.IP, resptime time.Duration) *layers.IGMPv1or2 {
	igmp := &layers.IGMPv1or2{}
	igmp.Type = layers.IGMPMembershipQuery
	igmp.GroupAddress = mcip
	igmp.MaxResponseTime = resptime
	return igmp
}

// IgmpQueryv3Layer : IGMP v3 Query Layer
func IgmpQueryv3Layer(mcip net.IP, resptime time.Duration) *layers.IGMP {
	igmp := &layers.IGMP{}
	igmp.Type = layers.IGMPMembershipQuery
	igmp.GroupAddress = mcip
	igmp.MaxResponseTime = resptime
	return igmp
}

// IgmpReportv2Layer : IGMP Layer
func IgmpReportv2Layer(mcip net.IP) *layers.IGMPv1or2 {
	igmp := &layers.IGMPv1or2{}
	igmp.Type = layers.IGMPMembershipReportV2
	igmp.GroupAddress = mcip
	return igmp
}

// IgmpLeavev2Layer : IGMP Leave Layer
func IgmpLeavev2Layer(mcip net.IP) *layers.IGMPv1or2 {
	igmp := &layers.IGMPv1or2{}
	igmp.Type = layers.IGMPLeaveGroup
	igmp.GroupAddress = mcip
	return igmp
}

// IgmpReportv3Layer : IGMP v3 Report Layer
func IgmpReportv3Layer(mcip net.IP, incl bool, srclist []net.IP) *layers.IGMP {
	// IGMP base
	igmp := &layers.IGMP{}
	igmp.Type = layers.IGMPMembershipReportV3
	igmp.NumberOfGroupRecords = 1

	// IGMP Group
	group := layers.IGMPv3GroupRecord{}
	if incl {
		group.Type = layers.IGMPIsIn
	} else {
		group.Type = layers.IGMPIsEx
	}
	group.MulticastAddress = mcip
	group.NumberOfSources = uint16(len(srclist))
	group.SourceAddresses = srclist
	igmp.GroupRecords = append(igmp.GroupRecords, group)

	return igmp
}

// Igmpv2QueryPacket : IGMP Query in Downstream
func Igmpv2QueryPacket(mcip net.IP, vlan of.VlanType, selfip net.IP, pbit uint8, maxResp uint32) ([]byte, error) {
	// Construct the layers that form the packet
	eth := IgmpDsEthLayer(mcip)
	dot1q := IgmpDsDot1qLayer(vlan, pbit)
	ip := IgmpDsIpv4Layer(selfip, mcip)
	igmp := IgmpQueryv2Layer(mcip, time.Duration(maxResp)*time.Second)

	// Now prepare the buffer into which the layers are to be serialized
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buff, opts, eth, dot1q, ip, igmp); err != nil {
		logger.Error(ctx, "Error in serializing layers")
		return nil, err
	}
	return buff.Bytes(), nil
}

// Igmpv3QueryPacket : IGMPv3 Query in Downstream
func Igmpv3QueryPacket(mcip net.IP, vlan of.VlanType, selfip net.IP, pbit uint8, maxResp uint32) ([]byte, error) {
	// Construct the layers that form the packet
	eth := IgmpDsEthLayer(mcip)
	dot1q := IgmpDsDot1qLayer(vlan, pbit)
	ip := IgmpDsIpv4Layer(selfip, mcip)
	igmp := IgmpQueryv3Layer(mcip, time.Duration(maxResp)*time.Second)

	// Now prepare the buffer into which the layers are to be serialized
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buff, opts, eth, dot1q, ip, igmp); err != nil {
		logger.Error(ctx, "Error in serializing layers")
		return nil, err
	}
	return buff.Bytes(), nil
}

// IgmpReportv2Packet : Packet - IGMP v2 report in upstream
func IgmpReportv2Packet(mcip net.IP, vlan of.VlanType, priority uint8, selfip net.IP) ([]byte, error) {
	// Construct the layers that form the packet
	eth := IgmpUsEthLayer(mcip)
	dot1q := IgmpUsDot1qLayer(vlan, priority)
	ip := Igmpv2UsIpv4Layer(selfip, mcip)
	igmp := IgmpReportv2Layer(mcip)

	// Now prepare the buffer into which the layers are to be serialized
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buff, opts, eth, dot1q, ip, igmp); err != nil {
		logger.Error(ctx, "Error in serializing layers")
		return nil, err
	}
	return buff.Bytes(), nil
}

// Igmpv3ReportPacket : Packet - IGMP v3 report in upstream
func Igmpv3ReportPacket(mcip net.IP, vlan of.VlanType, priority uint8, selfip net.IP, incl bool, srclist []net.IP) ([]byte, error) {
	// Construct the layers that form the packet
	eth := IgmpUsEthLayer(net.ParseIP("224.0.0.22").To4())
	dot1q := IgmpUsDot1qLayer(vlan, priority)
	ip := Igmpv3UsIpv4Layer(selfip)
	igmp := IgmpReportv3Layer(mcip, incl, srclist)

	// Now prepare the buffer into which the layers are to be serialized
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buff, opts, eth, dot1q, ip, igmp); err != nil {
		logger.Error(ctx, "Error in serializing layers")
		return nil, err
	}
	return buff.Bytes(), nil
}

// IgmpLeavePacket : Packet- IGMP Leave in upstream
func IgmpLeavePacket(mcip net.IP, vlan of.VlanType, priority uint8, selfip net.IP) ([]byte, error) {
	// Construct the layers that form the packet
	eth := IgmpUsEthLayer(mcip)
	dot1q := IgmpUsDot1qLayer(vlan, priority)
	ip := Igmpv2UsIpv4Layer(selfip, mcip)
	igmp := IgmpLeavev2Layer(mcip)

	// Now prepare the buffer into which the layers are to be serialized
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buff, opts, eth, dot1q, ip, igmp); err != nil {
		logger.Error(ctx, "Error in serializing layers")
		return nil, err
	}
	return buff.Bytes(), nil
}

// getVersion to get igmp version type
func getVersion(ver string) uint8 {
	if ver == "2" || ver == "v2" {
		return IgmpVersion2
	}
	return IgmpVersion3
}

// IsIPPresent is Utility to check if an IP address is in a list
func IsIPPresent(i net.IP, ips []net.IP) bool {
	for _, ip := range ips {
		if i.Equal(ip) {
			return true
		}
	}
	return false
}

// IgmpGroupPort : IGMP port implements a port which is associated with an IGMP
// version and the list of sources it implements for a given IGMP
// channel. We may improve this to have all IGMP channels so that
// we can implement per subscriber IGMP channel registration limits
// As a rule a single port cannot have both include and exclude
// lists. If we receive a include list we should purge the other
// list which is TODO
type IgmpGroupPort struct {
	Port              string
	CVlan             uint16
	Pbit              uint8
	Version           uint8
	Exclude           bool
	ExcludeList       []net.IP
	IncludeList       []net.IP
	QueryTimeoutCount uint32
	PonPortID         uint32
}

// NewIgmpGroupPort is constructor for a port
func NewIgmpGroupPort(port string, cvlan uint16, pbit uint8, version uint8, incl bool, ponPortID uint32) *IgmpGroupPort {
	var igp IgmpGroupPort
	igp.Port = port
	igp.CVlan = cvlan
	igp.Pbit = pbit
	igp.Version = version
	igp.Exclude = !incl
	igp.QueryTimeoutCount = 0
	igp.PonPortID = ponPortID
	return &igp
}

// InclSourceIsIn checks if a source is in include list
func (igp *IgmpGroupPort) InclSourceIsIn(src net.IP) bool {
	return IsIPPresent(src, igp.IncludeList)
}

// ExclSourceIsIn checks if a source is in exclude list
func (igp *IgmpGroupPort) ExclSourceIsIn(src net.IP) bool {
	return IsIPPresent(src, igp.ExcludeList)
}

// AddInclSource adds a source is in include list
func (igp *IgmpGroupPort) AddInclSource(src net.IP) {
	logger.Debugw(ctx, "Adding Include Source", log.Fields{"Port": igp.Port, "Src": src})
	igp.IncludeList = append(igp.IncludeList, src)
}

// AddExclSource adds a source is in exclude list
func (igp *IgmpGroupPort) AddExclSource(src net.IP) {
	logger.Debugw(ctx, "Adding Exclude Source", log.Fields{"Port": igp.Port, "Src": src})
	igp.ExcludeList = append(igp.ExcludeList, src)
}

// DelInclSource deletes a source is in include list
func (igp *IgmpGroupPort) DelInclSource(src net.IP) {
	logger.Debugw(ctx, "Deleting Include Source", log.Fields{"Port": igp.Port, "Src": src})
	for i, addr := range igp.IncludeList {
		if addr.Equal(src) {
			igp.IncludeList = append(igp.IncludeList[:i], igp.IncludeList[i+1:]...)
			return
		}
	}
}

// DelExclSource deletes a source is in exclude list
func (igp *IgmpGroupPort) DelExclSource(src net.IP) {
	logger.Debugw(ctx, "Deleting Exclude Source", log.Fields{"Port": igp.Port, "Src": src})
	for i, addr := range igp.ExcludeList {
		if addr.Equal(src) {
			igp.ExcludeList = append(igp.ExcludeList[:i], igp.ExcludeList[i+1:]...)
			return
		}
	}
}

// WriteToDb is utility to write IGMP Group Port Info to database
func (igp *IgmpGroupPort) WriteToDb(mvlan of.VlanType, gip net.IP, device string) error {
	b, err := json.Marshal(igp)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpRcvr(mvlan, gip, device, igp.Port, string(b)); err1 != nil {
		return err1
	}
	return nil
}

// NewIgmpGroupPortFromBytes create the IGMP group port from a byte slice
func NewIgmpGroupPortFromBytes(b []byte) (*IgmpGroupPort, error) {
	var igp IgmpGroupPort
	if err := json.Unmarshal(b, &igp); err != nil {
		logger.Warnw(ctx, "Decode of port failed", log.Fields{"str": string(b)})
		return nil, err
	}
	return &igp, nil
}

// IgmpGroupChannel structure
type IgmpGroupChannel struct {
	Device       string
	GroupID      uint32
	GroupName    string
	GroupAddr    net.IP
	Mvlan        of.VlanType
	Exclude      int
	ExcludeList  []net.IP
	IncludeList  []net.IP
	Version      uint8
	ServVersion  *uint8                    `json:"-"`
	CurReceivers map[string]*IgmpGroupPort `json:"-"`
	NewReceivers map[string]*IgmpGroupPort `json:"-"`
	proxyCfg     **IgmpProfile
	IgmpProxyIP  **net.IP                  `json:"-"`
}

// NewIgmpGroupChannel is constructor for a channel. The default IGMP version is set to 3
// as the protocol defines the way to manage backward compatibility
// The implementation handles simultaneous presense of lower versioned
// receivers
func NewIgmpGroupChannel(igd *IgmpGroupDevice, groupAddr net.IP, version uint8) *IgmpGroupChannel {
	var igc IgmpGroupChannel
	igc.Device = igd.Device
	igc.GroupID = igd.GroupID
	igc.GroupName = igd.GroupName
	igc.GroupAddr = groupAddr
	igc.Mvlan = igd.Mvlan
	igc.Version = version
	igc.CurReceivers = make(map[string]*IgmpGroupPort)
	igc.NewReceivers = make(map[string]*IgmpGroupPort)
	igc.proxyCfg = &igd.proxyCfg
	igc.IgmpProxyIP = &igd.IgmpProxyIP
	igc.ServVersion = igd.ServVersion
	return &igc
}

// NewIgmpGroupChannelFromBytes create the IGMP group channel from a byte slice
func NewIgmpGroupChannelFromBytes(b []byte) (*IgmpGroupChannel, error) {
	var igc IgmpGroupChannel
	if err := json.Unmarshal(b, &igc); err != nil {
		return nil, err
	}
	igc.CurReceivers = make(map[string]*IgmpGroupPort)
	igc.NewReceivers = make(map[string]*IgmpGroupPort)
	return &igc, nil
}

// RestorePorts to restore ports
func (igc *IgmpGroupChannel) RestorePorts() {

	igc.migrateIgmpPorts()
	ports, _ := db.GetIgmpRcvrs(igc.Mvlan, igc.GroupAddr, igc.Device)
	for _, port := range ports {
		b, ok := port.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		if igp, err := NewIgmpGroupPortFromBytes(b); err == nil {
			igc.NewReceivers[igp.Port] = igp
			logger.Infow(ctx, "Group Port Restored", log.Fields{"IGP": igp})
		} else {
			logger.Warn(ctx, "Failed to decode port from DB")
		}
	}
	if err := igc.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
}

// WriteToDb is utility to write IGMPGroupChannel Info to database
func (igc *IgmpGroupChannel) WriteToDb() error {
	b, err := json.Marshal(igc)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpChannel(igc.Mvlan, igc.GroupName, igc.Device, igc.GroupAddr, string(b)); err1 != nil {
		return err1
	}
	logger.Info(ctx, "IGC Updated")
	return nil
}

// UniPortList : UNI Port list per channle has stores the UNI port list for this
// channel.
type UniPortList struct {
	UNIList *util.ConcurrentMap // [UNIPort] UNIPort
}

// NewUniPortsList is Constructor for UniPortList structure
func NewUniPortsList() *UniPortList {
	var uniPortsList UniPortList

	uniPortsList.UNIList = util.NewConcurrentMap()
	return &uniPortsList
}

// GetUniPortCount returns the number of UNI ports subscribed to
// current channel.
func (uniPortsList *UniPortList) GetUniPortCount() uint64 {
	return uniPortsList.UNIList.Length()
}

// PonPortChannels : PON port channel map keeps the active channel list and its
// count for this group.
type PonPortChannels struct {
	ChannelList *util.ConcurrentMap // [channelIP]*UniPortList
}

// NewPonPortChannels is constructor for PonPortChannel.
func NewPonPortChannels() *PonPortChannels {
	var ponPortChannel PonPortChannels

	ponPortChannel.ChannelList = util.NewConcurrentMap()
	return &ponPortChannel
}

// GetActiveChannelCount returns the number of active channel count
// for this pon port in the current group.
func (ponPortChannels *PonPortChannels) GetActiveChannelCount() uint32 {
	return uint32(ponPortChannels.ChannelList.Length())
}

// AddChannelToMap Adds new channel to the pon port map
func (ponPortChannels *PonPortChannels) AddChannelToMap(uniPort, channel string) bool {

	isNewChannel := bool(false)
	uniList, ok := ponPortChannels.ChannelList.Get(channel)
	if !ok {
		// Channel doesn't exists. Adding new channel.
		uniList = NewUniPortsList()
		isNewChannel = true
	}
	uniList.(*UniPortList).UNIList.Set(uniPort, uniPort)
	ponPortChannels.ChannelList.Set(channel, uniList)
	return isNewChannel
}

// RemoveChannelFromMap Removed channel from the pon port map
func (ponPortChannels *PonPortChannels) RemoveChannelFromMap(uniPort, channel string) bool {

	isDeleted := bool(false)
	uniList, ok := ponPortChannels.ChannelList.Get(channel)
	if ok {
		uniList.(*UniPortList).UNIList.Remove(uniPort)
		if uniList.(*UniPortList).UNIList.Length() == 0 {
			// Last port from the channel is removed.
			// Removing channel from PON port map.
			ponPortChannels.ChannelList.Remove(channel)
			isDeleted = true
		} else {
			ponPortChannels.ChannelList.Set(channel, uniList)
		}
	} else {
		logger.Warnw(ctx, "Channel doesn't exists in the active channels list", log.Fields{"Channel": channel})
		return isDeleted
	}
	return isDeleted
}

// IgmpGroupDevice : IGMP Group Device manages the IGMP group for all listerns on
// a single OLT. It aggregates reports received on a single group
// and performs the count. It is responsible for sending upstream
// report when the first listener joins and is responsible for
// sending responses to upstream queries
type IgmpGroupDevice struct {
	Device            string
	SerialNo          string
	GroupID           uint32
	GroupName         string
	GroupAddr         net.IP
	RecvVersion       uint8
	ServVersion       *uint8
	RecvVersionExpiry time.Time
	ServVersionExpiry time.Time
	Mvlan             of.VlanType
	PonVlan           of.VlanType
	IsPonVlanPresent  bool
	GroupInstalled    bool
	GroupChannels     sync.Map            `json:"-"` // [ipAddr]*IgmpGroupChannel
	PortChannelMap    sync.Map            `json:"-"` // [portName][]net.IP
	PonPortChannelMap *util.ConcurrentMap `json:"-"` // [ponPortId]*PonPortChannels
	proxyCfg          *IgmpProfile                   // IgmpSrcIp from IgmpProfile is not used, it is kept for backward compatibility
	IgmpProxyIP       *net.IP             `json:"-"`
	NextQueryTime     time.Time
	QueryExpiryTime   time.Time
}

// NewIgmpGroupDevice is constructor for a device. The default IGMP version is set to 3
// as the protocol defines the way to manage backward compatibility
// The implementation handles simultaneous presense of lower versioned
// receivers
func NewIgmpGroupDevice(name string, ig *IgmpGroup, id uint32, version uint8) *IgmpGroupDevice {
	var igd IgmpGroupDevice
	igd.Device = name
	igd.GroupID = id
	igd.GroupName = ig.GroupName
	igd.GroupAddr = ig.GroupAddr
	igd.Mvlan = ig.Mvlan
	igd.PonVlan = ig.PonVlan
	igd.IsPonVlanPresent = ig.IsPonVlanPresent
	igd.GroupInstalled = false
	igd.RecvVersion = version
	igd.RecvVersionExpiry = time.Now()
	igd.ServVersionExpiry = time.Now()
	igd.PonPortChannelMap = util.NewConcurrentMap()

	va := GetApplication()
	if vd := va.GetDevice(igd.Device); vd != nil {
		igd.SerialNo = vd.SerialNum
	} else {
		logger.Errorw(ctx, "Volt Device not found.  log.Fields", log.Fields{"igd.Device": igd.Device})
		return nil
	}
	mvp := GetApplication().GetMvlanProfileByTag(igd.Mvlan)
	igd.ServVersion = mvp.IgmpServVersion[igd.SerialNo]

	var mcastCfg *McastConfig
	igd.proxyCfg, igd.IgmpProxyIP, mcastCfg = getIgmpProxyCfgAndIP(ig.Mvlan, igd.SerialNo)

	// mvlan profile id + olt serial number---igmp group id
	//igmpgroup id
	igd.NextQueryTime = time.Now().Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)
	igd.QueryExpiryTime = time.Now().Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)

	if mcastCfg != nil {
		mcastCfg.IgmpGroupDevices.Store(id, &igd)
		logger.Debugw(ctx, "Igd added to mcast config", log.Fields{"mvlan": mcastCfg.MvlanProfileID, "groupId": id})
	}
	return &igd
}

// IgmpGroupDeviceReInit is re-initializer for a device. The default IGMP version is set to 3
// as the protocol defines the way to manage backward compatibility
func (igd *IgmpGroupDevice) IgmpGroupDeviceReInit(ig *IgmpGroup) {

	logger.Infow(ctx, "Reinitialize Igmp Group Device", log.Fields{"Device": igd.Device, "GroupID": ig.GroupID, "OldName": igd.GroupName, "Name": ig.GroupName, "OldAddr": igd.GroupAddr.String(), "GroupAddr": ig.GroupAddr.String()})

	if (igd.GroupName != ig.GroupName) || !igd.GroupAddr.Equal(ig.GroupAddr) {
		_ = db.DelIgmpDevice(igd.Mvlan, igd.GroupName, igd.GroupAddr, igd.Device)
		igd.GroupName = ig.GroupName
		igd.GroupAddr = ig.GroupAddr
	}
	igd.RecvVersionExpiry = time.Now()
	igd.ServVersionExpiry = time.Now()
	igd.PonPortChannelMap = util.NewConcurrentMap()

	var mcastCfg *McastConfig
	igd.proxyCfg, igd.IgmpProxyIP, mcastCfg = getIgmpProxyCfgAndIP(ig.Mvlan, igd.SerialNo)

	igd.NextQueryTime = time.Now().Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)
	igd.QueryExpiryTime = time.Now().Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)

	if mcastCfg != nil {
		mcastCfg.IgmpGroupDevices.Store(ig.GroupID, igd)
		logger.Debugw(ctx, "Igd added to mcast config", log.Fields{"mvlan": mcastCfg.MvlanProfileID, "groupId": ig.GroupID})
	}
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
}

func getIgmpProxyCfgAndIP(mvlan of.VlanType, serialNo string) (*IgmpProfile, *net.IP, *McastConfig) {
	va := GetApplication()
	mVLANProfileID := va.GetMvlanProfileByTag(mvlan).Name
	var mcastCfg *McastConfig
	if mcastCfg = va.GetMcastConfig(serialNo, mVLANProfileID); mcastCfg == nil || (mcastCfg != nil && mcastCfg.IgmpProfileID == "") {
		logger.Debugw(ctx, "Default IGMP config to be used", log.Fields{"mVLANProfileID": mVLANProfileID, "OltSerialNo": serialNo})
		igmpProf := va.getIgmpProfileMap(DefaultIgmpProfID)
		return igmpProf, &igmpProf.IgmpSourceIP, mcastCfg
	}
	return va.getIgmpProfileMap(mcastCfg.IgmpProfileID), &mcastCfg.IgmpProxyIP, mcastCfg
}

// updateGroupName to update the group name
func (igd *IgmpGroupDevice) updateGroupName(newGroupName string) {

	oldName := igd.GroupName
	igd.GroupName = newGroupName
	updateGroupName := func(key, value interface{}) bool {
		igc := value.(*IgmpGroupChannel)
		igc.GroupName = newGroupName
		if err := igc.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
		}
		_ = db.DelIgmpChannel(igc.Mvlan, oldName, igc.Device, igc.GroupAddr)
		return true
	}
	igd.GroupChannels.Range(updateGroupName)
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
	_ = db.DelIgmpDevice(igd.Mvlan, oldName, igd.GroupAddr, igd.Device)
}

// NewIgmpGroupDeviceFromBytes is to create the IGMP group port from a byte slice
func NewIgmpGroupDeviceFromBytes(b []byte) (*IgmpGroupDevice, error) {
	var igd IgmpGroupDevice
	if err := json.Unmarshal(b, &igd); err != nil {
		return nil, err
	}
	return &igd, nil
}

// GetKey to get group name as key
func (igd *IgmpGroupDevice) GetKey() string {

	if !net.ParseIP("0.0.0.0").Equal(igd.GroupAddr) {
		return igd.GroupName + "_" + igd.GroupAddr.String()
	}
	return igd.GroupName

}

// RestoreChannel to restore channel
func (igd *IgmpGroupDevice) RestoreChannel(igmpGroupChannel []byte) {

	if igc, err := NewIgmpGroupChannelFromBytes(igmpGroupChannel); err == nil {
		igc.ServVersion = igd.ServVersion
		igc.IgmpProxyIP = &igd.IgmpProxyIP
		igc.proxyCfg = &igd.proxyCfg
		igd.GroupChannels.Store(igc.GroupAddr.String(), igc)
		igc.RestorePorts()

		for port, igp := range igc.NewReceivers {
			ipsList := []net.IP{}
			ipsIntf, _ := igd.PortChannelMap.Load(port)
			if ipsIntf != nil {
				ipsList = ipsIntf.([]net.IP)
			}

			ipsList = append(ipsList, igc.GroupAddr)
			igd.PortChannelMap.Store(port, ipsList)
			logger.Infow(ctx, "Group Channels Restored", log.Fields{"IGC": igc})
			igd.AddChannelToChannelsPerPon(port, igc.GroupAddr, igp.PonPortID)
		}
	} else {
		logger.Warnw(ctx, "Failed to decode port from DB", log.Fields{"err": err})
	}
	logger.Info(ctx, "Group Device & Channels Restored")
	igd.PortChannelMap.Range(printPortChannel)
	igd.GroupChannels.Range(printChannel)

}

// RestoreChannels to restore channels
func (igd *IgmpGroupDevice) RestoreChannels() {

	igd.migrateIgmpChannels()
	channels, _ := db.GetIgmpChannels(igd.Mvlan, igd.GroupName, igd.Device)
	for _, channel := range channels {

		b, ok := channel.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		igd.RestoreChannel(b)
	}

}

// printChannel to print channel info
func printChannel(key interface{}, value interface{}) bool {
	logger.Infow(ctx, "ChannelMap", log.Fields{"Channel": key.(string), "Igc": value.(*IgmpGroupChannel)})
	return true
}

// printPortChannel to print port channel
func printPortChannel(key interface{}, value interface{}) bool {
	logger.Infow(ctx, "PortChannelMap", log.Fields{"Port": key.(string), "List": value.([]net.IP)})
	return true
}

// WriteToDb is utility to write IGMP Group Device Info to the database
func (igd *IgmpGroupDevice) WriteToDb() error {
	b, err := json.Marshal(igd)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpDevice(igd.Mvlan, igd.GroupName, igd.GroupAddr, igd.Device, string(b)); err1 != nil {
		return err1
	}
	logger.Info(ctx, "IGD Updated")
	return nil
}

// Tick processes timing tick used to run timers within the device
func (igd *IgmpGroupDevice) Tick() uint8 {
	/* Not using RecvVersionExpiry as it is not used anywhere
	if time.Now().After(igd.RecvVersionExpiry) {
		igd.RecvVersion = IgmpVersion3
		return true
	}
	*/
	return 0
}

// GetSubscriberCountForChannelAndPonPort Gets the active subscriber count
// for the given channel for one particular PON port
func (igd *IgmpGroupDevice) GetSubscriberCountForChannelAndPonPort(ponPortID uint32, channelIP net.IP) uint64 {
	if portMapIntf, ok := igd.PonPortChannelMap.Get(ponPortID); ok {
		portChannelMap := portMapIntf.(*PonPortChannels)

		if channel, present := portChannelMap.ChannelList.Get(channelIP.String()); present {
			return channel.(*UniPortList).UNIList.Length()
		}
	} else {
		logger.Warnw(ctx, "PON port not found in PortChannelMap", log.Fields{"PON": ponPortID, "channel": channelIP})
	}
	return 0
}

// AddChannelToChannelsPerPon Adds the new channel into the per Pon channel list
func (igd *IgmpGroupDevice) AddChannelToChannelsPerPon(uniPort string, channelIP net.IP, ponPortID uint32) bool {
	logger.Debugw(ctx, "Adding channel to ActiveChannelsPerPon list", log.Fields{"PonPort": ponPortID, "channelIP": channelIP})

	isNewChannel := bool(false)
	isNewReceiver := false
	if port, ok := igd.PonPortChannelMap.Get(ponPortID); !ok {
		// PON port not exists in igd. adding it.
		isNewReceiver = true
		ponPortChannels := NewPonPortChannels()
		isNewChannel = ponPortChannels.AddChannelToMap(uniPort, channelIP.String())
		igd.PonPortChannelMap.Set(ponPortID, ponPortChannels)
	} else {
		// PON port exists in igd. Appending the channel list
		// in the PON port.
		isNewChannel = port.(*PonPortChannels).AddChannelToMap(uniPort, channelIP.String())
		igd.PonPortChannelMap.Set(ponPortID, port)
		count := port.(*PonPortChannels).GetActiveChannelCount()

		logger.Debugw(ctx, "activeChannelCount", log.Fields{"count": count})
	}
	GetApplication().UpdateActiveChannelCountForPonPort(igd.Device, uniPort, ponPortID, true, isNewChannel, igd)
	return isNewReceiver
}

// RemoveChannelFromChannelsPerPon removes the channel from the per pon channel list.
func (igd *IgmpGroupDevice) RemoveChannelFromChannelsPerPon(uniPort string, channelIP net.IP, ponPortID uint32) bool {
	logger.Debugw(ctx, "Removing channel from ActiveChannelsPerPon list", log.Fields{"PonPort": ponPortID, "channelIP": channelIP})
	var deleted bool
	ponRemoved := false

	if port, ok := igd.PonPortChannelMap.Get(ponPortID); ok {
		channelPortMap := port.(*PonPortChannels)
		deleted = channelPortMap.RemoveChannelFromMap(uniPort, channelIP.String())
		if deleted && channelPortMap.ChannelList.Length() == 0 {
			igd.PonPortChannelMap.Remove(ponPortID)
			ponRemoved = true
		}
		GetApplication().UpdateActiveChannelCountForPonPort(igd.Device, uniPort, ponPortID, false, deleted, igd)
	} else {
		logger.Warnw(ctx, "PON port doesn't exists in the igd", log.Fields{"PonPortID": ponPortID})
	}
	return ponRemoved
}

// InclSourceIsIn checks if a source is in include list
func (igc *IgmpGroupChannel) InclSourceIsIn(src net.IP) bool {
	return IsIPPresent(src, igc.IncludeList)
}

// ExclSourceIsIn checks if a source is in exclude list
func (igc *IgmpGroupChannel) ExclSourceIsIn(src net.IP) bool {
	return IsIPPresent(src, igc.ExcludeList)
}

// AddInclSource adds a source is in include list
func (igc *IgmpGroupChannel) AddInclSource(src net.IP) {
	logger.Debugw(ctx, "Adding Include Source for Channel", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device, "Src": src})
	igc.IncludeList = append(igc.IncludeList, src)
}

// AddExclSource adds a source is in exclude list
func (igc *IgmpGroupChannel) AddExclSource(src net.IP) {
	logger.Debugw(ctx, "Adding Exclude Source for Channel", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device, "Src": src})
	igc.ExcludeList = append(igc.ExcludeList, src)
}

// UpdateExclSource update excl source list for the given channel
func (igc *IgmpGroupChannel) UpdateExclSource(srcList []net.IP) bool {

	logger.Debugw(ctx, "Updating Exclude Source for Channel", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device, "Current List": igc.ExcludeList, "Incoming List": srcList})
	if !igc.IsExclListChanged(srcList) {
		return false
	}

	if igc.NumReceivers() == 1 {
		igc.ExcludeList = srcList
	} else {
		igc.ExcludeList = igc.computeExclList(srcList)
	}

	logger.Debugw(ctx, "Updated Exclude Source for Channel", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device, "Updated Excl List": igc.ExcludeList})
	return true
}

// computeExclList computes intersection of pervious & current src list
func (igc *IgmpGroupChannel) computeExclList(srcList []net.IP) []net.IP {

	updatedSrcList := []net.IP{}
	for _, src := range srcList {
		for _, excl := range igc.ExcludeList {
			if src.Equal(excl) {
				updatedSrcList = append(updatedSrcList, src)
			}
		}
	}
	return updatedSrcList
}

// IsExclListChanged checks if excl list has been updated
func (igc *IgmpGroupChannel) IsExclListChanged(srcList []net.IP) bool {

	srcPresent := false
	if len(igc.ExcludeList) != len(srcList) {
		return true
	}

	for _, src := range srcList {
		for _, excl := range igc.ExcludeList {
			srcPresent = false
			if src.Equal(excl) {
				srcPresent = true
				break
			}
		}
		if !srcPresent {
			return true
		}
	}
	return false
}

// DelInclSource deletes a source is in include list
func (igc *IgmpGroupChannel) DelInclSource(src net.IP) {
	mvp := GetApplication().GetMvlanProfileByTag(igc.Mvlan)
	/* If the SSM proxy is configured, then we can del the src ip from igc as whatever is in proxy that is final list */
	if _, ok := mvp.Proxy[igc.GroupName]; !ok {
		logger.Debugw(ctx, "Deleting Include Source for Channel", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device, "Src": src})
		for _, igp := range igc.CurReceivers {
			if igp.InclSourceIsIn(src) {
				logger.Infow(ctx, "Skipping deletion: Source Present for another Receiver", log.Fields{"Receiver": igp.Port})
				return
			}
		}
		for _, igp := range igc.NewReceivers {
			if igp.InclSourceIsIn(src) {
				logger.Infow(ctx, "Skipping deletion: Source Present for another Receiver", log.Fields{"Receiver": igp.Port})
				return
			}
		}
	} else {
		logger.Debug(ctx, "Proxy configured, not Deleting Include Source for Channel")
	}
	for i, addr := range igc.IncludeList {
		if addr.Equal(src) {
			igc.IncludeList = append(igc.IncludeList[:i], igc.IncludeList[i+1:]...)
			return
		}
	}
}

// DelExclSource deletes a source is in exclude list
func (igc *IgmpGroupChannel) DelExclSource(src net.IP) {
	logger.Debugw(ctx, "Deleting Exclude Source for Channel", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device, "Src": src})

	for _, igp := range igc.CurReceivers {
		if igp.ExclSourceIsIn(src) {
			logger.Infow(ctx, "Skipping deletion: Source Present for another Receiver", log.Fields{"Receiver": igp.Port})
			return
		}
	}
	for _, igp := range igc.NewReceivers {
		if igp.ExclSourceIsIn(src) {
			logger.Infow(ctx, "Skipping deletion: Source Present for another Receiver", log.Fields{"Receiver": igp.Port})
			return
		}
	}
	for i, addr := range igc.ExcludeList {
		if addr.Equal(src) {
			igc.ExcludeList = append(igc.ExcludeList[:i], igc.ExcludeList[i+1:]...)
			return
		}
	}
}

// ProcessSources process the received list of either included sources or the excluded sources
// The return value indicate sif the group is modified and needs to be informed
// to the upstream multicast servers
func (igc *IgmpGroupChannel) ProcessSources(port string, ip []net.IP, incl bool) (bool, bool) {
	groupChanged := false
	groupExclUpdated := false
	receiverSrcListEmpty := false
	// If the version type is 2, there isn't anything to process here
	if igc.Version == IgmpVersion2 && *igc.ServVersion == IgmpVersion2 {
		return false, false
	}

	igp := igc.GetReceiver(port)
	if igp == nil {
		logger.Warnw(ctx, "Receiver not found", log.Fields{"Port": port})
		return false, false
	}
	mvp := GetApplication().GetMvlanProfileByTag(igc.Mvlan)
	if incl {
		for _, src := range ip {

			if igp.ExclSourceIsIn(src) {
				igp.DelExclSource(src)
				if igc.ExclSourceIsIn(src) {
					igc.DelExclSource(src)
					groupChanged = true
				}
			}

			// If the source is not in the list of include sources for the port
			// add it. If so, check also if it is in list of include sources
			// at the device level.
			if !igp.InclSourceIsIn(src) {
				igp.AddInclSource(src)
				if !igc.InclSourceIsIn(src) {
					igc.AddInclSource(src)
					groupChanged = true
				}
			}
		}
		/* If any of the existing ip in the source list is removed we need to remove from the list in igp and igc */
		if _, ok := mvp.Proxy[igc.GroupName]; ok {
			/* If we get leave message from any subscriber, we do not have to delete the entries in the src list
			   Only if ther is any modification in the src list by proxy config update only then we need to update */
			if len(ip) != 0 && len(ip) != len(igc.IncludeList) {
				for i := len(igc.IncludeList) - 1; i >= 0; i-- {
					src := igc.IncludeList[i]
					if !IsIPPresent(src, ip) {
						igp.DelInclSource(src)
						igc.DelInclSource(src)
						groupChanged = true
					}
				}
			}
		}
	} else {
		for _, src := range ip {

			if igp.InclSourceIsIn(src) {
				igp.DelInclSource(src)
				if igc.InclSourceIsIn(src) {
					igc.DelInclSource(src)
					groupChanged = true
				}
				if len(igp.IncludeList) == 0 {
					receiverSrcListEmpty = true
				}
			}

			// If the source is not in the list of exclude sources for the port
			// add it. If so, check also if it is in list of include sources
			// at the device level.
			if !igp.ExclSourceIsIn(src) {
				igp.AddExclSource(src)
				/* If there is any update in the src list of proxy we need to update the igc */
				if _, ok := mvp.Proxy[igc.GroupName]; ok {
					if !igc.ExclSourceIsIn(src) {
						igc.AddExclSource(src)
						groupChanged = true
					}
				}
			}
		}
		/* If any of the existing ip in the source list is removed we need to remove from the list in igp and igc */
		if _, ok := mvp.Proxy[igc.GroupName]; ok {
			if len(ip) != len(igc.ExcludeList) {
				for i := len(igc.ExcludeList) - 1; i >= 0; i-- {
					src := igc.ExcludeList[i]
					if !IsIPPresent(src, ip) {
						igp.DelExclSource(src)
						igc.DelExclSource(src)
						groupChanged = true
					}
				}
			}
		}
		groupExclUpdated = igc.UpdateExclSource(ip)
	}
	if err := igp.WriteToDb(igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
		logger.Errorw(ctx, "Igmp group port Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	return (groupChanged || groupExclUpdated), receiverSrcListEmpty
}

// GetReceiver to get receiver info
func (igc *IgmpGroupChannel) GetReceiver(port string) *IgmpGroupPort {
	igp := igc.NewReceivers[port]
	if igp == nil {
		igp = igc.CurReceivers[port]
	}
	return igp
}

// AddReceiver add the receiver to the device and perform other actions such as adding the group
// to the physical device, add members, add flows to point the MC packets to the
// group. Also, send a IGMP report upstream if there is a change in the group
func (igd *IgmpGroupDevice) AddReceiver(port string, groupAddr net.IP,
	group *layers.IGMPv3GroupRecord, version uint8, cvlan uint16, pbit uint8, ponPortID uint32) {

	var igc *IgmpGroupChannel
	logger.Debugw(ctx, "Processing receiver for device", log.Fields{"Channel": groupAddr, "Port": port, "Device": igd.Device})

	igcIntf, ok := igd.GroupChannels.Load(groupAddr.String())
	if !ok {
		igc = NewIgmpGroupChannel(igd, groupAddr, version)
		igd.GroupChannels.Store(groupAddr.String(), igc)
	} else {
		igc = igcIntf.(*IgmpGroupChannel)
	}

	if !igd.GroupInstalled {
		igd.AddNewReceiver(port, groupAddr, group, cvlan, pbit, ponPortID)
		return
	}

	isNewReceiver := igc.AddReceiver(port, group, cvlan, pbit)
	if isNewReceiver {
		ipsList := []net.IP{}
		ipsIntf, _ := igd.PortChannelMap.Load(port)
		if ipsIntf != nil {
			ipsList = ipsIntf.([]net.IP)
		}
		ipsList = append(ipsList, groupAddr)
		igd.PortChannelMap.Store(port, ipsList)
		logger.Debugw(ctx, "Port Channel Updated", log.Fields{"Port": port, "AddedChannelList": ipsList, "Addr": groupAddr})

		isNewPonReceiver := igd.AddChannelToChannelsPerPon(port, groupAddr, ponPortID)
		//Modify group only if this is the first time the port is subscribing for the group
		if isNewPonReceiver {
			igd.ModMcGroup()
		}
	}
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
}

// AddNewReceiver to add new receiver
func (igd *IgmpGroupDevice) AddNewReceiver(port string, groupAddr net.IP, group *layers.IGMPv3GroupRecord, cvlan uint16, pbit uint8, ponPortID uint32) {

	logger.Debugw(ctx, "Adding New Device Receiver", log.Fields{"Channel": groupAddr, "Port": port, "Device": igd.Device})
	igcIntf, _ := igd.GroupChannels.Load(groupAddr.String())
	if igcIntf == nil {
		logger.Warnw(ctx, "No Group Channel present for given channel", log.Fields{"Channel": groupAddr, "Port": port, "Device": igd.Device})
		return
	}

	igc := igcIntf.(*IgmpGroupChannel)
	ipsList := []net.IP{}
	ipsIntf, _ := igd.PortChannelMap.Load(port)
	if ipsIntf != nil {
		ipsList = ipsIntf.([]net.IP)
	}
	ipsList = append(ipsList, groupAddr)
	igd.PortChannelMap.Store(port, ipsList)
	igd.AddChannelToChannelsPerPon(port, groupAddr, ponPortID)
	logger.Debugw(ctx, "Port Channel Updated", log.Fields{"Port": port, "NewChannelList": ipsList, "Addr": groupAddr})

	igd.AddMcGroup()
	igc.AddReceiver(port, group, cvlan, pbit)
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
}

// AddReceiver add the receiver to the device and perform other actions such as adding the group
// to the physical device, add members, add flows to point the MC packets to the
// group. Also, send a IGMP report upstream if there is a change in the group
func (igc *IgmpGroupChannel) AddReceiver(port string, group *layers.IGMPv3GroupRecord, cvlan uint16, pbit uint8) bool {

	var igp *IgmpGroupPort
	var groupModified = false
	var isNewReceiver = false

	var ip []net.IP
	incl := false
	mvp := GetApplication().GetMvlanProfileByTag(igc.Mvlan)
	if _, ok := mvp.Proxy[igc.GroupName]; ok {
		if mvp.Proxy[igc.GroupName].Mode == common.Include {
			incl = true
		}
		ip = mvp.Proxy[igc.GroupName].SourceList
	} else if group != nil {
		incl = isIncl(group.Type)
		ip = group.SourceAddresses
	}
	logger.Debugw(ctx, "Attempting to add receiver", log.Fields{"Version": igc.Version, "Port": port, "Incl": incl, "srcIp": ip})

	//logger.Infow(ctx, "Receivers", log.Fields{"New": igc.NewReceivers, "Current": igc.CurReceivers})
	logger.Debugw(ctx, "Receiver Group", log.Fields{"Igd GId": igc.GroupID})
	logger.Debugw(ctx, "Receiver Channel", log.Fields{"Igd addr": igc.GroupAddr})
	logger.Debugw(ctx, "Receiver Mvlan", log.Fields{"Igd mvlan": igc.Mvlan})
	logger.Debugw(ctx, "Receiver Sources", log.Fields{"Igd addr": ip})

	ponPortID := GetApplication().GetPonPortID(igc.Device, port)

	// Process the IGMP receiver. If it is already in, we should only process the changes
	// to source list.
	var newRcvExists bool
	igp, newRcvExists = igc.NewReceivers[port]
	if !newRcvExists {
		// Add the receiver to the list of receivers and make the necessary group modification
		// if this is the first time the receiver is added
		var curRcvExists bool
		if igp, curRcvExists = igc.CurReceivers[port]; curRcvExists {
			logger.Debugw(ctx, "Existing IGMP receiver", log.Fields{"Group": igc.GroupAddr.String(), "Port": port})
			delete(igc.CurReceivers, port)
			igp.QueryTimeoutCount = 0
			igc.NewReceivers[port] = igp
		} else {
			// New receiver who wasn't part of earlier list
			// Need to send out IGMP group modification for this port
			igp = NewIgmpGroupPort(port, cvlan, pbit, igc.Version, incl, uint32(ponPortID))
			igc.NewReceivers[port] = igp
			isNewReceiver = true
			logger.Debugw(ctx, "New IGMP receiver", log.Fields{"Group": igc.GroupAddr.String(), "Port": port})
			if len(igc.NewReceivers) == 1 && len(igc.CurReceivers) == 0 {
				groupModified = true
				igc.AddMcFlow()
				logger.Debugw(ctx, "Added New Flow", log.Fields{"Group": igc.GroupAddr.String(), "Port": port})
			}
			if !incl {
				igc.Exclude++
			}
		}
	}

	// Process the include/exclude list which may end up modifying the group
	if change, _ := igc.ProcessSources(port, ip, incl); change {
		groupModified = true
	}
	igc.ProcessMode(port, incl)

	// If the group is modified as this is the first receiver or due to include/exclude list modification
	// send a report to the upstream multicast servers
	if groupModified {
		logger.Debug(ctx, "Group Modified and IGMP report sent to the upstream server")
		igc.SendReport(false)
	} else if newRcvExists {
		return false
	}

	logger.Debugw(ctx, "Channel Receiver Added", log.Fields{"Group Channel": igc.GroupAddr, "Group Port": igp})

	if err := igc.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	if err := igp.WriteToDb(igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
		logger.Errorw(ctx, "Igmp group port Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	return isNewReceiver
}

// DelReceiver is called when Query expiry happened for a receiver. This removes the receiver from the
// the group
func (igc *IgmpGroupChannel) DelReceiver(port string, incl bool, srcList []net.IP) bool {
	// The receiver may exist either in NewReceiver list or
	// the CurReceivers list. Find and remove it from either
	// of the lists.
	logger.Debugw(ctx, "Deleting Receiver from Channel", log.Fields{"Port": port, "SrcList": srcList, "Incl": incl})
	logger.Debugw(ctx, "New Receivers", log.Fields{"New": igc.NewReceivers})
	logger.Debugw(ctx, "Current Receivers", log.Fields{"Current": igc.CurReceivers})

	receiversUpdated := false
	groupModified, receiverSrcListEmpty := igc.ProcessSources(port, srcList, incl)

	if len(srcList) == 0 || len(igc.IncludeList) == 0 || receiverSrcListEmpty {
		if igp, ok := igc.NewReceivers[port]; ok {
			logger.Debug(ctx, "Deleting from NewReceivers")
			delete(igc.NewReceivers, port)
			receiversUpdated = true
			if igp.Exclude {
				igc.Exclude--
			}
		} else {
			if igp, ok1 := igc.CurReceivers[port]; ok1 {
				logger.Debug(ctx, "Deleting from CurReceivers")
				delete(igc.CurReceivers, port)
				receiversUpdated = true
				if igp.Exclude {
					igc.Exclude--
				}
			} else {
				logger.Debug(ctx, "Receiver doesnot exist. Dropping Igmp leave")
				return false
			}
		}
		_ = db.DelIgmpRcvr(igc.Mvlan, igc.GroupAddr, igc.Device, port)
	}

	if igc.NumReceivers() == 0 {
		igc.DelMcFlow()
		mvp := GetApplication().GetMvlanProfileByTag(igc.Mvlan)
		/* If proxy is configured and NumReceivers is 0, then we can reset the igc src list so that we send leave */
		if _, ok := mvp.Proxy[igc.GroupName]; ok {
			igc.IncludeList = []net.IP{}
		}
		igc.SendLeaveToServer()
		logger.Debugw(ctx, "Deleted the receiver Flow", log.Fields{"Num Receivers": igc.NumReceivers()})
		return true
	}
	if groupModified {
		igc.SendReport(false)
		logger.Infow(ctx, "Updated SourceList for Channel", log.Fields{"Current": igc.CurReceivers, "New": igc.NewReceivers})
	}
	if err := igc.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	logger.Infow(ctx, "Updated Receiver info for Channel", log.Fields{"Current": igc.CurReceivers, "New": igc.NewReceivers})

	return receiversUpdated
}

// NumReceivers to get number of receivers
func (igd *IgmpGroupDevice) NumReceivers() int {
	var numReceivers int
	len := func(key interface{}, value interface{}) bool {
		numReceivers++
		return true
	}
	igd.PortChannelMap.Range(len)
	return numReceivers
}

// DelReceiver is called when Query expiry happened for a receiver. This removes the receiver from the
// the group
func (igd *IgmpGroupDevice) DelReceiver(groupAddr net.IP, port string, group *layers.IGMPv3GroupRecord, ponPortID uint32) {

	logger.Debugw(ctx, "Deleting Receiver for Device", log.Fields{"port": port, "GroupIP": groupAddr.String()})
	var igc *IgmpGroupChannel
	var igcIntf interface{}
	var ok bool
	var srcList []net.IP
	incl := false
	mvp := GetApplication().GetMvlanProfileByTag(igd.Mvlan)

	if _, ok := mvp.Proxy[igd.GroupName]; ok {
		incl = true
	} else if group != nil {
		srcList = group.SourceAddresses
		incl = isIncl(group.Type)
	}

	if igcIntf, ok = igd.GroupChannels.Load(groupAddr.String()); !ok {
		logger.Warnw(ctx, "Igmp Channel for group IP doesnt exist", log.Fields{"GroupAddr": groupAddr.String()})
		return
	}
	igc = igcIntf.(*IgmpGroupChannel)
	if ok := igc.DelReceiver(port, incl, srcList); !ok {
		return
	}

	if igc.NumReceivers() == 0 {
		igd.DelIgmpGroupChannel(igc)
	}
	igd.DelPortFromChannel(port, groupAddr)
	isGroupModified := igd.RemoveChannelFromChannelsPerPon(port, groupAddr, ponPortID)

	//Remove port from receiver if port has no subscription to any of the group channels
	if isGroupModified {
		igd.ModMcGroup()
	}
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
}

// DelChannelReceiver is called when Query expiry happened for a receiver. This removes the receiver from the
// the group
func (igd *IgmpGroupDevice) DelChannelReceiver(groupAddr net.IP) map[string]*IgmpGroupPort {

	portsRemoved := make(map[string]*IgmpGroupPort)
	groupModified := false
	// ifEmpty := true
	igcIntf, _ := igd.GroupChannels.Load(groupAddr.String())

	if igcIntf == nil {
		return portsRemoved
	}
	igc := igcIntf.(*IgmpGroupChannel)

	for port, igp := range igc.NewReceivers {
		_ = db.DelIgmpRcvr(igc.Mvlan, igc.GroupAddr, igc.Device, port) //TODO: Y not here
		igd.DelPortFromChannel(port, igc.GroupAddr)
		ponPortID := GetApplication().GetPonPortID(igd.Device, port)
		groupModified = igd.RemoveChannelFromChannelsPerPon(port, igc.GroupAddr, ponPortID)
		delete(igc.NewReceivers, port)
		portsRemoved[port] = igp
	}
	for port, igp := range igc.CurReceivers {
		_ = db.DelIgmpRcvr(igc.Mvlan, igc.GroupAddr, igc.Device, port)
		igd.DelPortFromChannel(port, igc.GroupAddr)
		ponPortID := GetApplication().GetPonPortID(igd.Device, port)
		groupModified = igd.RemoveChannelFromChannelsPerPon(port, igc.GroupAddr, ponPortID)
		delete(igc.CurReceivers, port)
		portsRemoved[port] = igp
	}

	igc.DelMcFlow()
	igd.DelIgmpGroupChannel(igc)
	igc.Exclude = 0
	igc.SendLeaveToServer()

	if groupModified {
		igd.ModMcGroup()
	}
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
	logger.Debugw(ctx, "Deleted the receiver Flow", log.Fields{"Num Receivers": igc.NumReceivers()})
	return portsRemoved
}

// DelIgmpGroupChannel to delete igmp group channel
func (igd *IgmpGroupDevice) DelIgmpGroupChannel(igc *IgmpGroupChannel) {

	if igc.NumReceivers() != 0 {
		igc.DelAllReceivers()
	}
	_ = db.DelIgmpChannel(igc.Mvlan, igc.GroupName, igc.Device, igc.GroupAddr)
	igd.GroupChannels.Delete(igc.GroupAddr.String())
	logger.Infow(ctx, "Deleted the Channel from Device", log.Fields{"Channel": igc.GroupAddr.String()})
	isLenZero := true
	checkIfEmpty := func(key interface{}, value interface{}) bool {
		isLenZero = false
		return false
	}
	igd.GroupChannels.Range(checkIfEmpty)
	if isLenZero {
		logger.Infow(ctx, "No more active channels. Deleting MC Group", log.Fields{"Device": igd.Device, "Group": igd.GroupName})
		igd.DelMcGroup(false)
	}
}

// func (igd *IgmpGroupDevice) DelIgmpChannel(igc *IgmpGroupChannel) {
// 	db.DelIgmpChannel(igc.GroupName, igc.Device, igc.GroupAddr)
// 	delete(igd.GroupChannels, igc.GroupAddr.String())
// 	logger.Debugw(ctx, "Deleted the Channel", log.Fields{"Num Receivers": igc.NumReceivers()})
// }

// DelPortFromChannel to delete port from channel
func (igd *IgmpGroupDevice) DelPortFromChannel(port string, groupAddr net.IP) bool {
	ipsList := []net.IP{}
	ipsListIntf, _ := igd.PortChannelMap.Load(port)
	if ipsListIntf != nil {
		ipsList = ipsListIntf.([]net.IP)
	}
	for i, addr := range ipsList {
		if addr.Equal(groupAddr) {
			ipsList = append(ipsList[:i], ipsList[i+1:]...)
			//Remove port from receiver if port has no subscription to any of the group channels
			if len(ipsList) == 0 {
				igd.PortChannelMap.Delete(port)
			} else {
				//Update the map with modified ips list
				igd.PortChannelMap.Store(port, ipsList)
			}
			logger.Debugw(ctx, "Port Channel Updated", log.Fields{"Port": port, "DelChannelList": ipsList, "Addr": groupAddr.String()})
			return true
		}
	}
	return false
}

// DelIgmpGroup deletes all devices for the provided igmp group
func (ig *IgmpGroup) DelIgmpGroup() {
	logger.Infow(ctx, "Deleting All Device for Group", log.Fields{"Group": ig.GroupName})
	for _, igd := range ig.Devices {
		ig.DelIgmpGroupDevice(igd)
	}
	GetApplication().DelIgmpGroup(ig)
}

// DelAllChannels deletes all receiver for the provided igmp device
func (igd *IgmpGroupDevice) DelAllChannels() {
	logger.Infow(ctx, "Deleting All Channel for Device", log.Fields{"Device": igd.Device, "Group": igd.GroupName})
	delGroupChannels := func(key interface{}, value interface{}) bool {
		igc := value.(*IgmpGroupChannel)
		igd.DelIgmpGroupChannel(igc)
		return true
	}
	igd.GroupChannels.Range(delGroupChannels)
}

// DelAllReceivers deletes all receiver for the provided igmp device
func (igc *IgmpGroupChannel) DelAllReceivers() {
	logger.Infow(ctx, "Deleting All Receiver for Channel", log.Fields{"Device": igc.Device, "Channel": igc.GroupAddr.String()})
	_ = db.DelAllIgmpRcvr(igc.Mvlan, igc.GroupAddr, igc.Device)
	igc.Exclude = 0
	igc.DelMcFlow()
	igc.SendLeaveToServer()
	logger.Infow(ctx, "MC Flow deleted and Leave sent", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device})
}

// ProcessQuery process query received from the upstream IGMP server
func (igd *IgmpGroupDevice) ProcessQuery(groupAddr net.IP, ver uint8) {
	logger.Debugw(ctx, "Received Query From Server", log.Fields{"Version": ver})
	if ver != *igd.ServVersion {
		igd.ServVersionExpiry = time.Now().Add(time.Duration(2*igd.proxyCfg.KeepAliveInterval) * time.Second)
		*igd.ServVersion = ver
		mvp := GetApplication().GetMvlanProfileByTag(igd.Mvlan)
		if err := mvp.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": mvp.Name})
		}
	}
	if igc, ok := igd.GroupChannels.Load(groupAddr.String()); ok {
		igc.(*IgmpGroupChannel).SendReport(true)
		return
	}
	logger.Infow(ctx, "No Members for Channel. Dropping Igmp Query", log.Fields{"Group": igd.GroupName, "Channel": groupAddr.String()})
}

// Igmpv2ReportPacket build an IGMPv2 Report for the upstream servers
func (igc *IgmpGroupChannel) Igmpv2ReportPacket() ([]byte, error) {
	logger.Debugw(ctx, "Buidling IGMP version 2 Report", log.Fields{"Device": igc.Device})
	return IgmpReportv2Packet(igc.GroupAddr, igc.Mvlan, (*igc.proxyCfg).IgmpCos, **igc.IgmpProxyIP)
}

// Igmpv3ReportPacket build an IGMPv3 Report for the upstream servers
func (igc *IgmpGroupChannel) Igmpv3ReportPacket() ([]byte, error) {
	logger.Debugw(ctx, "Buidling IGMP version 3 Report", log.Fields{"Device": igc.Device, "Exclude": igc.Exclude})
	if igc.Exclude > 0 {
		return Igmpv3ReportPacket(igc.GroupAddr, igc.Mvlan, (*igc.proxyCfg).IgmpCos, **igc.IgmpProxyIP, false, igc.ExcludeList)
	}
	return Igmpv3ReportPacket(igc.GroupAddr, igc.Mvlan, (*igc.proxyCfg).IgmpCos, **igc.IgmpProxyIP, true, igc.IncludeList)
}

// SendReport send a consolidated report to the server
func (igc *IgmpGroupChannel) SendReport(isQuery bool) {
	var report []byte
	var err error
	logger.Debugw(ctx, "Checking Version", log.Fields{"IGC Version": igc.Version, "Proxy Version": (*igc.proxyCfg).IgmpVerToServer,
		"Result": (getVersion((*igc.proxyCfg).IgmpVerToServer) == IgmpVersion2)})

	/**
	                               +------------------------------------------------------------------------+
	                               |         IGMP version(towards BNG) Configured at VGC                    |
	                               +-------------------------------+----------------------------------------+
	                               |                  v2           |                 v3                     |
	+===================+==========+===============================+========================================+
	| Received From RG  | V2 Join  | Process and Send as V2 to BNG | Process, Convert to v3 and Send to BNG |
	|                   |          |                               | Process, Send as v2, if the BNG is v2  |
	+===================+----------+-------------------------------+----------------------------------------+
	                    | V3 Join  | Process and Send as V2 to BNG | Process, Send v3 to BNG                |
	                    |          |                               | Process, Convert, Send as v2, if the   |
	                    |          |                               | BNG is v2                              |
	+===================+==========+===============================+========================================+
	| Received From BNG | V2 Query | V2 response to BNG            | V2 response to BNG                     |
	+===================+----------+-------------------------------+----------------------------------------+
	                    | V3 Query | Discard                       | V3 response to BNG                     |
	                    +==========+===============================+========================================+
	*/
	// igc.Version: 	igmp version received from RG.
	// igc.ServVersion: igmp version received from BNG or IgmpVerToServer present in proxy igmp conf.

	if isQuery && *igc.ServVersion == IgmpVersion3 && getVersion((*igc.proxyCfg).IgmpVerToServer) == IgmpVersion2 {
		// This is the last scenario where we must discard the query processing.
		logger.Debug(ctx, "Dropping query packet since the server verion is v3 but igmp proxy version is v2")
		return
	}

	if *igc.ServVersion == IgmpVersion2 || getVersion((*igc.proxyCfg).IgmpVerToServer) == IgmpVersion2 {
		report, err = igc.Igmpv2ReportPacket()
	} else {
		report, err = igc.Igmpv3ReportPacket()
	}
	if err != nil {
		logger.Warnw(ctx, "Error Preparing Report", log.Fields{"Device": igc.Device, "Ver": igc.Version, "Reason": err.Error()})
		return
	}
	nni, err := GetApplication().GetNniPort(igc.Device)
	if err == nil {
		_ = cntlr.GetController().PacketOutReq(igc.Device, nni, nni, report, false)
	} else {
		logger.Warnw(ctx, "Didn't find NNI port", log.Fields{"Device": igc.Device})
	}
}

// AddMcFlow adds flow to the device when the first receiver joins
func (igc *IgmpGroupChannel) AddMcFlow() {
	flow, err := igc.BuildMcFlow()
	if err != nil {
		logger.Warnw(ctx, "MC Flow Build Failed", log.Fields{"Reason": err.Error()})
		return
	}
	port, _ := GetApplication().GetNniPort(igc.Device)
	_ = cntlr.GetController().AddFlows(port, igc.Device, flow)
}

// DelMcFlow deletes flow from the device when the last receiver leaves
func (igc *IgmpGroupChannel) DelMcFlow() {
	flow, err := igc.BuildMcFlow()
	if err != nil {
		logger.Warnw(ctx, "MC Flow Build Failed", log.Fields{"Reason": err.Error()})
		return
	}
	flow.ForceAction = true
	device := GetApplication().GetDevice(igc.Device)

	if mvpIntf, _ := GetApplication().MvlanProfilesByTag.Load(igc.Mvlan); mvpIntf != nil {
		mvp := mvpIntf.(*MvlanProfile)
		err := mvp.DelFlows(device, flow)
		if err != nil {
			logger.Warnw(ctx, "Delering IGMP Flow for device failed ", log.Fields{"Device": device, "err": err})
		}
	}
}

// BuildMcFlow builds the flow using which it is added/deleted
func (igc *IgmpGroupChannel) BuildMcFlow() (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	//va := GetApplication()
	logger.Infow(ctx, "Building Mcast flow", log.Fields{"Mcast Group": igc.GroupAddr.String(), "Mvlan": igc.Mvlan.String()})
	uintGroupAddr := ipv4ToUint(igc.GroupAddr)
	subFlow := of.NewVoltSubFlow()
	subFlow.SetMatchVlan(igc.Mvlan)
	subFlow.SetIpv4Match()
	subFlow.SetMatchDstIpv4(igc.GroupAddr)
	mvp := GetApplication().GetMvlanProfileByTag(igc.Mvlan)
	//nni, err := va.GetNniPort(igc.Device)
	//if err != nil {
	//	return nil, err
	//}
	//inport, err := va.GetPortID(nni)
	//if err != nil {
	//	return nil, err
	//}
	//subFlow.SetInPort(inport)
	subFlow.SetOutGroup(igc.GroupID)
	cookiePort := uintGroupAddr
	subFlow.Cookie = uint64(cookiePort)<<32 | uint64(igc.Mvlan)
	subFlow.Priority = of.McFlowPriority
	metadata := uint64(mvp.PonVlan)
	subFlow.SetTableMetadata(metadata)

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built Mcast flow", log.Fields{"cookie": subFlow.Cookie, "subflow": subFlow})
	return flow, nil
}

//DelFlows - Triggers flow deletion after registering for flow indication event
func (mvp *MvlanProfile) DelFlows(device *VoltDevice, flow *of.VoltFlow) error {
	mvp.mvpFlowLock.Lock()
	defer mvp.mvpFlowLock.Unlock()

	var flowMap map[string]bool
	var ok bool

	for cookie := range flow.SubFlows {
		cookie := strconv.FormatUint(cookie, 10)
		fe := &FlowEvent{
			eType:     EventTypeMcastFlowRemoved,
			device:    device.Name,
			cookie:    cookie,
			eventData: mvp,
		}
		device.RegisterFlowDelEvent(cookie, fe)

		if flowMap, ok = mvp.PendingDeleteFlow[device.Name]; !ok {
			flowMap = make(map[string]bool)
		}
		flowMap[cookie] = true
		mvp.PendingDeleteFlow[device.Name] = flowMap
	}
	if err := mvp.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": mvp.Name})
	}
	return cntlr.GetController().DelFlows(device.NniPort, device.Name, flow)
}

//FlowRemoveSuccess - Process flow success indication
func (mvp *MvlanProfile) FlowRemoveSuccess(cookie string, device string) {
	mvp.mvpFlowLock.Lock()
	defer mvp.mvpFlowLock.Unlock()

	logger.Infow(ctx, "Mvlan Flow Remove Success Notification", log.Fields{"MvlanProfile": mvp.Name, "Cookie": cookie, "Device": device})

	if _, ok := mvp.PendingDeleteFlow[device]; ok {
		delete(mvp.PendingDeleteFlow[device], cookie)
	}

	if err := mvp.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": mvp.Name})
	}
}

//FlowRemoveFailure - Process flow failure indication
func (mvp *MvlanProfile) FlowRemoveFailure(cookie string, device string, errorCode uint32, errReason string) {

	mvp.mvpFlowLock.Lock()
	defer mvp.mvpFlowLock.Unlock()

	if flowMap, ok := mvp.PendingDeleteFlow[device]; ok {
		if _, ok := flowMap[cookie]; ok {
			logger.Errorw(ctx, "Mvlan Flow Remove Failure Notification", log.Fields{"MvlanProfile": mvp.Name, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason, "Device": device})
			return
		}
	}
	logger.Errorw(ctx, "Mvlan Flow Del Failure Notification for Unknown cookie", log.Fields{"MvlanProfile": mvp.Name, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason})

}

// AddMcGroup add the new group on the device when a receiver joins the group
func (igd *IgmpGroupDevice) AddMcGroup() {
	if !igd.GroupInstalled {
		group := &of.Group{}
		group.Command = of.GroupCommandAdd
		group.GroupID = igd.GroupID
		group.Device = igd.Device
		group.SetVlan = igd.PonVlan
		group.IsPonVlanPresent = igd.IsPonVlanPresent

		addbuckets := func(key interface{}, value interface{}) bool {
			port := key.(string)
			var portID uint32
			if d := GetApplication().GetDevice(group.Device); d != nil {
				GetApplication().portLock.Lock()
				p := d.GetPort(port)
				GetApplication().portLock.Unlock()
				portID = p.ID
			}
			//ponPortID := key.(uint32)
			if portID != 0xFF {
				group.Buckets = append(group.Buckets, portID)
			}
			return true
		}
		igd.PortChannelMap.Range(addbuckets)

		port, _ := GetApplication().GetNniPort(igd.Device)
		_ = cntlr.GetController().GroupUpdate(port, igd.Device, group)
		igd.GroupInstalled = true
	}
}

// ModMcGroup updates the group on the device when either a receiver leaves
// or joins the group
func (igd *IgmpGroupDevice) ModMcGroup() {
	if igd.GroupInstalled {
		group := &of.Group{}
		group.Command = of.GroupCommandMod
		group.GroupID = igd.GroupID
		group.Device = igd.Device
		group.SetVlan = igd.PonVlan
		group.IsPonVlanPresent = igd.IsPonVlanPresent

		addbuckets := func(key interface{}, value interface{}) bool {
                       port := key.(string)
                       var portID uint32
                       if d := GetApplication().GetDevice(group.Device); d != nil {
                               GetApplication().portLock.Lock()
                               p := d.GetPort(port)
                               GetApplication().portLock.Unlock()
                               portID = p.ID
                       }
                       //ponPortID := key.(uint32)
                       if portID != 0xFF {
                               group.Buckets = append(group.Buckets, portID)
			}
			return true
		}
		igd.PortChannelMap.Range(addbuckets)

		port, _ := GetApplication().GetNniPort(igd.Device)
		_ = cntlr.GetController().GroupUpdate(port, igd.Device, group)
	} else {
		logger.Warnw(ctx, "Update Group Failed. Group not yet created", log.Fields{"Igd": igd.Device})
	}
}

// DelMcGroup : The group is deleted when the last receiver leaves the group
func (igd *IgmpGroupDevice) DelMcGroup(forceDelete bool) {

	logger.Infow(ctx, "Delete Mc Group Request", log.Fields{"Device": igd.Device, "GroupID": igd.GroupID, "ForceFlag": forceDelete, "GroupInstalled": igd.GroupInstalled})
	/*
	if !forceDelete && !checkIfForceGroupRemove(igd.Device) {
		if success := AddToPendingPool(igd.Device, igd.getKey()); success {
			return
		}
	}*/
	if igd.GroupInstalled {
		logger.Debugw(ctx, "Deleting Group", log.Fields{"Device": igd.Device, "Id": igd.GroupID})
		group := &of.Group{}
		group.Command = of.GroupCommandDel
		group.GroupID = igd.GroupID
		group.Device = igd.Device
		group.ForceAction = true

		port, _ := GetApplication().GetNniPort(igd.Device)
		_ = cntlr.GetController().GroupUpdate(port, igd.Device, group)
		igd.GroupInstalled = false
	}
}

//AddToPendingPool - adds Igmp Device obj to pending pool
func AddToPendingPool(device string, groupKey string) bool {

	logger.Infow(ctx, "Add Device to IgmpGroup Pending Pool", log.Fields{"Device": device, "GroupKey": groupKey})
	if grp, ok := GetApplication().IgmpGroups.Load(groupKey); ok {
		ig := grp.(*IgmpGroup)
		ig.PendingPoolLock.Lock()
		logger.Infow(ctx, "Adding Device to IgmpGroup Pending Pool", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String()})
		ig.PendingGroupForDevice[device] = time.Now().Add(time.Duration(GroupExpiryTime) * time.Minute)
		ig.PendingPoolLock.Unlock()
		if err := ig.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
		}
		return true
	}
	return false
}

/*
func checkIfForceGroupRemove(device string) bool {
	if d := GetApplication().GetDevice(device); d != nil {
		if d.State == cntlr.DeviceStateREBOOTED || d.State == cntlr.DeviceStateDOWN {
			return true
		}
	}
	return false
}*/

// IgmpLeaveToServer sends IGMP leave to server. Called when the last receiver leaves the group
func (igc *IgmpGroupChannel) IgmpLeaveToServer() {
	if leave, err := IgmpLeavePacket(igc.GroupAddr, igc.Mvlan, (*igc.proxyCfg).IgmpCos, **igc.IgmpProxyIP); err == nil {
		nni, err1 := GetApplication().GetNniPort(igc.Device)
		if err1 == nil {
			_ = cntlr.GetController().PacketOutReq(igc.Device, nni, nni, leave, false)
		}
	}
}

// SendLeaveToServer delete the group when the last receiver leaves the group
func (igc *IgmpGroupChannel) SendLeaveToServer() {
	/**
	                               +-------------------------------------------------------------------------+
	                               |         IGMP version(towards BNG) Configured at VGC                     |
	                               +-------------------------------+-----------------------------------------+
	                               |                  v2           |                 v3                      |
	+===================+==========+===============================+=========================================+
	| Received From RG  | V2 Leave | Process and Send as V2 to BNG | Process, Convert to V3 and Send to BNG/ |
	|                   |          |                               | Process, Send as V2, if the BNG is V2   |
	+===================+----------+-------------------------------+-----------------------------------------+
	                    | V3 Leave | Process and Send as V2 to BNG | Process, Send V3 to BNG                 |
	                    |          |                               | Process, Convert, Send as V2, if the    |
	                    |          |                               | BNG is v2                               |
	                    +==========+===============================+=========================================+
	*/
	// igc.Version: 	igmp version received from RG.
	// igc.ServVersion: igmp version received from BNG or IgmpVerToServer present in proxy igmp conf.

	logger.Debugw(ctx, "Sending IGMP leave upstream", log.Fields{"Device": igc.Device})
	if *igc.ServVersion == IgmpVersion2 || getVersion((*igc.proxyCfg).IgmpVerToServer) == IgmpVersion2 {
		igc.IgmpLeaveToServer()
	} else {
		igc.SendReport(false)
	}
}

// QueryExpiry processes query expiry. Upon expiry, take stock of the situation
// add either retain/release the group based on number of receivers left
func (igd *IgmpGroupDevice) QueryExpiry() {
	logger.Debugw(ctx, "Query Expiry", log.Fields{"Device": igd.Device})


	// Delete the IGMP flow added for this port if port state is down or query count exceeded
	handleQueryExp := func(key interface{}, value interface{}) bool {
		igc := value.(*IgmpGroupChannel)
		for portKey, port := range igc.CurReceivers {

			if portKey == StaticPort {
				continue
			}

			logger.Warnw(ctx, "Expired Receiver Port", log.Fields{"PortKey": portKey, "IGP": port, "GroupAddr": igc.GroupAddr,
				"Count": port.QueryTimeoutCount})
			state, err := cntlr.GetController().GetPortState(igc.Device, portKey)
			logger.Debugw(ctx, "Expired Member Port State", log.Fields{"state": state})
			ponPortID := GetApplication().GetPonPortID(igd.Device, portKey)
			if err == nil && state == cntlr.PortStateDown {
				igd.DelReceiver(igc.GroupAddr, portKey, nil, ponPortID)
			}

			port.QueryTimeoutCount++
			logger.Debugw(ctx, "Expired Port TimeoutCount", log.Fields{"count": port.QueryTimeoutCount})
			if port.QueryTimeoutCount >= (*igc.proxyCfg).KeepAliveCount {
				logger.Errorw(ctx, "Expiry Timeout count exceeded. Trigger delete receiver", log.Fields{"PortKey": portKey,
					"GroupAddr": igc.GroupAddr, "Count": port.QueryTimeoutCount})
				igd.DelReceiver(igc.GroupAddr, portKey, nil, ponPortID)
				SendQueryExpiredEventGroupSpecific(portKey, igd, igc)
			} else {
				_ = port.WriteToDb(igc.Mvlan, igc.GroupAddr, igc.Device)
			}
		}
		return true
	}
	igd.GroupChannels.Range(handleQueryExp)
}

// SendQueryExpiredEventGroupSpecific to send group specific query expired event.
func SendQueryExpiredEventGroupSpecific(portKey string, igd *IgmpGroupDevice, igc *IgmpGroupChannel) {

	logger.Info(ctx, "Processing-SendQueryExpiredEventGroupSpecific-Event")
	va := GetApplication()
	mvpName := va.GetMvlanProfileByTag(igd.Mvlan).Name

	sendEvent := func(key interface{}, value interface{}) bool {
		if value.(*VoltService).IgmpEnabled && value.(*VoltService).MvlanProfileName == mvpName {
			logger.Debugw(ctx, "sending-query-expired-group-specific-event", log.Fields{"EventType": QueryExpiredGroupSpecific, "ServiceName": value.(*VoltService).Name})
		}
		return false
	}

	// Fetching service name to send with query expired event.
	vpvs, _ := va.VnetsByPort.Load(portKey)
	if vpvs == nil {
		logger.Errorw(ctx, "volt-port-vnet-is-nil", log.Fields{"vpvs": vpvs})
		return
	}

	for _, vpv := range vpvs.([]*VoltPortVnet) {
		vpv.services.Range(sendEvent)
	}
}

// GetMcastServiceForSubAlarm to get mcast service name for subscriber alarm.
func GetMcastServiceForSubAlarm(uniPort *VoltPort, mvp *MvlanProfile) string {

	var serviceName string
	mvpName := mvp.Name

	va := GetApplication()

	sendAlm := func(key interface{}, value interface{}) bool {
		if value.(*VoltService).IgmpEnabled && value.(*VoltService).MvlanProfileName == mvpName {
			serviceName = value.(*VoltService).Name
		}
		return true
	}

	// Fetching service name to send with active channels exceeded per subscriber alarm.
	vpvs, _ := va.VnetsByPort.Load(uniPort.Name)
	if vpvs == nil {
		logger.Errorw(ctx, "volt-port-vnet-is-nil", log.Fields{"vpvs": vpvs})
		return serviceName
	}

	for _, vpv := range vpvs.([]*VoltPortVnet) {
		vpv.services.Range(sendAlm)
	}

	return serviceName

}

// NumReceivers returns total number of receivers left on the group
func (igc *IgmpGroupChannel) NumReceivers() uint32 {
	return uint32(len(igc.CurReceivers) + len(igc.NewReceivers))
}

// SendQuery sends query to the receivers for counting purpose
func (igc *IgmpGroupChannel) SendQuery() {
	//var b []byte
	//var err error
	for portKey, port := range igc.NewReceivers {
		igc.CurReceivers[portKey] = port
	}

	igc.NewReceivers = make(map[string]*IgmpGroupPort)

	logger.Debugw(ctx, "Sending Query to receivers", log.Fields{"Receivers": igc.CurReceivers})
	for port, groupPort := range igc.CurReceivers {
		if port == StaticPort {
			continue
		}
		if queryPkt, err := igc.buildQuery(igc.GroupAddr, of.VlanType(groupPort.CVlan), groupPort.Pbit); err == nil {
			_ = cntlr.GetController().PacketOutReq(igc.Device, port, port, queryPkt, false)
			logger.Debugw(ctx, "Query Sent", log.Fields{"Device": igc.Device, "Port": port, "Packet": queryPkt})
		} else {
			logger.Warnw(ctx, "Query Creation Failed", log.Fields{"Reason": err.Error()})
		}
	}

}

// buildQuery to build query packet
func (igc *IgmpGroupChannel) buildQuery(groupAddr net.IP, cVlan of.VlanType, pbit uint8) ([]byte, error) {
	if igc.Version == IgmpVersion2 {
		return Igmpv2QueryPacket(igc.GroupAddr, cVlan, **igc.IgmpProxyIP, pbit, (*igc.proxyCfg).MaxResp)
	}
	return Igmpv3QueryPacket(igc.GroupAddr, cVlan, **igc.IgmpProxyIP, pbit, (*igc.proxyCfg).MaxResp)
}

// IgmpGroup implements a single MCIP that may have multiple receivers
// connected via multiple devices (OLTs). The IGMP group is stored on the
// VOLT application.
type IgmpGroup struct {
	GroupID               uint32
	Mvlan                 of.VlanType
	PonVlan               of.VlanType
	GroupName             string
	GroupAddr             net.IP
	Devices               map[string]*IgmpGroupDevice `json:"-"`
	PendingGroupForDevice map[string]time.Time        //map [deviceId, timestamp]  (ExpiryTime  = leave time + 15mins)
	Version               string
	IsPonVlanPresent      bool
	IsChannelBasedGroup   bool
	PendingPoolLock       sync.RWMutex
	IsGroupStatic         bool
	IgmpGroupLock         sync.RWMutex
}

// NewIgmpGroup is constructor for an IGMP group
func NewIgmpGroup(name string, vlan of.VlanType) *IgmpGroup {
	ig := IgmpGroup{}
	ig.GroupName = name
	ig.Mvlan = vlan
	ig.Devices = make(map[string]*IgmpGroupDevice)
	ig.PendingGroupForDevice = make(map[string]time.Time)
	return &ig
}

// IgmpGroupInit to initialize igmp group members
func (ig *IgmpGroup) IgmpGroupInit(name string, gip net.IP, mvp *MvlanProfile) {
	ig.GroupName = name
	ig.Mvlan = mvp.Mvlan
	ig.PonVlan = mvp.PonVlan
	ig.IsPonVlanPresent = mvp.IsPonVlanPresent
	ig.Devices = make(map[string]*IgmpGroupDevice)
	ig.PendingGroupForDevice = make(map[string]time.Time)
	ig.IsChannelBasedGroup = mvp.IsChannelBasedGroup
	ig.IsGroupStatic = mvp.Groups[name].IsStatic
	if ig.IsChannelBasedGroup {
		ig.GroupAddr = gip
	} else {
		ig.GroupAddr = net.ParseIP("0.0.0.0")
	}
}

// IgmpGroupReInit to re-initialize igmp group members
func (ig *IgmpGroup) IgmpGroupReInit(name string, gip net.IP) {

	logger.Infow(ctx, "Reinitialize Igmp Group", log.Fields{"GroupID": ig.GroupID, "OldName": ig.GroupName, "Name": name, "OldAddr": ig.GroupAddr.String(), "GroupAddr": gip.String()})

	ig.GroupName = name
	if ig.IsChannelBasedGroup {
		ig.GroupAddr = gip
	} else {
		ig.GroupAddr = net.ParseIP("0.0.0.0")
	}

	for _, igd := range ig.Devices {
		igd.IgmpGroupDeviceReInit(ig)
	}
}

// IsStaticGroup to check if group is static
func (mvp *MvlanProfile) IsStaticGroup(groupName string) bool {
	return mvp.Groups[groupName].IsStatic
}

// updateGroupName to update group name
func (ig *IgmpGroup) updateGroupName(newGroupName string) {
	if !ig.IsChannelBasedGroup {
		logger.Errorw(ctx, "Group name update not supported for GroupChannel based group", log.Fields{"Ig": ig})
		return
	}
	oldKey := ig.getKey()
	ig.GroupName = newGroupName
	for _, igd := range ig.Devices {
		igd.updateGroupName(newGroupName)
	}
	if err := ig.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
	}
	if !ig.IsChannelBasedGroup {
		_ = db.DelIgmpGroup(oldKey)
	}
}

//HandleGroupMigration - handles migration of group members between static & dynamic
func (ig *IgmpGroup) HandleGroupMigration(deviceID string, groupAddr net.IP) {

	var group *layers.IGMPv3GroupRecord
	app := GetApplication()
	if deviceID == "" {
		logger.Infow(ctx, "Handle Group Migration Request for all devices", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "IG": ig.GroupName, "Mvlan": ig.Mvlan})
		for device := range ig.Devices {
			ig.HandleGroupMigration(device, groupAddr)
		}
	} else {
		logger.Infow(ctx, "Handle Group Migration Request", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "IG": ig.GroupName})
		var newIg *IgmpGroup
		receivers := ig.DelIgmpChannel(deviceID, groupAddr)
		if ig.NumDevicesActive() == 0 {
			app.DelIgmpGroup(ig)
		}
		if newIg = app.GetIgmpGroup(ig.Mvlan, groupAddr); newIg == nil {
			logger.Infow(ctx, "IG Group doesn't exist, creating new group", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "IG": ig.GroupName, "Mvlan": ig.Mvlan})
			if newIg = app.AddIgmpGroup(app.GetMvlanProfileByTag(ig.Mvlan).Name, groupAddr, deviceID); newIg == nil {
				logger.Errorw(ctx, "Group Creation failed during group migration", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr})
				return
			}
		}
		mvp := app.GetMvlanProfileByTag(ig.Mvlan)
		isStaticGroup := mvp.IsStaticGroup(ig.GroupName)
		logger.Infow(ctx, "Existing receivers for old group", log.Fields{"Receivers": receivers})
		newIg.IgmpGroupLock.Lock()
		for port, igp := range receivers {
			if !isStaticGroup && port == StaticPort {
				continue
			}
			group = nil
			var reqType layers.IGMPv3GroupRecordType
			srcAddresses := []net.IP{}
			if igp.Version == IgmpVersion3 {
				if igp.Exclude {
					srcAddresses = append(srcAddresses, igp.ExcludeList...)
					reqType = layers.IGMPIsEx
				} else {
					srcAddresses = append(srcAddresses, igp.IncludeList...)
					reqType = layers.IGMPIsIn
				}
				group = &layers.IGMPv3GroupRecord{
					SourceAddresses: srcAddresses,
					Type:            reqType,
				}
			}
			logger.Infow(ctx, "Adding receiver to new group", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "newIg": newIg.GroupName, "IGP": igp})
			ponPort := GetApplication().GetPonPortID(deviceID, port)
			newIg.AddReceiver(deviceID, port, groupAddr, group, igp.Version, igp.CVlan, igp.Pbit, ponPort)
		}
		newIg.IgmpGroupLock.Unlock()
	}
}

// AddIgmpGroupDevice add a device to the group which happens when the first receiver of the device
// is added to the IGMP group.
func (ig *IgmpGroup) AddIgmpGroupDevice(device string, id uint32, version uint8) *IgmpGroupDevice {
	logger.Infow(ctx, "Adding Device to IGMP group", log.Fields{"Device": device, "GroupName": ig.GroupName})
	igd := NewIgmpGroupDevice(device, ig, id, version)
	ig.Devices[device] = igd
	if err := igd.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
	return igd
}

// DelIgmpGroupDevice delete the device from the group which happens when we receive a leave or when
// there is not response for IGMP query from the receiver
func (ig *IgmpGroup) DelIgmpGroupDevice(igd *IgmpGroupDevice) {
	logger.Infow(ctx, "Deleting Device from IGMP group", log.Fields{"Device": igd.Device, "Name": ig.GroupName})
	va := GetApplication()
	countersToBeUpdated := false
	if igd.NumReceivers() != 0 {
		countersToBeUpdated = true
	}
	igd.DelAllChannels()

	//Clear all internal maps so that the groups can be reused
	igd.PortChannelMap.Range(func(key, value interface{}) bool {

		//Update the counters only if not already updated
		//(i.e) 1. In case of channel remove during Mvlan Update
		if countersToBeUpdated {
			port := key.(string)
			channelList := value.([]net.IP)
			ponPortID := va.GetPonPortID(igd.Device, port)

			for _, channel := range channelList {
				igd.RemoveChannelFromChannelsPerPon(port, channel, ponPortID)
			}
		}

		igd.PortChannelMap.Delete(key)
		return true
	})
	igd.PonPortChannelMap = util.NewConcurrentMap()

	if mcastCfg := va.GetMcastConfig(igd.SerialNo, va.GetMvlanProfileByTag(igd.Mvlan).Name); mcastCfg != nil {
		mcastCfg.IgmpGroupDevices.Delete(igd.GroupID)
		logger.Debugw(ctx, "Igd deleted from mcast config", log.Fields{"mvlan": mcastCfg.MvlanProfileID, "groupId": igd.GroupID})
	}
	if !igd.GroupInstalled {
		_ = db.DelIgmpDevice(igd.Mvlan, ig.GroupName, ig.GroupAddr, igd.Device)
		delete(ig.Devices, igd.Device)
	}
}

// AddReceiver delete the device from the group which happens when we receive a leave or when
// there is not response for IGMP query from the receiver
func (ig *IgmpGroup) AddReceiver(device string, port string, groupIP net.IP,
	group *layers.IGMPv3GroupRecord, ver uint8, cvlan uint16, pbit uint8, ponPort uint32) {

	logger.Debugw(ctx, "Adding Receiver", log.Fields{"Port": port})
	if igd, ok := ig.getIgmpGroupDevice(device); !ok {
		igd = ig.AddIgmpGroupDevice(device, ig.GroupID, ver)
		igd.AddReceiver(port, groupIP, group, ver, cvlan, pbit, ponPort)
	} else {
		logger.Infow(ctx, "IGMP Group Receiver", log.Fields{"IGD": igd.Device})
		igd.AddReceiver(port, groupIP, group, ver, cvlan, pbit, ponPort)
	}
}

func (ig *IgmpGroup) getIgmpGroupDevice(device string) (*IgmpGroupDevice, bool) {
	ig.PendingPoolLock.Lock()
	defer ig.PendingPoolLock.Unlock()

	if _, ok := ig.PendingGroupForDevice[device]; ok {
		logger.Infow(ctx, "Removing the IgmpGroupDevice from pending pool", log.Fields{"GroupID": ig.GroupID, "Device": device, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String()})
		delete(ig.PendingGroupForDevice, device)
		if err := ig.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
		}
	}
	igd, ok := ig.Devices[device]
	return igd, ok
}

// DelReceiveronDownInd deletes a receiver which is the combination of device (OLT)
// and port on Port Down event
func (ig *IgmpGroup) DelReceiveronDownInd(device string, port string, ponPortID uint32) {
	logger.Debugw(ctx, "Deleting Receiver for Group", log.Fields{"Device": device, "port": port})

	mvp := GetApplication().GetMvlanProfileByTag(ig.Mvlan)
	mvp.mvpLock.RLock()
	defer mvp.mvpLock.RUnlock()
	igd, ok := ig.Devices[device]
	if !ok {
		logger.Infow(ctx, "IGMP Group device was not found for ", log.Fields{"Device": device})
		return
	}
	ipsList := []net.IP{}
	ipsListIntf, ok := igd.PortChannelMap.Load(port)
	if ok {
		ipsList = append(ipsList, ipsListIntf.([]net.IP)...)
	}
	logger.Infow(ctx, "Port Channel List", log.Fields{"Port": port, "IPsList": ipsList})
	igd.PortChannelMap.Range(printPortChannel)


	for _, groupAddr := range ipsList {
		logger.Debugw(ctx, "Port Channels", log.Fields{"Port": port, "IPsList": ipsList, "GroupAddr": groupAddr, "Len": len(ipsList)})
		igd.DelReceiver(groupAddr, port, nil, ponPortID)
	}

	if igd.NumReceivers() == 0 {
		ig.DelIgmpGroupDevice(igd)
	}
}

// DelReceiver deletes a receiver which is the combination of device (OLT)
// and port
func (ig *IgmpGroup) DelReceiver(device string, port string, groupAddr net.IP, group *layers.IGMPv3GroupRecord, ponPortID uint32) {
	logger.Debugw(ctx, "Deleting Receiver for Group", log.Fields{"Device": device, "port": port, "GroupIP": groupAddr.String()})
	if igd, ok := ig.Devices[device]; ok {
		//igd.DelReceiverForGroupAddr(groupAddr, port)
		igd.DelReceiver(groupAddr, port, group, ponPortID)
		if igd.NumReceivers() == 0 {
			ig.DelIgmpGroupDevice(igd)
		}
	}
}

// GetAllIgmpChannelForDevice - Returns all channels with active members associated to the Igmp Group for the given device
func (ig *IgmpGroup) GetAllIgmpChannelForDevice(deviceID string) map[string]string {

	if deviceID == "" {
		return ig.GetAllIgmpChannel()
	}

	allChannels := make(map[string]string)
	igd := ig.Devices[deviceID]
	getAllChannels := func(key interface{}, value interface{}) bool {
		channels := key.(string)
		allChannels[channels] = channels //same value as only key is required
		return true
	}
	igd.GroupChannels.Range(getAllChannels)

	return allChannels
}

// GetAllIgmpChannel - Returns all channels with active members associated to the Igmp Group
func (ig *IgmpGroup) GetAllIgmpChannel() map[string]string {
	allChannels := make(map[string]string)
	for _, igd := range ig.Devices {
		getAllChannels := func(key interface{}, value interface{}) bool {
			channels := key.(string)
			allChannels[channels] = channels
			return true
		}
		igd.GroupChannels.Range(getAllChannels)
	}
	return allChannels
}

// DelIgmpChannel deletes all receivers for the provided igmp group channel for the given device
func (ig *IgmpGroup) DelIgmpChannel(deviceID string, groupAddr net.IP) map[string]*IgmpGroupPort {
	logger.Infow(ctx, "Deleting Channel from devices", log.Fields{"Device": deviceID, "Group": ig.GroupName, "Channel": groupAddr.String()})
	if deviceID == "" {
		for device := range ig.Devices {
			ig.DelIgmpChannel(device, groupAddr)
		}
		return nil
	}
	igd := ig.Devices[deviceID]
	receivers := igd.DelChannelReceiver(groupAddr)
	if igd.NumReceivers() == 0 {
		ig.DelIgmpGroupDevice(igd)
	}
	return receivers
}

// IsNewReceiver checks if the received port is new receiver or existing one.
// Returns true if new receiver.
func (ig *IgmpGroup) IsNewReceiver(device, uniPortID string, groupAddr net.IP) bool {
	if ig == nil {
		// IGMP group does not exists. So considering it as new receiver.
		return true
	}
	logger.Debugw(ctx, "IGMP Group", log.Fields{"channel": groupAddr, "groupName": ig.GroupName}) // TODO: Remove me
	igd, exists := ig.Devices[device]
	if !exists || !igd.GroupInstalled {
		// IGMP group not exists OR Group is not created in the device.
		// So this is a new receiver.
		logger.Debugw(ctx, "igd not exists or group is not created in device", log.Fields{"exists": exists}) // TODO: Remove me
		return true
	}
	if igc, ok := igd.GroupChannels.Load(groupAddr.String()); ok {
		logger.Debugw(ctx, "IGMP Channel receivers", log.Fields{"igc-receivers": igc.(*IgmpGroupChannel).CurReceivers}) // TODO: Remove me
		_, rcvrExistCur := igc.(*IgmpGroupChannel).CurReceivers[uniPortID]
		_, rcvrExistNew := igc.(*IgmpGroupChannel).NewReceivers[uniPortID]
		if rcvrExistCur || rcvrExistNew {
			// Existing receiver
			return false
		}
	}
	return true
}

// Tick for Addition of groups to an MVLAN profile
func (ig *IgmpGroup) Tick() {
	now := time.Now()
	for _, igd := range ig.Devices {
		var igdChangeCnt uint8

		if _, ok := GetApplication().DevicesDisc.Load(igd.Device); !ok {
			logger.Info(ctx, "Skipping Query and Expiry check since Device is unavailable")
			continue
		}
		if now.After(igd.NextQueryTime) {
			// Set the next query time and the query expiry time to
			// KeepAliveInterval and MaxResp seconds after current time
			igd.NextQueryTime = now.Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)
			igd.QueryExpiryTime = now.Add(time.Duration(igd.proxyCfg.MaxResp) * time.Second)
			logger.Debugw(ctx, "Query Start", log.Fields{"NextQuery": igd.NextQueryTime, "Expiry": igd.QueryExpiryTime})
			igdChangeCnt++
			logger.Debugw(ctx, "Sending Query to device", log.Fields{"Device": igd.Device})
			sendQueryForAllChannels := func(key interface{}, value interface{}) bool {
				igc := value.(*IgmpGroupChannel)
				//TODO - Do generic query to avoid multiple msgs
				igc.SendQuery()
				return true
			}
			igd.GroupChannels.Range(sendQueryForAllChannels)
		}
		if now.After(igd.QueryExpiryTime) {
			igd.QueryExpiry()
			// This will keep it quiet till the next query time and then
			// it will be reset to a value after the query initiation time
			igd.QueryExpiryTime = igd.NextQueryTime
			logger.Debugw(ctx, "Expiry", log.Fields{"NextQuery": igd.NextQueryTime, "Expiry": igd.QueryExpiryTime})
			igdChangeCnt++
			if igd.NumReceivers() == 0 {
				ig.DelIgmpGroupDevice(igd)
				continue
			}
		}

		igdChangeCnt += igd.Tick()

		if igdChangeCnt > 0 {
			if err := igd.WriteToDb(); err != nil {
				logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device,
							"GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
			}
		}
	}
}

// QueryExpiry processes expiry of query sent to the receivers. Up on
// expiry, process the consolidated response for each of the devices participating
// in the MC stream. When a device has no receivers, the device is deleted
// from the group.
func (ig *IgmpGroup) QueryExpiry() {
	for _, igd := range ig.Devices {
		if _, ok := GetApplication().DevicesDisc.Load(igd.Device); ok {
			igd.QueryExpiry()
			if igd.NumReceivers() == 0 {
				ig.DelIgmpGroupDevice(igd)
			}

		} else {
			logger.Info(ctx, "Skipping Expiry since Device is unavailable")
		}
	}
}

// Hash : The IGMP group hash is used to distribute the processing of timers so that
// the processing is spread across doesn't spike at one instant. This also
// ensures that there is sufficient responsiveness to other requests happening
// simultaneously.
func (ig *IgmpGroup) Hash() uint16 {
	mvp := GetApplication().GetMvlanProfileByTag(ig.Mvlan)

	if mvp == nil {
		return 0
	}

	mvp.mvpLock.RLock()
	defer mvp.mvpLock.RUnlock()
	group := mvp.Groups[ig.GroupName]

	//Case where mvlan update in-progress
	if group == nil || len(group.McIPs) == 0 {
		return 0
	}
	groupIP := group.McIPs[0]
	return uint16(groupIP[2])<<8 + uint16(groupIP[3])
}

// NumDevicesAll returns the number of devices (OLT) active on the IGMP group. When
// the last device leaves the IGMP group is removed. If this is not done,
// the number of IGMP groups only keep increasing and can impact CPU when
// the system runs for a very long duration
func (ig *IgmpGroup) NumDevicesAll() int {
	return len(ig.Devices)
}

// NumDevicesActive returns the number of devices (OLT) active on the IGMP group. When
// the last device leaves the IGMP group is removed. If this is not done,
// the number of IGMP groups only keep increasing and can impact CPU when
// the system runs for a very long duration
func (ig *IgmpGroup) NumDevicesActive() int {
	count := 0
	for _, igd := range ig.Devices {
		if igd.NumReceivers() == 0 && igd.GroupInstalled {
			continue
		}
		count++
	}
	return count
}

// NumReceivers to return receiver list
func (ig *IgmpGroup) NumReceivers() map[string]int {
	receiverList := make(map[string]int)
	for device, igd := range ig.Devices {
		receiverList[device] = igd.NumReceivers()
	}
	return receiverList
}

// RestoreDevices : IGMP group write to DB
func (ig *IgmpGroup) RestoreDevices() {

	ig.migrateIgmpDevices()
	devices, _ := db.GetIgmpDevices(ig.Mvlan, ig.GroupName, ig.GroupAddr)
	for _, device := range devices {
		b, ok := device.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		if igd, err := NewIgmpGroupDeviceFromBytes(b); err == nil {
			igd.PonPortChannelMap = util.NewConcurrentMap()
			// Update the proxy config pointers.
			var mcastCfg *McastConfig
			igd.proxyCfg, igd.IgmpProxyIP, mcastCfg = getIgmpProxyCfgAndIP(ig.Mvlan, igd.SerialNo)
			if mcastCfg != nil {
				mcastCfg.IgmpGroupDevices.Store(igd.GroupID, igd)
				logger.Debugw(ctx, "Igd added to mcast config", log.Fields{"mvlan": mcastCfg.MvlanProfileID, "groupId": igd.GroupID})
			}

			mvp := GetApplication().GetMvlanProfileByTag(igd.Mvlan)
			igd.ServVersion = mvp.IgmpServVersion[igd.SerialNo]

			// During vgc upgrade from old version, igd.NextQueryTime and igd.QueryExpiryTime will not be present in db.
			// hence they are initialized with current time offset.
			emptyTime := time.Time{}
			if emptyTime == igd.NextQueryTime {
				logger.Debugw(ctx, "VGC igd upgrade", log.Fields{"igd grp name": igd.GroupName})
				igd.NextQueryTime = time.Now().Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)
				igd.QueryExpiryTime = time.Now().Add(time.Duration(igd.proxyCfg.KeepAliveInterval) * time.Second)
				if err := igd.WriteToDb(); err != nil {
					logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device,
								"GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
				}
			}

			ig.Devices[igd.Device] = igd
			if ig.IsChannelBasedGroup {
				channel, _ := db.GetIgmpChannel(igd.Mvlan, igd.GroupName, igd.Device, igd.GroupAddr)
				igd.RestoreChannel([]byte(channel))
			} else {
				igd.RestoreChannels()
			}
			igd.PortChannelMap.Range(printPortChannel)
			logger.Infow(ctx, "Group Device Restored", log.Fields{"IGD": igd})
		} else {
			logger.Warnw(ctx, "Unable to decode device from database", log.Fields{"str": string(b)})
		}
	}
}

// getKey to return group key
func (ig *IgmpGroup) getKey() string {
	profile, ok := GetApplication().MvlanProfilesByTag.Load(ig.Mvlan)
	if ok {
		mvp := profile.(*MvlanProfile)
		return mvp.generateGroupKey(ig.GroupName, ig.GroupAddr.String())
	}
	return ""
}

/*
// getKey to return group key
func (igd *IgmpGroupDevice) getKey() string {
	profile, ok := GetApplication().MvlanProfilesByTag.Load(igd.Mvlan)
	if ok {
		mvp := profile.(*MvlanProfile)
		return mvp.generateGroupKey(igd.GroupName, igd.GroupAddr.String())
	}
	return ""
}*/

// generateGroupKey to generate group key
func (mvp *MvlanProfile) generateGroupKey(name string, ipAddr string) string {
	if mvp.IsChannelBasedGroup {
		return mvp.Mvlan.String() + "_" + ipAddr
	}
	return mvp.Mvlan.String() + "_" + name
}

// WriteToDb is utility to write Igmp Group Info to database
func (ig *IgmpGroup) WriteToDb() error {
	ig.Version = database.PresentVersionMap[database.IgmpGroupPath]
	b, err := json.Marshal(ig)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpGroup(ig.getKey(), string(b)); err1 != nil {
		return err1
	}
	return nil
}

// RestoreIgmpGroupsFromDb to restore igmp groups from database
func (va *VoltApplication) RestoreIgmpGroupsFromDb() {

	groups, _ := db.GetIgmpGroups()
	for _, group := range groups {
		b, ok := group.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var ig IgmpGroup
		err := json.Unmarshal(b, &ig)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of IGMP Group failed")
			continue
		}
		ig.Devices = make(map[string]*IgmpGroupDevice)

		//For Upgrade Case
		if len(ig.PendingGroupForDevice) == 0 {
			ig.PendingGroupForDevice = make(map[string]time.Time)
		}
		logger.Infow(ctx, "Restoring Groups", log.Fields{"igGroupID": ig.GroupID, "igGroupName": ig.GroupName, "igMvlan": ig.Mvlan})
		grpKey := ig.getKey()
		va.IgmpGroups.Store(grpKey, &ig)
		// Just delete and lose the IGMP group with the same group Id
		if _, err := va.GetIgmpGroupID(ig.GroupID); err != nil {
			logger.Warnw(ctx, "GetIgmpGroupID Failed", log.Fields{"igGroupID": ig.GroupID, "Error": err})
		}
		ig.RestoreDevices()

		if ig.NumDevicesActive() == 0 {
			va.AddGroupToPendingPool(&ig)
		}
		logger.Infow(ctx, "Restored Groups", log.Fields{"igGroupID": ig.GroupID, "igGroupName": ig.GroupName, "igMvlan": ig.Mvlan})
	}
}

// AddIgmpGroup : When the first IGMP packet is received, the MVLAN profile is identified
// for the IGMP group and grp obj is obtained from the available pending pool of groups.
// If not, new group obj will be created based on available group IDs
func (va *VoltApplication) AddIgmpGroup(mvpName string, gip net.IP, device string) *IgmpGroup {

	var ig *IgmpGroup
	if mvp, grpName := va.GetMvlanProfileForMcIP(mvpName, gip); mvp != nil {
		if ig = va.GetGroupFromPendingPool(mvp.Mvlan, device); ig != nil {
			logger.Infow(ctx, "Igmp Group obtained from global pending pool", log.Fields{"MvlanProfile": mvpName, "GroupID": ig.GroupID, "Device": device, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String()})
			oldKey := mvp.generateGroupKey(ig.GroupName, ig.GroupAddr.String())
			ig.IgmpGroupReInit(grpName, gip)
			ig.IsGroupStatic = mvp.Groups[grpName].IsStatic
			ig.UpdateIgmpGroup(oldKey, ig.getKey())
		} else {
			logger.Infow(ctx, "No Igmp Group available in global pending pool. Creating new Igmp Group", log.Fields{"MvlanProfile": mvpName, "Device": device, "GroupAddr": gip.String()})
			if ig = va.GetAvailIgmpGroupID(); ig == nil {
				logger.Error(ctx, "Igmp Group Creation Failed: Group Id Unavailable")
				return nil
			}
			ig.IgmpGroupInit(grpName, gip, mvp)
			grpKey := ig.getKey()
			va.IgmpGroups.Store(grpKey, ig)
		}
		if err := ig.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
		}
		return ig
	}
	logger.Error(ctx, "GetMvlan Pro failed", log.Fields{"Group": gip})
	return nil
}

// GetIgmpGroup helps search for the IGMP group from the list of
// active IGMP groups. For now, the assumption is that a group
// cannot belong to more than on MVLAN. If we change that definition,
// we have to take a relook at this implementation. The key will include
// both MVLAN and the group IP.
func (va *VoltApplication) GetIgmpGroup(mvlan of.VlanType, gip net.IP) *IgmpGroup {

	profile, _ := va.MvlanProfilesByTag.Load(mvlan)
	if profile == nil {
		logger.Errorw(ctx, "Mvlan Profile not found for incoming packet. Dropping Request", log.Fields{"Mvlan": mvlan, "GroupAddr": gip.String()})
		return nil
	}
	mvp := profile.(*MvlanProfile)
	_, gName := va.GetMvlanProfileForMcIP(mvp.Name, gip)
	grpKey := mvp.generateGroupKey(gName, gip.String())
	logger.Debugw(ctx, "Get IGMP Group", log.Fields{"Group": grpKey})
	igIntf, ok := va.IgmpGroups.Load(grpKey)
	if ok {
		logger.Debugw(ctx, "Get IGMP Group Success", log.Fields{"Group": grpKey})
		ig := igIntf.(*IgmpGroup)

		//Case: Group was part of pending and Join came with same channel or different channel from same group
		// (from same or different device)
		// In that case, the same group will be allocated since the group is still part of va.IgmpGroups
		// So, the groups needs to be removed from global pending pool
		va.RemoveGroupDevicesFromPendingPool(ig)
		return ig
	}
	return nil
}

// GetStaticGroupName to get static igmp group
func (mvp *MvlanProfile) GetStaticGroupName(gip net.IP) string {
	for _, mvg := range mvp.Groups {
		if mvg.IsStatic {
			if doesIPMatch(gip, mvg.McIPs) {
				return mvg.Name
			}
		}
	}
	return ""
}

// GetStaticIgmpGroup to get static igmp group
func (mvp *MvlanProfile) GetStaticIgmpGroup(gip net.IP) *IgmpGroup {

	staticGroupName := mvp.GetStaticGroupName(gip)
	grpKey := mvp.generateGroupKey(staticGroupName, gip.String())
	logger.Debugw(ctx, "Get Static IGMP Group", log.Fields{"Group": grpKey})
	ig, ok := GetApplication().IgmpGroups.Load(grpKey)
	if ok {
		logger.Debugw(ctx, "Get Static IGMP Group Success", log.Fields{"Group": grpKey})
		return ig.(*IgmpGroup)
	}
	return nil
}

// UpdateIgmpGroup : When the pending group is allocated to new
func (ig *IgmpGroup) UpdateIgmpGroup(oldKey, newKey string) {

	//If the group is allocated to same McastGroup, no need to update the
	//IgmpGroups map
	if oldKey == newKey {
		return
	}
	logger.Infow(ctx, "Updating Igmp Group with new MVP Group Info", log.Fields{"OldKey": oldKey, "NewKey": newKey, "GroupID": ig.GroupID})

	GetApplication().IgmpGroups.Delete(oldKey)
	_ = db.DelIgmpGroup(oldKey)

	GetApplication().IgmpGroups.Store(newKey, ig)
	if err := ig.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
	}
}

// DelIgmpGroup : When the last subscriber leaves the IGMP group across all the devices
// the IGMP group is removed.
func (va *VoltApplication) DelIgmpGroup(ig *IgmpGroup) {

	profile, found := GetApplication().MvlanProfilesByTag.Load(ig.Mvlan)
	if found {
		mvp := profile.(*MvlanProfile)

		grpKey := mvp.generateGroupKey(ig.GroupName, ig.GroupAddr.String())

		if igIntf, ok := va.IgmpGroups.Load(grpKey); ok {
			ig := igIntf.(*IgmpGroup)
			ig.IgmpGroupLock.Lock()
			if ig.NumDevicesAll() == 0 {
				logger.Debugw(ctx, "Deleting IGMP Group", log.Fields{"Group": grpKey})
				va.PutIgmpGroupID(ig)
				va.IgmpGroups.Delete(grpKey)
				_ = db.DelIgmpGroup(grpKey)
			} else {
				logger.Infow(ctx, "Skipping IgmpGroup Device. Pending Igmp Group Devices present", log.Fields{"GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String(), "PendingDevices": len(ig.Devices)})
				va.AddGroupToPendingPool(ig)
				if err := ig.WriteToDb(); err != nil {
					logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
				}
			}
			ig.IgmpGroupLock.Unlock()
		}

	}
}

// GetPonPortID Gets the PON port ID from uniPortID
func (va *VoltApplication) GetPonPortID(device, uniPortID string) uint32 {

	isNNI := strings.Contains(uniPortID, "nni")
	if isNNI || uniPortID == StaticPort {
		logger.Debugw(ctx, "Cannot get pon port from UNI port", log.Fields{"port": uniPortID})
		return 0xFF
	}
	dIntf, ok := va.DevicesDisc.Load(device)
	if !ok {
		return 0xFF
	}
	d := dIntf.(*VoltDevice)

	uniPort := d.GetPort(uniPortID)
	if uniPort == nil {
		return 0xFF
	}
	return GetPonPortIDFromUNIPort(uniPort.ID)
}

// AggActiveChannelsCountPerSub aggregates the active channel count for given uni port.
// It will iterate over all the groups and store the sum of active channels in VoltPort.
func (va *VoltApplication) AggActiveChannelsCountPerSub(device, uniPort string, port *VoltPort) {
	var activeChannelCount uint32

	collectActiveChannelCount := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		igd := ig.Devices[device]
		if igd == nil {
			return true
		}
		if portChannels, ok := igd.PortChannelMap.Load(uniPort); ok {
			channelList := portChannels.([]net.IP)
			activeChannelCount += uint32(len(channelList))
		}
		return true
	}
	va.IgmpGroups.Range(collectActiveChannelCount)

	logger.Debugw(ctx, "AggrActiveChannelCount for Subscriber",
		log.Fields{"UniPortID": uniPort, "count": activeChannelCount})

	port.ActiveChannels = activeChannelCount
}

// AggActiveChannelsCountForPonPort Aggregates the active channel count for given pon port.
// It will iterate over all the groups and store the sum of active channels in VoltDevice.
func (va *VoltApplication) AggActiveChannelsCountForPonPort(device string, ponPortID uint32, port *PonPortCfg) {

	var activeChannelCount uint32

	collectActiveChannelCount := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		igd := ig.Devices[device]
		if igd == nil {
			return true
		}
		if ponPortChannels, ok := igd.PonPortChannelMap.Get(ponPortID); ok {
			activeChannelCount += ponPortChannels.(*PonPortChannels).GetActiveChannelCount()
		}
		return true
	}
	va.IgmpGroups.Range(collectActiveChannelCount)

	logger.Debugw(ctx, "AggrActiveChannelCount for Pon Port",
		log.Fields{"PonPortID": ponPortID, "count": activeChannelCount})

	port.ActiveIGMPChannels = activeChannelCount
}

// UpdateActiveChannelCountForPonPort increments the global counter for active
// channel count per pon port.
func (va *VoltApplication) UpdateActiveChannelCountForPonPort(device, uniPortID string, ponPortID uint32, isAdd, isChannel bool, igd *IgmpGroupDevice) {
	incrDecr := func(value uint32) uint32 {
		if isAdd {
			return value + 1
		}
		return value - 1
	}
	if d, exists := va.DevicesDisc.Load(device); exists {
		voltDevice := d.(*VoltDevice)

		if isChannel {
			voltDevice.ActiveChannelCountLock.Lock()
			// If New channel is added/deleted, then only update the ActiveChannelsPerPon
			if value, ok := voltDevice.ActiveChannelsPerPon.Load(ponPortID); ok {
				port := value.(*PonPortCfg)
				port.ActiveIGMPChannels = incrDecr(port.ActiveIGMPChannels)
				voltDevice.ActiveChannelsPerPon.Store(ponPortID, port)
				logger.Debugw(ctx, "+++ActiveChannelsPerPon", log.Fields{"count": port.ActiveIGMPChannels}) // TODO: remove me
			}
			voltDevice.ActiveChannelCountLock.Unlock()
		}
		if uPort, ok := voltDevice.Ports.Load(uniPortID); ok {
			uniPort := uPort.(*VoltPort)
			uniPort.ActiveChannels = incrDecr(uniPort.ActiveChannels)
			voltDevice.Ports.Store(uniPortID, uniPort)
			logger.Debugw(ctx, "+++ActiveChannelsPerSub", log.Fields{"count": uniPort.ActiveChannels}) // TODO: remove me
		}
	}
}

// IsMaxChannelsCountExceeded checks if the PON port active channel
// capacity and subscriber level channel capacity is reached to max allowed
// channel per pon threshold. If Exceeds, return true else return false.
func (va *VoltApplication) IsMaxChannelsCountExceeded(device, uniPortID string,
	ponPortID uint32, ig *IgmpGroup, channelIP net.IP, mvp *MvlanProfile) bool {

	// New receiver check is required to identify the IgmpReportMsg received
	// in response to the IGMP Query sent from VGC.
	if newReceiver := ig.IsNewReceiver(device, uniPortID, channelIP); !newReceiver {
		logger.Debugw(ctx, "Not a new receiver. It is a response to IGMP Query",
			log.Fields{"port": uniPortID, "channel": channelIP})
		return false
	}

	if vDev, exists := va.DevicesDisc.Load(device); exists {
		voltDevice := vDev.(*VoltDevice)

		// Checking subscriber active channel count with maxChannelsAllowedPerSub
		if uniPort, present := voltDevice.Ports.Load(uniPortID); present {
			if uniPort.(*VoltPort).ActiveChannels >= mvp.MaxActiveChannels {
				logger.Errorw(ctx, "Max allowed channels per subscriber is exceeded",
					log.Fields{"activeCount": uniPort.(*VoltPort).ActiveChannels, "channel": channelIP, "UNI": uniPort.(*VoltPort).Name})
				if !(uniPort.(*VoltPort).ChannelPerSubAlarmRaised) {
					serviceName := GetMcastServiceForSubAlarm(uniPort.(*VoltPort), mvp)
					logger.Debugw(ctx, "Raising-SendActiveChannelPerSubscriberAlarm-Initiated", log.Fields{"ActiveChannels": uniPort.(*VoltPort).ActiveChannels, "ServiceName": serviceName})
					uniPort.(*VoltPort).ChannelPerSubAlarmRaised = true
				}
				return true
			}
		} else {
			logger.Errorw(ctx, "UNI port not found in VoltDevice", log.Fields{"uniPortID": uniPortID})
		}
		if value, ok := voltDevice.ActiveChannelsPerPon.Load(ponPortID); ok {
			ponPort := value.(*PonPortCfg)

			logger.Debugw(ctx, "----Active channels count for PON port",
				log.Fields{"PonPortID": ponPortID, "activeChannels": ponPort.ActiveIGMPChannels,
					"maxAllowedChannelsPerPon": ponPort.MaxActiveChannels})

			if ponPort.ActiveIGMPChannels < ponPort.MaxActiveChannels {
				// PON port active channel capacity is not yet reached to max allowed channels per pon.
				// So allowing to add receiver.
				return false
			} else if ponPort.ActiveIGMPChannels >= ponPort.MaxActiveChannels && ig != nil {
				// PON port active channel capacity is reached to max allowed channels per pon.
				// Check if same channel is already configured on that PON port.
				// If that channel is present, then allow AddReceiver else it will be rejected.
				igd, isPresent := ig.Devices[device]
				if isPresent {
					if channelListForPonPort, _ := igd.PonPortChannelMap.Get(ponPortID); channelListForPonPort != nil {
						if _, isExists := channelListForPonPort.(*PonPortChannels).ChannelList.Get(channelIP.String()); isExists {
							return false
						}
					}
				}
			}
			logger.Errorw(ctx, "Active channels count for PON port exceeded",
				log.Fields{"PonPortID": ponPortID, "activeChannels": ponPort.ActiveIGMPChannels, "channel": channelIP, "UNI": uniPortID})
		} else {
			logger.Warnw(ctx, "PON port level active channel count does not exists",
				log.Fields{"ponPortID": ponPortID})
			return false
		}
	}
	logger.Warnw(ctx, "Max allowed channels per pon threshold is reached", log.Fields{"PonPortID": ponPortID})
	return true
}

// ProcessIgmpv2Pkt : This is IGMPv2 packet.
func (va *VoltApplication) ProcessIgmpv2Pkt(device string, port string, pkt gopacket.Packet) {
	// First get the layers of interest
	dot1Q := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	pktVlan := of.VlanType(dot1Q.VLANIdentifier)
	igmpv2 := pkt.Layer(layers.LayerTypeIGMP).(*layers.IGMPv1or2)

	ponPortID := va.GetPonPortID(device, port)

	var vpv *VoltPortVnet

	logger.Debugw(ctx, "Received IGMPv2 Type", log.Fields{"Type": igmpv2.Type})

	if igmpv2.Type == layers.IGMPMembershipReportV2 || igmpv2.Type == layers.IGMPMembershipReportV1 {

		logger.Infow(ctx, "IGMP Join received: v2", log.Fields{"Addr": igmpv2.GroupAddress, "Port": port})

		// This is a report coming from the PON. We must be able to first find the
		// subscriber from the VLAN tag and port and verify if the IGMP proxy is
		// enabled for the subscriber
		vpv, _ = va.GetVnetFromPkt(device, port, pkt)

		if vpv == nil {
			logger.Errorw(ctx, "Couldn't find VNET associated with port", log.Fields{"Port": port})
			return
		} else if !vpv.IgmpEnabled {
			logger.Errorw(ctx, "IGMP is not activated on the port", log.Fields{"Port": port})
			return
		}

		mvp := va.GetMvlanProfileByName(vpv.MvlanProfileName)
		if mvp == nil {
			logger.Errorw(ctx, "Igmp Packet Received for Subscriber with Missing Mvlan Profile",
				log.Fields{"Receiver": vpv.Port, "MvlanProfile": vpv.MvlanProfileName})
			return
		}
		mvlan := mvp.Mvlan

		mvp.mvpLock.RLock()
		defer mvp.mvpLock.RUnlock()
		// The subscriber is validated and now process the IGMP report
		ig := va.GetIgmpGroup(mvlan, igmpv2.GroupAddress)

		if yes := va.IsMaxChannelsCountExceeded(device, port, ponPortID, ig, igmpv2.GroupAddress, mvp); yes {
			logger.Warnw(ctx, "Dropping IGMP Join v2: Active channel threshold exceeded",
				log.Fields{"PonPortID": ponPortID, "Addr": igmpv2.GroupAddress, "MvlanProfile": vpv.MvlanProfileName})
			return
		}
		if ig != nil {
			logger.Infow(ctx, "IGMP Group", log.Fields{"Group": ig.GroupID, "devices": ig.Devices})
			// If the IGMP group is already created. just add the receiver
			ig.IgmpGroupLock.Lock()
			// Check for port state to avoid race condition where PortDown event
			// acquired lock before packet processing
			vd := GetApplication().GetDevice(device)
			vp := vd.GetPort(port)
			if vp == nil || vp.State != PortStateUp {
				logger.Warnw(ctx, "Join received from a Port that is DOWN or not present",
						log.Fields{"Port": port})
				ig.IgmpGroupLock.Unlock()
				return
			}
			ig.AddReceiver(device, port, igmpv2.GroupAddress, nil, IgmpVersion2, dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
			ig.IgmpGroupLock.Unlock()
		} else {
			// Create the IGMP group and then add the receiver to the group
			if ig := va.AddIgmpGroup(vpv.MvlanProfileName, igmpv2.GroupAddress, device); ig != nil {
				logger.Infow(ctx, "New IGMP Group", log.Fields{"Group": ig.GroupID, "devices": ig.Devices})
				ig.IgmpGroupLock.Lock()
				// Check for port state to avoid race condition where PortDown event
				// acquired lock before packet processing
				vd := GetApplication().GetDevice(device)
				vp := vd.GetPort(port)
				if vp == nil || vp.State != PortStateUp {
					logger.Warnw(ctx, "Join received from a Port that is DOWN or not present",
							log.Fields{"Port": port})
					ig.IgmpGroupLock.Unlock()
					return
				}
				ig.AddReceiver(device, port, igmpv2.GroupAddress, nil, IgmpVersion2, dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
				ig.IgmpGroupLock.Unlock()
			} else {
				logger.Errorw(ctx, "IGMP Group Creation Failed", log.Fields{"Addr": igmpv2.GroupAddress})
				return
			}
		}
	} else if igmpv2.Type == layers.IGMPLeaveGroup {
		// This is a IGMP leave coming from one of the receivers. We essentially remove the
		// the receiver.
		logger.Infow(ctx, "IGMP Leave received: v2", log.Fields{"Addr": igmpv2.GroupAddress, "Port": port})

		vpv, _ = va.GetVnetFromPkt(device, port, pkt)
		if vpv == nil {
			logger.Errorw(ctx, "Couldn't find VNET associated with port", log.Fields{"Port": port})
			return
		} else if !vpv.IgmpEnabled {
			logger.Errorw(ctx, "IGMP is not activated on the port", log.Fields{"Port": port})
			return
		}

		mvp := va.GetMvlanProfileByName(vpv.MvlanProfileName)
		mvp.mvpLock.RLock()
		defer mvp.mvpLock.RUnlock()
		mvlan := mvp.Mvlan
		// The subscriber is validated and now process the IGMP report
		if ig := va.GetIgmpGroup(mvlan, igmpv2.GroupAddress); ig != nil {
			ig.IgmpGroupLock.Lock()
			// Delete the receiver once the IgmpGroup is identified
			ig.DelReceiver(device, port, igmpv2.GroupAddress, nil, ponPortID)
			ig.IgmpGroupLock.Unlock()
			if ig.NumDevicesActive() == 0 {
				va.DelIgmpGroup(ig)
			}
		}
	} else {
		// This must be a query on the NNI port. However, we dont make that assumption.
		// Need to look for the IGMP group based on the VLAN in the packet as
		// the MVLAN

		//Check if mvlan profile exist for the incoming pkt vlan
		profile, _ := va.MvlanProfilesByTag.Load(pktVlan)
		if profile == nil {
			logger.Errorw(ctx, "Mvlan Profile not found for incoming packet. Dropping Request", log.Fields{"Mvlan": pktVlan})
			return
		}
		mvp := profile.(*MvlanProfile)
		mvp.mvpLock.RLock()
		defer mvp.mvpLock.RUnlock()

		if net.ParseIP("0.0.0.0").Equal(igmpv2.GroupAddress) {
			va.processIgmpQueries(device, pktVlan, IgmpVersion2)
		} else {
			if ig := va.GetIgmpGroup(pktVlan, igmpv2.GroupAddress); ig != nil {
				ig.IgmpGroupLock.Lock()
				igd, ok := ig.Devices[device]
				if ok {
					igd.ProcessQuery(igmpv2.GroupAddress, IgmpVersion2)
				} else {
					logger.Warnw(ctx, "IGMP Device not found", log.Fields{"Device": device, "Group": igmpv2.GroupAddress})
				}
				ig.IgmpGroupLock.Unlock()
			}
		}
	}
}

// ProcessIgmpv3Pkt : Process IGMPv3 packet
func (va *VoltApplication) ProcessIgmpv3Pkt(device string, port string, pkt gopacket.Packet) {
	// First get the layers of interest
	dot1QLayer := pkt.Layer(layers.LayerTypeDot1Q)

	if dot1QLayer == nil {
		logger.Error(ctx, "Igmp Packet Received without Vlan - Dropping pkt")
		return
	}
	dot1Q := dot1QLayer.(*layers.Dot1Q)
	pktVlan := of.VlanType(dot1Q.VLANIdentifier)
	igmpv3 := pkt.Layer(layers.LayerTypeIGMP).(*layers.IGMP)

	ponPortID := va.GetPonPortID(device, port)

	var vpv *VoltPortVnet
	logger.Debugw(ctx, "Received IGMPv3 Type", log.Fields{"Type": igmpv3.Type})

	if igmpv3.Type == layers.IGMPMembershipReportV3 {
		// This is a report coming from the PON. We must be able to first find the
		// subscriber from the VLAN tag and port and verify if the IGMP proxy is
		// enabled for the subscriber
		vpv, _ = va.GetVnetFromPkt(device, port, pkt)
		if vpv == nil {
			logger.Errorw(ctx, "Couldn't find VNET associated with port", log.Fields{"Port": port})
			return
		} else if !vpv.IgmpEnabled {
			logger.Errorw(ctx, "IGMP is not activated on the port", log.Fields{"Port": port})
			return
		}
		mvp := va.GetMvlanProfileByName(vpv.MvlanProfileName)
		if mvp == nil {
			logger.Errorw(ctx, "Igmp Packet received for Subscriber with Missing Mvlan Profile",
				log.Fields{"Receiver": vpv.Port, "MvlanProfile": vpv.MvlanProfileName})
			return
		}
		mvp.mvpLock.RLock()
		defer mvp.mvpLock.RUnlock()
		mvlan := mvp.Mvlan

		for _, group := range igmpv3.GroupRecords {

			isJoin := isIgmpJoin(group.Type, group.SourceAddresses)
			// The subscriber is validated and now process the IGMP report
			ig := va.GetIgmpGroup(mvlan, group.MulticastAddress)
			if isJoin {
				if yes := va.IsMaxChannelsCountExceeded(device, port, ponPortID, ig, group.MulticastAddress, mvp); yes {
					logger.Warnw(ctx, "Dropping IGMP Join v3: Active channel threshold exceeded",
						log.Fields{"PonPortID": ponPortID, "Addr": group.MulticastAddress, "MvlanProfile": vpv.MvlanProfileName})

					return
				}
				if ig != nil {
					// If the IGMP group is already created. just add the receiver
					logger.Infow(ctx, "IGMP Join received for existing group", log.Fields{"Addr": group.MulticastAddress, "Port": port})
					ig.IgmpGroupLock.Lock()
					// Check for port state to avoid race condition where PortDown event
					// acquired lock before packet processing
					vd := GetApplication().GetDevice(device)
					vp := vd.GetPort(port)
					if vp == nil || vp.State != PortStateUp {
						logger.Warnw(ctx, "Join received from a Port that is DOWN or not present",
								log.Fields{"Port": port})
						ig.IgmpGroupLock.Unlock()
						return
					}
					ig.AddReceiver(device, port, group.MulticastAddress, &group, IgmpVersion3,
						dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
					ig.IgmpGroupLock.Unlock()
				} else {
					// Create the IGMP group and then add the receiver to the group
					logger.Infow(ctx, "IGMP Join received for new group", log.Fields{"Addr": group.MulticastAddress, "Port": port})
					if ig := va.AddIgmpGroup(vpv.MvlanProfileName, group.MulticastAddress, device); ig != nil {
						ig.IgmpGroupLock.Lock()
						// Check for port state to avoid race condition where PortDown event
						// acquired lock before packet processing
						vd := GetApplication().GetDevice(device)
						vp := vd.GetPort(port)
						if vp == nil || vp.State != PortStateUp {
							logger.Warnw(ctx, "Join received from a Port that is DOWN or not present",
									log.Fields{"Port": port})
							ig.IgmpGroupLock.Unlock()
							return
						}
						ig.AddReceiver(device, port, group.MulticastAddress, &group, IgmpVersion3,
							dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
						ig.IgmpGroupLock.Unlock()
					} else {
						logger.Warnw(ctx, "IGMP Group Creation Failed", log.Fields{"Addr": group.MulticastAddress})
					}
				}
			} else if ig != nil {
				logger.Infow(ctx, "IGMP Leave received for existing group", log.Fields{"Addr": group.MulticastAddress, "Port": port})
				ig.IgmpGroupLock.Lock()
				ig.DelReceiver(device, port, group.MulticastAddress, &group, ponPortID)
				ig.IgmpGroupLock.Unlock()
				if ig.NumDevicesActive() == 0 {
					va.DelIgmpGroup(ig)
				}
			} else {
				logger.Warnw(ctx, "IGMP Leave received for unknown group", log.Fields{"Addr": group.MulticastAddress})
			}
		}
	} else {
		// This must be a query on the NNI port. However, we dont make that assumption.
		// Need to look for the IGMP group based on the VLAN in the packet as
		// the MVLAN

		//Check if mvlan profile exist for the incoming pkt vlan
		profile, _ := va.MvlanProfilesByTag.Load(pktVlan)
		if profile == nil {
			logger.Errorw(ctx, "Mvlan Profile not found for incoming packet. Dropping Request", log.Fields{"Mvlan": pktVlan})
			return
		}
		mvp := profile.(*MvlanProfile)
		mvp.mvpLock.RLock()
		defer mvp.mvpLock.RUnlock()

		if net.ParseIP("0.0.0.0").Equal(igmpv3.GroupAddress) {
			va.processIgmpQueries(device, pktVlan, IgmpVersion3)
		} else {
			if ig := va.GetIgmpGroup(pktVlan, igmpv3.GroupAddress); ig != nil {
				ig.IgmpGroupLock.Lock()
				igd, ok := ig.Devices[device]
				if ok {
					igd.ProcessQuery(igmpv3.GroupAddress, IgmpVersion3)
				} else {
					logger.Warnw(ctx, "IGMP Device not found", log.Fields{"Device": device, "Group": igmpv3.GroupAddress})
				}
				ig.IgmpGroupLock.Unlock()
			}
		}
	}
}

// processIgmpQueries to process the igmp queries
func (va *VoltApplication) processIgmpQueries(device string, pktVlan of.VlanType, version uint8) {
	// This is a generic query and respond with all the groups channels in currently being viewed.
	processquery := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		ig.IgmpGroupLock.Lock()
		if ig.Mvlan != pktVlan {
			ig.IgmpGroupLock.Unlock()
			return true
		}
		igd, ok := ig.Devices[device]
		if !ok {
			logger.Warnw(ctx, "IGMP Device not found", log.Fields{"Device": device})
			ig.IgmpGroupLock.Unlock()
			return true
		}
		processQueryForEachChannel := func(key interface{}, value interface{}) bool {
			groupAddr := key.(string)
			igd.ProcessQuery(net.ParseIP(groupAddr), version)
			return true
		}
		igd.GroupChannels.Range(processQueryForEachChannel)
		ig.IgmpGroupLock.Unlock()
		return true
	}
	va.IgmpGroups.Range(processquery)
}

// isIgmpJoin to check if it is igmp join
func isIgmpJoin(recordType layers.IGMPv3GroupRecordType, sourceAddr []net.IP) bool {
	var join = false

	if (layers.IGMPToEx == recordType) || (layers.IGMPIsEx == recordType) {
		join = true
	} else if layers.IGMPBlock == recordType {
		if len(sourceAddr) == 0 {
			join = true
		}
	} else if (layers.IGMPToIn == recordType) || (layers.IGMPIsIn == recordType) || (layers.IGMPAllow == recordType) {
		if len(sourceAddr) != 0 {
			join = true
		}
	}
	return join
}

func isIncl(recordType layers.IGMPv3GroupRecordType) bool {

	if (layers.IGMPToIn == recordType) || (layers.IGMPIsIn == recordType) || (layers.IGMPAllow == recordType) {
		return true
	}
	return false
}

// IgmpProcessPkt to process the IGMP packet received. The packet received brings along with it
// the port on which the packet is received and the device the port is in.
func (va *VoltApplication) IgmpProcessPkt(device string, port string, pkt gopacket.Packet) {
	igmpl := pkt.Layer(layers.LayerTypeIGMP)
	if igmpl == nil {
		logger.Error(ctx, "Invalid IGMP packet arrived as IGMP packet")
		return
	}
	if igmp, ok := igmpl.(*layers.IGMPv1or2); ok {
		// This is an IGMPv2 packet.
		logger.Debugw(ctx, "IGMPv2 Packet Received", log.Fields{"IPAddr": igmp.GroupAddress})
		va.ProcessIgmpv2Pkt(device, port, pkt)
		return
	}
	if igmpv3, ok := igmpl.(*layers.IGMP); ok {
		logger.Debugw(ctx, "IGMPv3 Packet Received", log.Fields{"NumOfGroups": igmpv3.NumberOfGroupRecords})
		va.ProcessIgmpv3Pkt(device, port, pkt)
	}
}

// IgmpPacketInd for igmp packet indication
func (va *VoltApplication) IgmpPacketInd(device string, port string, pkt gopacket.Packet) {
	pt := NewIgmpPacketTask(device, port, pkt)
	va.IgmpTasks.AddTask(pt)
}

// ------------------------------------------------------------
// MVLAN related implemnetation
//
// Each MVLAN is configured with groups of multicast IPs. The idea of
// groups is to be able to group some multicast channels into an individual
// PON group and have a unique multicast GEM port for that set. However, in
// the current implementation, the concept of grouping is not fully utilized.

// MvlanGroup structure
// A set of MC IPs form a group

// MCGroupProxy identifies source specific multicast(SSM) config.
type MCGroupProxy struct {
	// Mode represents source list include/exclude
	Mode common.MulticastSrcListMode
	// SourceList represents list of multicast server IP addresses.
	SourceList []net.IP
}

// MvlanGroup identifies MC group info
type MvlanGroup struct {
	Name     string
	Wildcard bool
	McIPs    []string
	IsStatic bool
}

// OperInProgress type
type OperInProgress uint8

const (
	// UpdateInProgress constant
	UpdateInProgress OperInProgress = 2
	// NoOp constant
	NoOp OperInProgress = 1
	// Nil constant
	Nil OperInProgress = 0
)

// MvlanProfile : A set of groups of MC IPs for a MVLAN profile. It is assumed that
// the MVLAN IP is not repeated within multiples groups and across
// MVLAN profiles. The first match is used up on search to lcoate the
// MVLAN profile for an MC IP
type MvlanProfile struct {
	Name                string
	Mvlan               of.VlanType
	PonVlan             of.VlanType
	Groups              map[string]*MvlanGroup
	Proxy               map[string]*MCGroupProxy
	Version             string
	IsPonVlanPresent    bool
	IsChannelBasedGroup bool
	DevicesList         map[string]OperInProgress //device serial number //here
	oldGroups           map[string]*MvlanGroup
	oldProxy            map[string]*MCGroupProxy
	MaxActiveChannels   uint32
	PendingDeleteFlow   map[string]map[string]bool
	DeleteInProgress    bool
	IgmpServVersion     map[string]*uint8
	mvpLock             sync.RWMutex
	mvpFlowLock         sync.RWMutex
}

// NewMvlanProfile is constructor for MVLAN profile.
func NewMvlanProfile(name string, mvlan of.VlanType, ponVlan of.VlanType, isChannelBasedGroup bool, OLTSerialNums []string, actChannelPerPon uint32) *MvlanProfile {
	var mvp MvlanProfile
	mvp.Name = name
	mvp.Mvlan = mvlan
	mvp.PonVlan = ponVlan
	mvp.mvpLock = sync.RWMutex{}
	mvp.Groups = make(map[string]*MvlanGroup)
	mvp.Proxy = make(map[string]*MCGroupProxy)
	mvp.DevicesList = make(map[string]OperInProgress)
	mvp.PendingDeleteFlow = make(map[string]map[string]bool)
	mvp.IsChannelBasedGroup = isChannelBasedGroup
	mvp.MaxActiveChannels = actChannelPerPon
	mvp.DeleteInProgress = false
	mvp.IgmpServVersion = make(map[string]*uint8)

	if (ponVlan != of.VlanNone) && (ponVlan != 0) {
		mvp.IsPonVlanPresent = true
	}
	return &mvp
}

// AddMvlanProxy for addition of groups to an MVLAN profile
func (mvp *MvlanProfile) AddMvlanProxy(name string, proxyInfo common.MulticastGroupProxy) {
	proxy := &MCGroupProxy{}
	proxy.Mode = proxyInfo.Mode
	proxy.SourceList = util.GetExpIPList(proxyInfo.SourceList)

	if _, ok := mvp.Proxy[name]; !ok {
		logger.Debugw(ctx, "Added MVLAN Proxy", log.Fields{"Name": name, "Proxy": proxy})
	} else {
		logger.Debugw(ctx, "Updated MVLAN Proxy", log.Fields{"Name": name, "Proxy": proxy})
	}
	if proxyInfo.IsStatic == common.IsStaticYes {
		mvp.Groups[name].IsStatic = true
	}
	mvp.Proxy[name] = proxy
}

// AddMvlanGroup for addition of groups to an MVLAN profile
func (mvp *MvlanProfile) AddMvlanGroup(name string, ips []string) {
	mvg := &MvlanGroup{}
	mvg.Name = name
	mvg.Wildcard = len(ips) == 0
	mvg.McIPs = ips
	mvg.IsStatic = false
	if _, ok := mvp.Groups[name]; !ok {
		logger.Debugw(ctx, "Added MVLAN Group", log.Fields{"VLAN": mvp.Mvlan, "Name": name, "mvg": mvg, "IPs": mvg.McIPs})
	} else {
		logger.Debugw(ctx, "Updated MVLAN Group", log.Fields{"VLAN": mvp.Mvlan, "Name": name})
	}
	mvp.Groups[name] = mvg
}

// GetUsMatchVlan provides mvlan for US Match parameter
func (mvp *MvlanProfile) GetUsMatchVlan() of.VlanType {
	if mvp.IsPonVlanPresent {
		return mvp.PonVlan
	}
	return mvp.Mvlan
}

// WriteToDb is utility to write Mvlan Profile Info to database
func (mvp *MvlanProfile) WriteToDb() error {

	if mvp.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Redis Update for MvlanProfile, MvlanProfile delete in progress", log.Fields{"Mvlan": mvp.Mvlan})
		return nil
	}

	mvp.Version = database.PresentVersionMap[database.MvlanPath]
	b, err := json.Marshal(mvp)
	if err != nil {
		return err
	}
	if err1 := db.PutMvlan(uint16(mvp.Mvlan), string(b)); err1 != nil {
		return err1
	}
	return nil
}

//isChannelStatic - Returns true if the given channel is part of static group in the Mvlan Profile
func (mvp *MvlanProfile) isChannelStatic(channel net.IP) bool {
	for _, mvg := range mvp.Groups {
		if mvg.IsStatic {
			if isChannelStatic := doesIPMatch(channel, mvg.McIPs); isChannelStatic {
				return true
			}
		}
	}
	return false
}

//containsStaticChannels - Returns if any static channels is part of the Mvlan Profile
func (mvp *MvlanProfile) containsStaticChannels() bool {
	for _, mvg := range mvp.Groups {
		if mvg.IsStatic && len(mvg.McIPs) != 0 {
			return true
		}
	}
	return false
}

//getAllStaticChannels - Returns all static channels in the Mvlan Profile
func (mvp *MvlanProfile) getAllStaticChannels() ([]net.IP, bool) {
	channelList := []net.IP{}
	containsStatic := false
	for _, mvg := range mvp.Groups {
		if mvg.IsStatic {
			staticChannels, _ := mvg.getAllChannels()
			channelList = append(channelList, staticChannels...)
		}
	}
	if len(channelList) > 0 {
		containsStatic = true
	}
	return channelList, containsStatic
}

//getAllOldGroupStaticChannels - Returns all static channels in the Mvlan Profile
func (mvp *MvlanProfile) getAllOldGroupStaticChannels() ([]net.IP, bool) {
	channelList := []net.IP{}
	containsStatic := false
	for _, mvg := range mvp.oldGroups {
		if mvg.IsStatic {
			staticChannels, _ := mvg.getAllChannels()
			channelList = append(channelList, staticChannels...)
		}
	}
	if len(channelList) > 0 {
		containsStatic = true
	}
	return channelList, containsStatic
}

//getAllChannels - Returns all channels in the Mvlan Profile
func (mvg *MvlanGroup) getAllChannels() ([]net.IP, bool) {
	channelList := []net.IP{}

	if mvg == nil || len(mvg.McIPs) == 0 {
		return []net.IP{}, false
	}

	grpChannelOrRange := mvg.McIPs
	for _, channelOrRange := range grpChannelOrRange {
		if strings.Contains(channelOrRange, "-") {
			var splits = strings.Split(channelOrRange, "-")
			ipStart := util.IP2LongConv(net.ParseIP(splits[0]))
			ipEnd := util.IP2LongConv(net.ParseIP(splits[1]))

			for i := ipStart; i <= ipEnd; i++ {
				channelList = append(channelList, util.Long2ipConv(i))
			}
		} else {
			channelList = append(channelList, net.ParseIP(channelOrRange))
		}
	}
	return channelList, true
}

//SetUpdateStatus - Sets profile update status for devices
func (mvp *MvlanProfile) SetUpdateStatus(serialNum string, status OperInProgress) {
	if serialNum != "" {
		mvp.DevicesList[serialNum] = status
		return
	}

	for srNo := range mvp.DevicesList {
		mvp.DevicesList[srNo] = status
	}
}

//isUpdateInProgress - checking is update is in progress for the mvlan profile
func (mvp *MvlanProfile) isUpdateInProgress() bool {

	for srNo := range mvp.DevicesList {
		if mvp.DevicesList[srNo] == UpdateInProgress {
			return true
		}
	}
	return false
}

//IsUpdateInProgressForDevice - Checks is Mvlan Profile update is is progress for the given device
func (mvp *MvlanProfile) IsUpdateInProgressForDevice(device string) bool {
	if vd := GetApplication().GetDevice(device); vd != nil {
		if mvp.DevicesList[vd.SerialNum] == UpdateInProgress {
			return true
		}
	}
	return false
}

// DelFromDb to delere mvlan from database
func (mvp *MvlanProfile) DelFromDb() {
	_ = db.DelMvlan(uint16(mvp.Mvlan))
}

// storeMvlansMap to store mvlan map
func (va *VoltApplication) storeMvlansMap(mvlan of.VlanType, name string, mvp *MvlanProfile) {
	va.MvlanProfilesByTag.Store(mvlan, mvp)
	va.MvlanProfilesByName.Store(name, mvp)
}

// deleteMvlansMap to delete mvlan map
func (va *VoltApplication) deleteMvlansMap(mvlan of.VlanType, name string) {
	va.MvlanProfilesByTag.Delete(mvlan)
	va.MvlanProfilesByName.Delete(name)
}

// RestoreMvlansFromDb to read from the DB and restore all the MVLANs
func (va *VoltApplication) RestoreMvlansFromDb() {
	mvlans, _ := db.GetMvlans()
	for _, mvlan := range mvlans {
		b, ok := mvlan.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var mvp MvlanProfile
		err := json.Unmarshal(b, &mvp)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of MVLAN failed")
			continue
		}
		va.storeMvlansMap(mvp.Mvlan, mvp.Name, &mvp)

		for srNo := range mvp.DevicesList {
			if mvp.IgmpServVersion[srNo] == nil {
				servVersion := IgmpVersion0
				mvp.IgmpServVersion[srNo] = &servVersion
			}
		}
		logger.Infow(ctx, "Restored Mvlan Profile", log.Fields{"MVPName": mvp.Name})
	}
}

// GetMvlanProfileByTag fetches MVLAN profile based on the MC VLAN
func (va *VoltApplication) GetMvlanProfileByTag(vlan of.VlanType) *MvlanProfile {
	if mvp, ok := va.MvlanProfilesByTag.Load(vlan); ok {
		return mvp.(*MvlanProfile)
	}
	return nil
}

// GetMvlanProfileByName fetches MVLAN profile based on the profile name.
func (va *VoltApplication) GetMvlanProfileByName(name string) *MvlanProfile {
	if mvp, ok := va.MvlanProfilesByName.Load(name); ok {
		return mvp.(*MvlanProfile)
	}
	return nil
}

//UpdateMvlanProfile - only channel groups be updated
func (va *VoltApplication) UpdateMvlanProfile(name string, vlan of.VlanType, groups map[string][]string, activeChannelCount int, proxy map[string]common.MulticastGroupProxy) error {

	mvpIntf, ok := va.MvlanProfilesByName.Load(name)
	if !ok {
		logger.Error(ctx, "Update Mvlan Failed: Profile does not exist")
		return errors.New("MVLAN profile not found")
	}
	mvp := mvpIntf.(*MvlanProfile)
	// check if groups are same then just update the OLTSerial numbers, push the config on new serial numbers

	existingGroup := mvp.Groups
	existingProxy := mvp.Proxy
	mvp.Groups = make(map[string]*MvlanGroup)
	mvp.Proxy = make(map[string]*MCGroupProxy)

	/* Need to protect groups and proxy write lock */
	mvp.mvpLock.Lock()
	for grpName, grpIPList := range groups {
		mvp.AddMvlanGroup(grpName, grpIPList)
	}
	for grpName, proxyInfo := range proxy {
		mvp.AddMvlanProxy(grpName, proxyInfo)
	}
	if _, ok := mvp.Groups[common.StaticGroup]; ok {
		if _, yes := mvp.Proxy[common.StaticGroup]; !yes {
			mvp.Groups[common.StaticGroup].IsStatic = true
		}
	}
	prevMaxActiveChannels := mvp.MaxActiveChannels
	if reflect.DeepEqual(mvp.Groups, existingGroup) && reflect.DeepEqual(mvp.Proxy, existingProxy) {
		logger.Info(ctx, "No change in groups config")
		if uint32(activeChannelCount) != mvp.MaxActiveChannels {
			mvp.MaxActiveChannels = uint32(activeChannelCount)
			if err := mvp.WriteToDb(); err != nil {
				logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
			}
			if prevMaxActiveChannels != mvp.MaxActiveChannels {
				mvp.UpdateActiveChannelSubscriberAlarm()
			}
		}
		mvp.mvpLock.Unlock()
		return nil
	}
	mvp.mvpLock.Unlock()
	mvp.MaxActiveChannels = uint32(activeChannelCount)

	// Status is maintained so that in the event of any crash or reboot during update,
	// the recovery is possible once the pod is UP again
	mvp.SetUpdateStatus("", UpdateInProgress)
	mvp.oldGroups = existingGroup
	mvp.oldProxy = existingProxy
	va.storeMvlansMap(vlan, name, mvp)
	if err := mvp.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
	}
	if prevMaxActiveChannels != mvp.MaxActiveChannels {
		mvp.UpdateActiveChannelSubscriberAlarm()
	}

	// The update task is added as part of Igm p task list, so that any parallel igmp pkt processing is avoided
	// Until, the update operation is completed, the igmp pkt processing will be enqueued
	updateTask := NewUpdateMvlanTask(mvp, "")
	va.IgmpTasks.AddTask(updateTask)
	return nil
}

// isDeviceInList to check if device is the list
func isDeviceInList(serialNum string, OLTSerialNums []string) bool {
	for _, oltSerialNum := range OLTSerialNums {
		if serialNum == oltSerialNum {
			return true
		}
	}
	return false
}

// McastConfigKey creates the key using the olt serial number and mvlan profile id
func McastConfigKey(oltSerialNum string, mvlanProfID string) string {
	return oltSerialNum + "_" + mvlanProfID
}

// GetMcastConfig to get McastConfig Information by OLT and Mvlan Profile ID
func (va *VoltApplication) GetMcastConfig(oltSerialNum string, mvlanProfID string) *McastConfig {
	if mc, ok := va.McastConfigMap.Load(McastConfigKey(oltSerialNum, mvlanProfID)); ok {
		return mc.(*McastConfig)
	}
	return nil
}

func (va *VoltApplication) storeMcastConfig(oltSerialNum string, mvlanProfID string, mcastConfig *McastConfig) {
	va.McastConfigMap.Store(McastConfigKey(oltSerialNum, mvlanProfID), mcastConfig)
}

func (va *VoltApplication) deleteMcastConfig(oltSerialNum string, mvlanProfID string) {
	va.McastConfigMap.Delete(McastConfigKey(oltSerialNum, mvlanProfID))
}

// AddMcastConfig for addition of a MVLAN profile
func (va *VoltApplication) AddMcastConfig(MvlanProfileID string, IgmpProfileID string, IgmpProxyIP string, OltSerialNum string) error {
	var mcastCfg *McastConfig

	mcastCfg = va.GetMcastConfig(OltSerialNum, MvlanProfileID)
	if mcastCfg == nil {
		mcastCfg = &McastConfig{}
	} else {
		logger.Debugw(ctx, "Mcast Config already exists", log.Fields{"OltSerialNum": mcastCfg.OltSerialNum,
			"MVLAN Profile ID": mcastCfg.MvlanProfileID})
	}

	// Update all igds available
	mvpIntf, ok := va.MvlanProfilesByName.Load(MvlanProfileID)
	if !ok {
		return errors.New("MVLAN profile not found during add mcast config")
	}
	mvlan := mvpIntf.(*MvlanProfile).Mvlan

	mcastCfg.OltSerialNum = OltSerialNum
	mcastCfg.MvlanProfileID = MvlanProfileID
	mcastCfg.IgmpProfileID = IgmpProfileID
	mcastCfg.IgmpProxyIP = net.ParseIP(IgmpProxyIP)

	proxyCfg := va.getIgmpProfileMap(IgmpProfileID)

	iterIgmpGroups := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		if ig.Mvlan != mvlan {
			return true
		}

		for _, igd := range ig.Devices {
			if igd.SerialNo != OltSerialNum {
				continue
			}
			igd.proxyCfg = proxyCfg
			if IgmpProfileID == "" {
				igd.IgmpProxyIP = &igd.proxyCfg.IgmpSourceIP
			} else {
				igd.IgmpProxyIP = &mcastCfg.IgmpProxyIP
			}
			mcastCfg.IgmpGroupDevices.Store(igd.GroupID, igd)
			logger.Debugw(ctx, "Igd updated with proxyCfg and proxyIP", log.Fields{"name": igd.GroupName,
				"IgmpProfileID": IgmpProfileID, "ProxyIP": mcastCfg.IgmpProxyIP})
		}
		return true
	}
	va.IgmpGroups.Range(iterIgmpGroups)

	va.storeMcastConfig(OltSerialNum, MvlanProfileID, mcastCfg)
	if err := mcastCfg.WriteToDb(); err != nil {
		logger.Errorw(ctx, "McastConfig Write to DB failed", log.Fields{"OltSerialNum": mcastCfg.OltSerialNum, "MvlanProfileID": mcastCfg.MvlanProfileID})
	}
	va.addOltToMvlan(MvlanProfileID, OltSerialNum)

	return nil
}

func (va *VoltApplication) addOltToMvlan(MvlanProfileID string, OltSerialNum string) {
	var mvp *MvlanProfile
	if mvpIntf, ok := va.MvlanProfilesByName.Load(MvlanProfileID); ok {
		servVersion := IgmpVersion0
		mvp = mvpIntf.(*MvlanProfile)
		mvp.DevicesList[OltSerialNum] = NoOp
		mvp.IgmpServVersion[OltSerialNum] = &servVersion
		if err := mvp.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
		}
		mvp.pushIgmpMcastFlows(OltSerialNum)
	}
}

func (va *VoltApplication) delOltFromMvlan(MvlanProfileID string, OltSerialNum string) {
	var mvp *MvlanProfile
	if mvpIntf, ok := va.MvlanProfilesByName.Load(MvlanProfileID); ok {
		mvp = mvpIntf.(*MvlanProfile)
		//Delete from mvp list
		mvp.removeIgmpMcastFlows(OltSerialNum)
		delete(mvp.DevicesList, OltSerialNum)
		if err := mvp.WriteToDb(); err != nil {
			logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
		}
	}
}

// DelMcastConfig for addition of a MVLAN profile
func (va *VoltApplication) DelMcastConfig(MvlanProfileID string, IgmpProfileID string, IgmpProxyIP string, OltSerialNum string) {

	va.delOltFromMvlan(MvlanProfileID, OltSerialNum)
	va.deleteMcastConfig(OltSerialNum, MvlanProfileID)
	_ = db.DelMcastConfig(McastConfigKey(OltSerialNum, MvlanProfileID))
	if d := va.GetDeviceBySerialNo(OltSerialNum); d != nil {
		if mvp := va.GetMvlanProfileByName(MvlanProfileID); mvp != nil {
			va.RemoveGroupsFromPendingPool(d.Name, mvp.Mvlan)
		}
	}
}

// DelAllMcastConfig for deletion of all mcast config
func (va *VoltApplication) DelAllMcastConfig(OltSerialNum string) error {

	deleteIndividualMcastConfig := func(key interface{}, value interface{}) bool {
		mcastCfg := value.(*McastConfig)
		if mcastCfg.OltSerialNum == OltSerialNum {
			va.DelMcastConfig(mcastCfg.MvlanProfileID, mcastCfg.IgmpProfileID, mcastCfg.IgmpProxyIP.String(), mcastCfg.OltSerialNum)
		}
		return true
	}
	va.McastConfigMap.Range(deleteIndividualMcastConfig)
	return nil
}

// UpdateMcastConfig for addition of a MVLAN profile
func (va *VoltApplication) UpdateMcastConfig(MvlanProfileID string, IgmpProfileID string, IgmpProxyIP string, OltSerialNum string) error {

	mcastCfg := va.GetMcastConfig(OltSerialNum, MvlanProfileID)
	if mcastCfg == nil {
		logger.Warnw(ctx, "Mcast Config not found. Unable to update", log.Fields{"Mvlan Profile ID": MvlanProfileID, "OltSerialNum": OltSerialNum})
		return nil
	}

	oldProfID := mcastCfg.IgmpProfileID
	mcastCfg.IgmpProfileID = IgmpProfileID
	mcastCfg.IgmpProxyIP = net.ParseIP(IgmpProxyIP)

	va.storeMcastConfig(OltSerialNum, MvlanProfileID, mcastCfg)

	// Update all igds
	if oldProfID != mcastCfg.IgmpProfileID {
		updateIgdProxyCfg := func(key interface{}, value interface{}) bool {
			igd := value.(*IgmpGroupDevice)
			igd.proxyCfg = va.getIgmpProfileMap(mcastCfg.IgmpProfileID)
			if IgmpProfileID == "" {
				igd.IgmpProxyIP = &igd.proxyCfg.IgmpSourceIP
			} else {
				igd.IgmpProxyIP = &mcastCfg.IgmpProxyIP
			}
			return true
		}
		mcastCfg.IgmpGroupDevices.Range(updateIgdProxyCfg)
	}

	if err := mcastCfg.WriteToDb(); err != nil {
		logger.Errorw(ctx, "McastConfig Write to DB failed", log.Fields{"OltSerialNum": mcastCfg.OltSerialNum, "MvlanProfileID": mcastCfg.MvlanProfileID})
	}

	return nil
}

// WriteToDb is utility to write Mcast config Info to database
func (mc *McastConfig) WriteToDb() error {
	mc.Version = database.PresentVersionMap[database.McastConfigPath]
	b, err := json.Marshal(mc)
	if err != nil {
		return err
	}
	if err1 := db.PutMcastConfig(McastConfigKey(mc.OltSerialNum, mc.MvlanProfileID), string(b)); err1 != nil {
		return err1
	}
	return nil
}

// RestoreMcastConfigsFromDb to read from the DB and restore Mcast configs
func (va *VoltApplication) RestoreMcastConfigsFromDb() {
	mcastConfigs, _ := db.GetMcastConfigs()
	for hash, mcastConfig := range mcastConfigs {
		b, ok := mcastConfig.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var mc McastConfig
		err := json.Unmarshal(b, &mc)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of Mcast config failed")
			continue
		}
		va.storeMcastConfig(mc.OltSerialNum, mc.MvlanProfileID, &mc)
		logger.Infow(ctx, "Restored Mcast config", log.Fields{"OltSerialNum": mc.OltSerialNum, "MvlanProfileID": mc.MvlanProfileID, "hash": hash})
	}
}

// AddMvlanProfile for addition of a MVLAN profile
func (va *VoltApplication) AddMvlanProfile(name string, mvlan of.VlanType, ponVlan of.VlanType,
	groups map[string][]string, isChannelBasedGroup bool, OLTSerialNum []string, activeChannelsPerPon int, proxy map[string]common.MulticastGroupProxy) error {
	var mvp *MvlanProfile

	if mvp = va.GetMvlanProfileByTag(mvlan); mvp != nil {
		logger.Errorw(ctx, "Duplicate MVLAN ID configured", log.Fields{"mvlan": mvlan})
		return errors.New("MVLAN profile with same VLANID exists")
	}
	if mvpIntf, ok := va.MvlanProfilesByName.Load(name); ok {
		mvp = mvpIntf.(*MvlanProfile)
		for _, serialNum := range OLTSerialNum {
			if mvp.DevicesList[serialNum] != Nil {
				//This is backup restore scenario, just update the profile
				logger.Info(ctx, "Add Mvlan : Profile Name already exists, update-the-profile")
				return va.UpdateMvlanProfile(name, mvlan, groups, activeChannelsPerPon, proxy)
			}
		}
	}

	if mvp == nil {
		mvp = NewMvlanProfile(name, mvlan, ponVlan, isChannelBasedGroup, OLTSerialNum, uint32(activeChannelsPerPon))
	}

	va.storeMvlansMap(mvlan, name, mvp)

	/* Need to protect groups and proxy write lock */
	mvp.mvpLock.Lock()
	for grpName, grpInfo := range groups {
		mvp.AddMvlanGroup(grpName, grpInfo)
	}
	for grpName, proxyInfo := range proxy {
		mvp.AddMvlanProxy(grpName, proxyInfo)
	}
	if _, ok := mvp.Groups[common.StaticGroup]; ok {
		if _, yes := mvp.Proxy[common.StaticGroup]; !yes {
			mvp.Groups[common.StaticGroup].IsStatic = true
		}
	}

	logger.Debugw(ctx, "Added MVLAN Profile", log.Fields{"MVLAN": mvp.Mvlan, "PonVlan": mvp.PonVlan, "Name": mvp.Name, "Grp IPs": mvp.Groups, "IsPonVlanPresent": mvp.IsPonVlanPresent})
	mvp.mvpLock.Unlock()

	if err := mvp.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
	}

	return nil
}

//pushIgmpMcastFlows - Adds all IGMP related flows (generic DS flow & static group flows)
func (mvp *MvlanProfile) pushIgmpMcastFlows(OLTSerialNum string) {

	mvp.mvpLock.RLock()
	defer mvp.mvpLock.RUnlock()

	if mvp.DevicesList[OLTSerialNum] == Nil {
		logger.Infow(ctx, "Mvlan Profile not configure for device", log.Fields{"Device": OLTSerialNum, "Mvlan": mvp.Mvlan})
		return
	}

	d := GetApplication().GetDeviceBySerialNo(OLTSerialNum)
	if d == nil {
		logger.Warnw(ctx, "Skipping Igmp & Mcast Flow processing: Device Not Found", log.Fields{"Device_SrNo": OLTSerialNum, "Mvlan": mvp.Mvlan})
		return
	}

	p := d.GetPort(d.NniPort)

	if p != nil && p.State == PortStateUp {
		logger.Infow(ctx, "NNI Port Status is: UP & Vlan Enabled", log.Fields{"Device": d, "port": p})

		//Push Igmp DS Control Flows
		err := mvp.ApplyIgmpDSFlowForMvp(d.Name)
		if err != nil {
			logger.Errorw(ctx, "DS IGMP Flow Add Failed for device",
				log.Fields{"Reason": err.Error(), "device": d.Name})
		}

		//Trigger Join for static channels
		if channelList, containsStatic := mvp.getAllStaticChannels(); containsStatic {
			mvp.ProcessStaticGroup(d.Name, channelList, true)
		} else {
			logger.Infow(ctx, "No Static Channels Present", log.Fields{"mvp": mvp.Name, "Mvlan": mvp.Mvlan})
		}
	}
}

/*
//pushIgmpMcastFlowsToAllOlt - Adds all IGMP related flows (generic DS flow & static group flows) to all OLTs
func (mvp *MvlanProfile) pushIgmpMcastFlowsToAllOlt() {

	//for all devices apply igmp DS trap flow rules
	pushIgmpFlows := func(key interface{}, value interface{}) bool {
		d := value.(*VoltDevice)
		p := d.GetPort(d.NniPort)
			if p != nil && p.State == PortStateUp {
				logger.Infow(ctx, "NNI Port Status is: UP & Vlan Enabled", log.Fields{"Device": d, "port": p})

				//Push Igmp DS Control Flows
				err := mvp.ApplyIgmpDSFlowForMvp(d.Name)
				if err != nil {
					logger.Errorw(ctx, "DS IGMP Flow Add Failed for device",
						log.Fields{"Reason": err.Error(), "device": d.Name})
				}

				//Trigger Join for static channels
				if channelList, containsStatic := mvp.getAllStaticChannels(); containsStatic {
					mvp.ProcessStaticGroup(d.Name, channelList, true)
				} else {
					logger.Infow(ctx, "No Static Channels Present", log.Fields{"mvp": mvp.Name, "Mvlan": mvp.Mvlan})
				}
			}
		return true
	}
	mvp.mvpLock.RLock()
	defer mvp.mvpLock.RUnlock()
	GetApplication().DevicesDisc.Range(pushIgmpFlows)
}

//removeIgmpFlows - Removes all IGMP related flows (generic DS flow)
func (mvp *MvlanProfile) removeIgmpFlows(oltSerialNum string) {

	if d := GetApplication().GetDeviceBySerialNo(oltSerialNum); d != nil {
		p := d.GetPort(d.NniPort)
		if p != nil {
			logger.Infow(ctx, "NNI Port Status is: UP", log.Fields{"Device": d, "port": p})
			err := mvp.RemoveIgmpDSFlowForMvp(d.Name)
			if err != nil {
				logger.Errorw(ctx, "DS IGMP Flow Del Failed", log.Fields{"Reason": err.Error(), "device": d.Name})
			}
		}
	}
}*/

//removeIgmpMcastFlows - Removes all IGMP related flows (generic DS flow & static group flows)
func (mvp *MvlanProfile) removeIgmpMcastFlows(oltSerialNum string) {

	mvp.mvpLock.RLock()
	defer mvp.mvpLock.RUnlock()

	if d := GetApplication().GetDeviceBySerialNo(oltSerialNum); d != nil {
		p := d.GetPort(d.NniPort)
		if p != nil {
			logger.Infow(ctx, "NNI Port Status is: UP", log.Fields{"Device": d, "port": p})

			// ***Do not change the order***
			// When Vlan is disabled, the process end is determined by the DS Igmp flag in device

			//Trigger Leave for static channels
			if channelList, containsStatic := mvp.getAllStaticChannels(); containsStatic {
				mvp.ProcessStaticGroup(d.Name, channelList, false)
			} else {
				logger.Infow(ctx, "No Static Channels Present", log.Fields{"mvp": mvp.Name, "Mvlan": mvp.Mvlan})
			}

			//Remove all dynamic members for the Mvlan Profile
			GetApplication().IgmpGroups.Range(func(key, value interface{}) bool {
				ig := value.(*IgmpGroup)
				if ig.Mvlan == mvp.Mvlan {
					igd := ig.Devices[d.Name]
					ig.DelIgmpGroupDevice(igd)
					if ig.NumDevicesActive() == 0 {
						GetApplication().DelIgmpGroup(ig)
					}
				}
				return true
			})

			//Remove DS Igmp trap flow
			err := mvp.RemoveIgmpDSFlowForMvp(d.Name)
			if err != nil {
				logger.Errorw(ctx, "DS IGMP Flow Del Failed", log.Fields{"Reason": err.Error(), "device": d.Name})
			}
		}
	}
}

// ApplyIgmpDSFlowForMvp to apply Igmp DS flow for mvlan.
func (mvp *MvlanProfile) ApplyIgmpDSFlowForMvp(device string) error {
	va := GetApplication()
	dIntf, ok := va.DevicesDisc.Load(device)
	if !ok {
		return errors.New("Device Doesn't Exist")
	}
	d := dIntf.(*VoltDevice)
	mvlan := mvp.Mvlan

	flowAlreadyApplied, ok := d.IgmpDsFlowAppliedForMvlan[uint16(mvlan)]
	if !ok || !flowAlreadyApplied {
		flows, err := mvp.BuildIgmpDSFlows(device)
		if err == nil {
			err = cntlr.GetController().AddFlows(d.NniPort, device, flows)
			if err != nil {
				logger.Warnw(ctx, "Configuring IGMP Flow for device failed ", log.Fields{"Device": device, "err": err})
				return err
			}
			d.IgmpDsFlowAppliedForMvlan[uint16(mvlan)] = true
			logger.Infow(ctx, "Updating voltDevice that IGMP DS flow as \"added\" for ",
				log.Fields{"device": d.SerialNum, "mvlan": mvlan})
		} else {
			logger.Errorw(ctx, "DS IGMP Flow Add Failed", log.Fields{"Reason": err.Error(), "Mvlan": mvlan})
		}
	}

	return nil
}

// RemoveIgmpDSFlowForMvp to remove Igmp DS flow for mvlan.
func (mvp *MvlanProfile) RemoveIgmpDSFlowForMvp(device string) error {

	va := GetApplication()
	mvlan := mvp.Mvlan

	dIntf, ok := va.DevicesDisc.Load(device)
	if !ok {
		return errors.New("Device Doesn't Exist")
	}
	d := dIntf.(*VoltDevice)
	/* No need of strict check during DS IGMP deletion
	flowAlreadyApplied, ok := d.IgmpDsFlowAppliedForMvlan[uint16(mvlan)]
	if ok && flowAlreadyApplied
	*/
	flows, err := mvp.BuildIgmpDSFlows(device)
	if err == nil {
		flows.ForceAction = true

		err = mvp.DelFlows(d, flows)
		if err != nil {
			logger.Warnw(ctx, "De-Configuring IGMP Flow for device failed ", log.Fields{"Device": device, "err": err})
			return err
		}
		d.IgmpDsFlowAppliedForMvlan[uint16(mvlan)] = false
		logger.Infow(ctx, "Updating voltDevice that IGMP DS flow as \"removed\" for ",
			log.Fields{"device": d.SerialNum, "mvlan": mvlan})
	} else {
		logger.Errorw(ctx, "DS IGMP Flow Del Failed", log.Fields{"Reason": err.Error()})
	}

	return nil
}

// BuildIgmpDSFlows to build Igmp DS flows for NNI port
func (mvp *MvlanProfile) BuildIgmpDSFlows(device string) (*of.VoltFlow, error) {
	dIntf, ok := GetApplication().DevicesDisc.Load(device)
	if !ok {
		return nil, errors.New("Device Doesn't Exist")
	}
	d := dIntf.(*VoltDevice)

	logger.Infow(ctx, "Building DS IGMP Flow for NNI port", log.Fields{"vs": d.NniPort, "Mvlan": mvp.Mvlan})
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)
	subFlow.SetMatchVlan(mvp.Mvlan)

	nniPort, err := GetApplication().GetNniPort(device)
	if err != nil {
		return nil, err
	}
	nniPortID, err1 := GetApplication().GetPortID(nniPort)
	if err1 != nil {
		return nil, errors.New("Unknown NNI outport")
	}
	subFlow.SetInPort(nniPortID)
	subFlow.SetIgmpMatch()
	subFlow.SetReportToController()
	subFlow.Cookie = uint64(nniPortID)<<32 | uint64(mvp.Mvlan)
	subFlow.Priority = of.IgmpFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built DS IGMP flow", log.Fields{"cookie": subFlow.Cookie, "subflow": subFlow})
	return flow, nil
}

//updateStaticGroups - Generates static joins & leaves for newly added and removed static channels respectively
func (mvp *MvlanProfile) updateStaticGroups(deviceID string, added []net.IP, removed []net.IP) {

	//Update static group configs for all associated devices
	updateGroups := func(key interface{}, value interface{}) bool {
		d := value.(*VoltDevice)

		if mvp.DevicesList[d.SerialNum] == Nil {
			logger.Infow(ctx, "Mvlan Profile not configure for device", log.Fields{"Device": d, "Profile Device List": mvp.DevicesList})
			return true
		}
		//TODO if mvp.IsChannelBasedGroup {
		mvp.ProcessStaticGroup(d.Name, added, true)
		mvp.ProcessStaticGroup(d.Name, removed, false)
		//}
		return true
	}

	if deviceID != "" {
		vd := GetApplication().GetDevice(deviceID)
		updateGroups(deviceID, vd)
	} else {
		GetApplication().DevicesDisc.Range(updateGroups)
	}
}

//updateDynamicGroups - Generates joins with updated sources for existing channels
func (mvp *MvlanProfile) updateDynamicGroups(deviceID string, added []net.IP, removed []net.IP) {

	//mvlan := mvp.Mvlan
	va := GetApplication()

	updateGroups := func(key interface{}, value interface{}) bool {
		d := value.(*VoltDevice)

		if mvp.DevicesList[d.SerialNum] == Nil {
			logger.Infow(ctx, "Mvlan Profile not configure for device", log.Fields{"Device": d, "Profile Device List": mvp.DevicesList})
			return true
		}
		for _, groupAddr := range added {

			_, gName := va.GetMvlanProfileForMcIP(mvp.Name, groupAddr)
			grpKey := mvp.generateGroupKey(gName, groupAddr.String())
			logger.Debugw(ctx, "IGMP Group", log.Fields{"Group": grpKey, "groupAddr": groupAddr})
			if igIntf, ok := va.IgmpGroups.Load(grpKey); ok {
				ig := igIntf.(*IgmpGroup)
				if igd, ok := ig.getIgmpGroupDevice(d.Name); ok {
					if igcIntf, ok := igd.GroupChannels.Load(groupAddr.String()); ok {
						igc := igcIntf.(*IgmpGroupChannel)
						incl := false
						var ip []net.IP
						var groupModified = false
						if _, ok := mvp.Proxy[igc.GroupName]; ok {
							if mvp.Proxy[igc.GroupName].Mode == common.Include {
								incl = true
							}
							ip = mvp.Proxy[igc.GroupName].SourceList
						}
						for port, igp := range igc.NewReceivers {
							// Process the include/exclude list which may end up modifying the group
							if change, _ := igc.ProcessSources(port, ip, incl); change {
								groupModified = true
							}
							igc.ProcessMode(port, incl)

							if err := igp.WriteToDb(igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
								logger.Errorw(ctx, "Igmp group port Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
							}
						}
						// If the group is modified as this is the first receiver or due to include/exclude list modification
						// send a report to the upstream multicast servers
						if groupModified {
							logger.Debug(ctx, "Group Modified and IGMP report sent to the upstream server")
							igc.SendReport(false)
						}
						if err := igc.WriteToDb(); err != nil {
							logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
						}
					}
				}
			}
		}

		return true
	}

	if deviceID != "" {
		vd := GetApplication().GetDevice(deviceID)
		updateGroups(deviceID, vd)
	} else {
		GetApplication().DevicesDisc.Range(updateGroups)
	}
}

//GroupsUpdated - Handles removing of Igmp Groups, flows & group table entries for
//channels removed as part of update
func (mvp *MvlanProfile) GroupsUpdated(deviceID string) {

	deleteChannelIfRemoved := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)

		if ig.Mvlan != mvp.Mvlan {
			return true
		}
		grpName := ig.GroupName
		logger.Infow(ctx, "###Update Cycle", log.Fields{"IG": ig.GroupName, "Addr": ig.GroupAddr})
		//Check if group exists and remove the entire group object otherwise
		if currentChannels := mvp.Groups[grpName]; currentChannels != nil {

			if mvp.IsChannelBasedGroup {
				channelPresent := doesIPMatch(ig.GroupAddr, currentChannels.McIPs)
				if channelPresent || mvp.isChannelStatic(ig.GroupAddr) {
					return true
				}
			} else {
				allExistingChannels := ig.GetAllIgmpChannelForDevice(deviceID)
				for channel := range allExistingChannels {
					channelIP := net.ParseIP(channel)
					channelPresent := mvp.IsChannelPresent(channelIP, currentChannels.McIPs, mvp.IsStaticGroup(ig.GroupName))
					if channelPresent {
						staticChannel := mvp.isChannelStatic(channelIP)
						logger.Infow(ctx, "###Channel Comparision", log.Fields{"staticChannel": staticChannel, "Group": mvp.IsStaticGroup(ig.GroupName), "Channel": channel})
						// Logic:
						// If channel is Static & existing Group is also static - No migration required
						// If channel is not Static & existing Group is also not static - No migration required

						// If channel is Static and existing Group is not static - Migrate (from dynamic to static)
						//    (Channel already part of dynamic, added to static)

						// If channel is not Static but existing Group is static - Migrate (from static to dynamic)
						//    (Channel removed from satic but part of dynamic)
						if (staticChannel != mvp.IsStaticGroup(ig.GroupName)) || (ig.IsGroupStatic != mvp.IsStaticGroup(ig.GroupName)) { // Equivalent of XOR
							ig.HandleGroupMigration(deviceID, channelIP)
						} else {
							if (ig.IsGroupStatic) && mvp.IsStaticGroup(ig.GroupName) {
								if ig.GroupName != mvp.GetStaticGroupName(channelIP) {
									ig.HandleGroupMigration(deviceID, channelIP)
								}
							}
							continue
						}
					} else {
						logger.Debugw(ctx, "Channel Removed", log.Fields{"Channel": channel, "Group": grpName})
						ig.DelIgmpChannel(deviceID, net.ParseIP(channel))
						if ig.NumDevicesActive() == 0 {
							GetApplication().DelIgmpGroup(ig)
						}
					}
				}
				ig.IsGroupStatic = mvp.IsStaticGroup(ig.GroupName)
				if err := ig.WriteToDb(); err != nil {
					logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
				}
				return true
			}
		}
		logger.Debugw(ctx, "Group Removed", log.Fields{"Channel": ig.GroupAddr, "Group": grpName, "ChannelBasedGroup": ig.IsChannelBasedGroup})
		ig.DelIgmpGroup()
		logger.Debugw(ctx, "Removed Igmp Group", log.Fields{"Channel": ig.GroupAddr, "Group": grpName})
		return true
	}
	GetApplication().IgmpGroups.Range(deleteChannelIfRemoved)
}

// IsChannelPresent to check if channel is present
func (mvp *MvlanProfile) IsChannelPresent(channelIP net.IP, groupChannelList []string, IsStaticGroup bool) bool {
	// Only in case of static group, migration need to be supported.
	// Dynamic to dynamic group migration not supported currently
	if doesIPMatch(channelIP, groupChannelList) || mvp.isChannelStatic(channelIP) {
		return true
	} else if IsStaticGroup {
		return (mvp.GetMvlanGroup(channelIP) != "")
	}

	return false
}

// GetMvlanProfileForMcIP - Get an MVLAN profile for a given MC IP. This is used when an
// IGMP report is received from the PON port. The MVLAN profile
// located is used to idnetify the MC VLAN used in upstream for
// join/leave
func (va *VoltApplication) GetMvlanProfileForMcIP(profileName string, ip net.IP) (*MvlanProfile, string) {
	if mvpIntf, ok := va.MvlanProfilesByName.Load(profileName); ok {
		mvp := mvpIntf.(*MvlanProfile)
		if grpName := mvp.GetMvlanGroup(ip); grpName != "" {
			return mvp, grpName
		}
	} else {
		logger.Warnw(ctx, "Mvlan Profile not found for given profile name", log.Fields{"Profile": profileName})
	}
	return nil, ""
}

// GetMvlanGroup to get mvlan group
func (mvp *MvlanProfile) GetMvlanGroup(ip net.IP) string {
	//Check for Static Group First
	if mvp.containsStaticChannels() {
		grpName := mvp.GetStaticGroupName(ip)
		if grpName != "" {
			return grpName
		}
	}

	for _, mvg := range mvp.Groups {
		if mvg.Wildcard {
			return mvg.Name
		}
		if doesIPMatch(ip, mvg.McIPs) {
			return mvg.Name
		}
	}
	return ""
}

// IgmpTick for igmp tick info
func (va *VoltApplication) IgmpTick() {
	tickCount++
	if (tickCount % 1000) == 0 {
		logger.Debugw(ctx, "Time @ Tick", log.Fields{"Tick": tickCount, "Time": time.Now()})
	}
	igmptick := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		if ig.NumDevicesActive() != 0 {
			if tickCount%10 == ig.Hash()%10 {
				ig.IgmpGroupLock.Lock()
				ig.Tick()
				ig.IgmpGroupLock.Unlock()
				if ig.NumDevicesActive() == 0 {
					va.DelIgmpGroup(ig)
				}
			}
		}
		return true
	}
	va.IgmpGroups.Range(igmptick)
}

// Tick to add Tick Task
func (va *VoltApplication) Tick() {
	tt := NewTickTask()
	va.IgmpTasks.AddTask(tt)
	// va.IgmpTick()
}

//AddIgmpProfile for addition of IGMP Profile
func (va *VoltApplication) AddIgmpProfile(igmpProfileConfig *common.IGMPConfig) error {
	var igmpProfile *IgmpProfile

	if igmpProfileConfig.ProfileID == DefaultIgmpProfID {
		logger.Info(ctx, "Updating default IGMP profile")
		return va.UpdateIgmpProfile(igmpProfileConfig)
	}

	igmpProfile = va.checkIgmpProfileMap(igmpProfileConfig.ProfileID)
	if igmpProfile == nil {
		igmpProfile = newIgmpProfile(igmpProfileConfig)
	} else {
		logger.Errorw(ctx, "IGMP profile already exists", log.Fields{"IgmpProfile": igmpProfileConfig.ProfileID})
		return errors.New("IGMP Profile already exists")
	}

	va.storeIgmpProfileMap(igmpProfileConfig.ProfileID, igmpProfile)

	if err := igmpProfile.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp profile Write to DB failed", log.Fields{"profileID": igmpProfile.ProfileID})
	}

	return nil
}

func newIgmpProfile(igmpProfileConfig *common.IGMPConfig) *IgmpProfile {
	var igmpProfile IgmpProfile
	igmpProfile.ProfileID = igmpProfileConfig.ProfileID
	igmpProfile.UnsolicitedTimeOut = uint32(igmpProfileConfig.UnsolicitedTimeOut)
	igmpProfile.MaxResp = uint32(igmpProfileConfig.MaxResp)

	keepAliveInterval := uint32(igmpProfileConfig.KeepAliveInterval)

	//KeepAliveInterval should have a min of 10 seconds
	if keepAliveInterval < MinKeepAliveInterval {
		keepAliveInterval = MinKeepAliveInterval
		logger.Infow(ctx, "Auto adjust keepAliveInterval - Value < 10", log.Fields{"Received": igmpProfileConfig.KeepAliveInterval, "Configured": keepAliveInterval})
	}
	igmpProfile.KeepAliveInterval = keepAliveInterval

	igmpProfile.KeepAliveCount = uint32(igmpProfileConfig.KeepAliveCount)
	igmpProfile.LastQueryInterval = uint32(igmpProfileConfig.LastQueryInterval)
	igmpProfile.LastQueryCount = uint32(igmpProfileConfig.LastQueryCount)
	igmpProfile.FastLeave = *igmpProfileConfig.FastLeave
	igmpProfile.PeriodicQuery = *igmpProfileConfig.PeriodicQuery
	igmpProfile.IgmpCos = uint8(igmpProfileConfig.IgmpCos)
	igmpProfile.WithRAUpLink = *igmpProfileConfig.WithRAUpLink
	igmpProfile.WithRADownLink = *igmpProfileConfig.WithRADownLink

	if igmpProfileConfig.IgmpVerToServer == "2" || igmpProfileConfig.IgmpVerToServer == "v2" {
		igmpProfile.IgmpVerToServer = "2"
	} else {
		igmpProfile.IgmpVerToServer = "3"
	}
	igmpProfile.IgmpSourceIP = net.ParseIP(igmpProfileConfig.IgmpSourceIP)

	return &igmpProfile
}

// checkIgmpProfileMap to get Igmp Profile. If not found return nil
func (va *VoltApplication) checkIgmpProfileMap(name string) *IgmpProfile {
	if igmpProfileIntf, ok := va.IgmpProfilesByName.Load(name); ok {
		return igmpProfileIntf.(*IgmpProfile)
	}
	return nil
}

// newDefaultIgmpProfile Igmp profiles with default values
func newDefaultIgmpProfile() *IgmpProfile {
	return &IgmpProfile{
		ProfileID:          DefaultIgmpProfID,
		UnsolicitedTimeOut: 60,
		MaxResp:            10, // seconds
		KeepAliveInterval:  60, // seconds
		KeepAliveCount:     3,  // TODO - May not be needed
		LastQueryInterval:  0,  // TODO - May not be needed
		LastQueryCount:     0,  // TODO - May not be needed
		FastLeave:          true,
		PeriodicQuery:      false, // TODO - May not be needed
		IgmpCos:            7,     //p-bit value included in the IGMP packet
		WithRAUpLink:       false, // TODO - May not be needed
		WithRADownLink:     false, // TODO - May not be needed
		IgmpVerToServer:    "3",
		IgmpSourceIP:       net.ParseIP("172.27.0.1"), // This will be replaced by configuration
	}
}

func (va *VoltApplication) resetIgmpProfileToDefault() {
	igmpProf := va.getIgmpProfileMap(DefaultIgmpProfID)
	defIgmpProf := newDefaultIgmpProfile()

	igmpProf.UnsolicitedTimeOut = defIgmpProf.UnsolicitedTimeOut
	igmpProf.MaxResp = defIgmpProf.MaxResp
	igmpProf.KeepAliveInterval = defIgmpProf.KeepAliveInterval
	igmpProf.KeepAliveCount = defIgmpProf.KeepAliveCount
	igmpProf.LastQueryInterval = defIgmpProf.LastQueryInterval
	igmpProf.LastQueryCount = defIgmpProf.LastQueryCount
	igmpProf.FastLeave = defIgmpProf.FastLeave
	igmpProf.PeriodicQuery = defIgmpProf.PeriodicQuery
	igmpProf.IgmpCos = defIgmpProf.IgmpCos
	igmpProf.WithRAUpLink = defIgmpProf.WithRAUpLink
	igmpProf.WithRADownLink = defIgmpProf.WithRADownLink
	igmpProf.IgmpVerToServer = defIgmpProf.IgmpVerToServer
	igmpProf.IgmpSourceIP = defIgmpProf.IgmpSourceIP

	if err := igmpProf.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp profile Write to DB failed", log.Fields{"profileID": igmpProf.ProfileID})
	}
}

// getIgmpProfileMap to get Igmp Profile. If not found return default IGMP config
func (va *VoltApplication) getIgmpProfileMap(name string) *IgmpProfile {
	if igmpProfileIntf, ok := va.IgmpProfilesByName.Load(name); ok {
		return igmpProfileIntf.(*IgmpProfile)
	}

	// There will be always a default igmp profile.
	defaultIgmpProfileIntf, _ := va.IgmpProfilesByName.Load(DefaultIgmpProfID)
	return defaultIgmpProfileIntf.(*IgmpProfile)
}

// storeIgmpProfileMap to store Igmp Profile
func (va *VoltApplication) storeIgmpProfileMap(name string, igmpProfile *IgmpProfile) {
	va.IgmpProfilesByName.Store(name, igmpProfile)
}

// deleteIgmpProfileMap to delete Igmp Profile
func (va *VoltApplication) deleteIgmpProfileMap(name string) {
	va.IgmpProfilesByName.Delete(name)
}

// WriteToDb is utility to write Igmp Config Info to database
func (igmpProfile *IgmpProfile) WriteToDb() error {
	igmpProfile.Version = database.PresentVersionMap[database.IgmpProfPath]
	b, err := json.Marshal(igmpProfile)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpProfile(igmpProfile.ProfileID, string(b)); err1 != nil {
		return err1
	}
	return nil
}

//DelIgmpProfile for addition of IGMP Profile
func (va *VoltApplication) DelIgmpProfile(igmpProfileConfig *common.IGMPConfig) error {
	// Deletion of default igmp profile is blocked from submgr. Keeping additional check for safety.
	if igmpProfileConfig.ProfileID == DefaultIgmpProfID {
		logger.Info(ctx, "Resetting default IGMP profile")
		va.resetIgmpProfileToDefault()
		return nil
	}
	igmpProfile := va.checkIgmpProfileMap(igmpProfileConfig.ProfileID)
	if igmpProfile == nil {
		logger.Warnw(ctx, "Igmp Profile not found. Unable to delete", log.Fields{"Profile ID": igmpProfileConfig.ProfileID})
		return nil
	}

	va.deleteIgmpProfileMap(igmpProfileConfig.ProfileID)

	_ = db.DelIgmpProfile(igmpProfileConfig.ProfileID)

	return nil
}

//UpdateIgmpProfile for addition of IGMP Profile
func (va *VoltApplication) UpdateIgmpProfile(igmpProfileConfig *common.IGMPConfig) error {
	igmpProfile := va.checkIgmpProfileMap(igmpProfileConfig.ProfileID)
	if igmpProfile == nil {
		logger.Errorw(ctx, "Igmp Profile not found. Unable to update", log.Fields{"Profile ID": igmpProfileConfig.ProfileID})
		return errors.New("IGMP Profile not found")
	}

	igmpProfile.ProfileID = igmpProfileConfig.ProfileID
	igmpProfile.UnsolicitedTimeOut = uint32(igmpProfileConfig.UnsolicitedTimeOut)
	igmpProfile.MaxResp = uint32(igmpProfileConfig.MaxResp)

	keepAliveInterval := uint32(igmpProfileConfig.KeepAliveInterval)

	//KeepAliveInterval should have a min of 10 seconds
	if keepAliveInterval < MinKeepAliveInterval {
		keepAliveInterval = MinKeepAliveInterval
		logger.Infow(ctx, "Auto adjust keepAliveInterval - Value < 10", log.Fields{"Received": igmpProfileConfig.KeepAliveInterval, "Configured": keepAliveInterval})
	}
	igmpProfile.KeepAliveInterval = keepAliveInterval

	igmpProfile.KeepAliveCount = uint32(igmpProfileConfig.KeepAliveCount)
	igmpProfile.LastQueryInterval = uint32(igmpProfileConfig.LastQueryInterval)
	igmpProfile.LastQueryCount = uint32(igmpProfileConfig.LastQueryCount)
	igmpProfile.FastLeave = *igmpProfileConfig.FastLeave
	igmpProfile.PeriodicQuery = *igmpProfileConfig.PeriodicQuery
	igmpProfile.IgmpCos = uint8(igmpProfileConfig.IgmpCos)
	igmpProfile.WithRAUpLink = *igmpProfileConfig.WithRAUpLink
	igmpProfile.WithRADownLink = *igmpProfileConfig.WithRADownLink

	if igmpProfileConfig.IgmpVerToServer == "2" || igmpProfileConfig.IgmpVerToServer == "v2" {
		igmpProfile.IgmpVerToServer = "2"
	} else {
		igmpProfile.IgmpVerToServer = "3"
	}

	if igmpProfileConfig.IgmpSourceIP != "" {
		igmpProfile.IgmpSourceIP = net.ParseIP(igmpProfileConfig.IgmpSourceIP)
	}

	if err := igmpProfile.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp profile Write to DB failed", log.Fields{"profileID": igmpProfile.ProfileID})
	}

	return nil
}

// RestoreIGMPProfilesFromDb to read from the DB and restore IGMP Profiles
func (va *VoltApplication) RestoreIGMPProfilesFromDb() {
	// Loading IGMP profiles
	igmpProfiles, _ := db.GetIgmpProfiles()
	for _, igmpProfile := range igmpProfiles {
		b, ok := igmpProfile.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var igmpProf IgmpProfile
		err := json.Unmarshal(b, &igmpProf)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of IGMP Profile failed")
			continue
		}
		va.storeIgmpProfileMap(igmpProf.ProfileID, &igmpProf)
		logger.Infow(ctx, "Restored Igmp Profile", log.Fields{"Conf": igmpProf})
	}
}

// InitIgmpSrcMac for initialization of igmp source mac
func (va *VoltApplication) InitIgmpSrcMac() {
	srcMac, err := getPodMacAddr()
	if err != nil {
		igmpSrcMac = "00:11:11:11:11:11"
		return
	}
	igmpSrcMac = srcMac
}

// removeIPFromList to remove ip from the list
func removeIPFromList(s []net.IP, value net.IP) []net.IP {
	i := 0
	for i = 0; i < len(s); i++ {
		if s[i].Equal(value) {
			break
		}
	}
	if i != len(s) {
		//It means value is found in the slice
		return append(s[0:i], s[i+1:]...)
	}
	return s
}

// DelMvlanProfile for deletion of a MVLAN group
func (va *VoltApplication) DelMvlanProfile(name string) error {
	if mvpIntf, ok := va.MvlanProfilesByName.Load(name); ok {
		mvp := mvpIntf.(*MvlanProfile)

		if len(mvp.DevicesList) == 0 {
			mvp.DeleteInProgress = true
			mvp.DelFromDb()
			va.deleteMvlansMap(mvp.Mvlan, name)
			logger.Debugw(ctx, "Deleted MVLAN Profile", log.Fields{"Name": mvp.Name})
		} else {
			logger.Errorw(ctx, "Unable to delete Mvlan Profile as there is still an OLT attached to it", log.Fields{"Name": mvp.Name,
				"Device List": mvp.DevicesList})
			return errors.New("MVLAN attached to devices")
		}

		return nil
	}
	logger.Errorw(ctx, "MVLAN Profile not found", log.Fields{"MvlanProfile Name": name})
	return nil
}

// ReceiverUpInd for receiver up indication
func (va *VoltApplication) ReceiverUpInd(device string, port string, mvpName string, vlan of.VlanType, pbits []of.PbitType) {
	logger.Infow(ctx, "Receiver Indication: UP", log.Fields{"device": device, "port": port, "MVP": mvpName, "vlan": vlan, "pbits": pbits})
	if mvpIntf, ok := va.MvlanProfilesByName.Load(mvpName); ok {
		mvp := mvpIntf.(*MvlanProfile)
		if devIntf, ok := va.DevicesDisc.Load(device); ok {
			dev := devIntf.(*VoltDevice)
			proxyCfg, proxyIP, _ := getIgmpProxyCfgAndIP(mvp.Mvlan, dev.SerialNum)
			for _, pbit := range pbits {
				sendGeneralQuery(device, port, vlan, uint8(pbit), proxyCfg, proxyIP)
			}
		} else {
			logger.Warnw(ctx, "Device not found for given port", log.Fields{"device": device, "port": port})
		}
	} else {
		logger.Warnw(ctx, "Mvlan Profile not found for given profileName", log.Fields{"MVP": mvpName, "vlan": vlan})
	}
}

// sendGeneralQuery to send general query
func sendGeneralQuery(device string, port string, cVlan of.VlanType, pbit uint8, proxyCfg *IgmpProfile, proxyIP *net.IP) {

	if queryPkt, err := Igmpv2QueryPacket(NullIPAddr, cVlan, *proxyIP, pbit, proxyCfg.MaxResp); err == nil {
		if err := cntlr.GetController().PacketOutReq(device, port, port, queryPkt, false); err != nil {
			logger.Warnw(ctx, "General Igmpv2 Query Failed to send", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
		} else {
			logger.Debugw(ctx, "General Igmpv2 Query Sent", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
		}
	}
	if getVersion(proxyCfg.IgmpVerToServer) == IgmpVersion3 {
		if queryPkt, err := Igmpv3QueryPacket(NullIPAddr, cVlan, *proxyIP, pbit, proxyCfg.MaxResp); err == nil {
			if err := cntlr.GetController().PacketOutReq(device, port, port, queryPkt, false); err != nil {
				logger.Warnw(ctx, "General Igmpv3 Query Failed to send", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
			} else {
				logger.Debugw(ctx, "General Igmpv3 Query Sent", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
			}
		}
	}
}

// ReceiverDownInd to send receiver down indication
func (va *VoltApplication) ReceiverDownInd(device string, port string) {
	logger.Infow(ctx, " Receiver Indication: DOWN", log.Fields{"device": device, "port": port})

	ponPortID := va.GetPonPortID(device, port)

	del := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		ig.IgmpGroupLock.Lock()
		ig.DelReceiveronDownInd(device, port, ponPortID)
		ig.IgmpGroupLock.Unlock()
		if ig.NumDevicesActive() == 0 {
			va.DelIgmpGroup(ig)
		}
		return true
	}
	va.IgmpGroups.Range(del)
}

// doesIPMatch to check if ip match with any ip from the list
func doesIPMatch(ip net.IP, ipsOrRange []string) bool {
	for _, ipOrRange := range ipsOrRange {
		if strings.Contains(ipOrRange, "-") {
			var splits = strings.Split(ipOrRange, "-")
			ipStart := util.IP2LongConv(net.ParseIP(splits[0]))
			ipEnd := util.IP2LongConv(net.ParseIP(splits[1]))
			if ipEnd < ipStart {
				return false
			}
			ipInt := util.IP2LongConv(ip)
			if ipInt >= ipStart && ipInt <= ipEnd {
				return true
			}
		} else if ip.Equal(net.ParseIP(ipOrRange)) {
			return true
		}
	}
	return false
}

// ProcessStaticGroup - Process Static Join/Leave Req for static channels
func (mvp *MvlanProfile) ProcessStaticGroup(device string, groupAddresses []net.IP, isJoin bool) {

	logger.Debugw(ctx, "Received Static Group Request", log.Fields{"Device": device, "Join": isJoin, "Group Address List": groupAddresses})

	mvlan := mvp.Mvlan
	va := GetApplication()

	//TODO - Handle bulk add of groupAddr
	for _, groupAddr := range groupAddresses {

		ig := mvp.GetStaticIgmpGroup(groupAddr)
		if isJoin {
			vd := va.GetDevice(device)
			igmpProf, _, _ := getIgmpProxyCfgAndIP(mvlan, vd.SerialNum)
			ver := igmpProf.IgmpVerToServer

			if ig == nil {
				// First time group Creation: Create the IGMP group and then add the receiver to the group
				logger.Infow(ctx, "Static IGMP Add received for new group", log.Fields{"Addr": groupAddr, "Port": StaticPort})
				if ig := GetApplication().AddIgmpGroup(mvp.Name, groupAddr, device); ig != nil {
					ig.IgmpGroupLock.Lock()
					ig.AddReceiver(device, StaticPort, groupAddr, nil, getVersion(ver),
						0, 0, 0xFF)
					ig.IgmpGroupLock.Unlock()
				} else {
					logger.Warnw(ctx, "Static IGMP Group Creation Failed", log.Fields{"Addr": groupAddr})
				}
			} else {
				//Converting existing dynamic group to static group
				if !mvp.IsStaticGroup(ig.GroupName) {
					ig.updateGroupName(ig.GroupName)
				}
				// Update case: If the IGMP group is already created. just add the receiver
				logger.Infow(ctx, "Static IGMP Add received for existing group", log.Fields{"Addr": groupAddr, "Port": StaticPort})
				ig.IgmpGroupLock.Lock()
				ig.AddReceiver(device, StaticPort, groupAddr, nil, getVersion(ver),
					0, 0, 0xFF)
				ig.IgmpGroupLock.Unlock()
			}
		} else if ig != nil {
			logger.Infow(ctx, "Static IGMP Del received for existing group", log.Fields{"Addr": groupAddr, "Port": StaticPort})

			if ig.IsChannelBasedGroup {
				grpName := mvp.GetMvlanGroup(ig.GroupAddr)
				if grpName != "" {
					ig.IgmpGroupLock.Lock()
					ig.DelReceiver(device, StaticPort, groupAddr, nil, 0xFF)
					ig.IgmpGroupLock.Unlock()
					ig.updateGroupName(grpName)
				} else {
					ig.DelIgmpGroup()
				}
			} else {
				ig.IgmpGroupLock.Lock()
				ig.DelReceiver(device, StaticPort, groupAddr, nil, 0xFF)
				ig.IgmpGroupLock.Unlock()
			}
			if ig.NumDevicesActive() == 0 {
				GetApplication().DelIgmpGroup(ig)
			}
		} else {
			logger.Warnw(ctx, "Static IGMP Del received for unknown group", log.Fields{"Addr": groupAddr})
		}
	}
}

//getStaticChannelDiff - return the static channel newly added and removed from existing static group
func (mvp *MvlanProfile) getStaticChannelDiff() (newlyAdded []net.IP, removed []net.IP, common []net.IP) {

	var commonChannels []net.IP
	newChannelList, _ := mvp.getAllStaticChannels()
	existingChannelList, _ := mvp.getAllOldGroupStaticChannels()
	if len(existingChannelList) == 0 {
		return newChannelList, []net.IP{}, []net.IP{}
	}
	for _, newChannel := range append([]net.IP{}, newChannelList...) {
		for _, existChannel := range append([]net.IP{}, existingChannelList...) {

			//Remove common channels between existing and new list
			// The remaining in the below slices give the results
			// Remaining in newChannelList: Newly added
			// Remaining in existingChannelList: Removed channels
			if existChannel.Equal(newChannel) {
				existingChannelList = removeIPFromList(existingChannelList, existChannel)
				newChannelList = removeIPFromList(newChannelList, newChannel)
				commonChannels = append(commonChannels, newChannel)
				logger.Infow(ctx, "#############Channel: "+existChannel.String()+" New: "+newChannel.String(), log.Fields{"Added": newChannelList, "Removed": existingChannelList})
				break
			}
		}
	}
	return newChannelList, existingChannelList, commonChannels
}

//getGroupChannelDiff - return the channel newly added and removed from existing group
func (mvp *MvlanProfile) getGroupChannelDiff(newGroup *MvlanGroup, oldGroup *MvlanGroup) (newlyAdded []net.IP, removed []net.IP, common []net.IP) {

	var commonChannels []net.IP
	newChannelList, _ := newGroup.getAllChannels()
	existingChannelList, _ := oldGroup.getAllChannels()
	if len(existingChannelList) == 0 {
		return newChannelList, []net.IP{}, []net.IP{}
	}
	for _, newChannel := range append([]net.IP{}, newChannelList...) {
		for _, existChannel := range append([]net.IP{}, existingChannelList...) {

			//Remove common channels between existing and new list
			// The remaining in the below slices give the results
			// Remaining in newChannelList: Newly added
			// Remaining in existingChannelList: Removed channels
			if existChannel.Equal(newChannel) {
				existingChannelList = removeIPFromList(existingChannelList, existChannel)
				newChannelList = removeIPFromList(newChannelList, newChannel)
				commonChannels = append(commonChannels, newChannel)
				logger.Infow(ctx, "#############Channel: "+existChannel.String()+" New: "+newChannel.String(), log.Fields{"Added": newChannelList, "Removed": existingChannelList})
				break
			}
		}
	}
	return newChannelList, existingChannelList, commonChannels
}

// UpdateProfile - Updates the group & member info w.r.t the mvlan profile for the given device
func (mvp *MvlanProfile) UpdateProfile(deviceID string) {
	logger.Infow(ctx, "Update Mvlan Profile task triggered", log.Fields{"Mvlan": mvp.Mvlan})
	var removedStaticChannels []net.IP
	addedStaticChannels := []net.IP{}
	/* Taking mvpLock to protect the mvp groups and proxy */
	mvp.mvpLock.RLock()
	defer mvp.mvpLock.RUnlock()

	serialNo := ""
	if deviceID != "" {
		if vd := GetApplication().GetDevice(deviceID); vd != nil {
			serialNo = vd.SerialNum
			if mvp.DevicesList[serialNo] != UpdateInProgress {
				logger.Warnw(ctx, "Exiting Update Task since device not present in MvlanProfile", log.Fields{"Device": deviceID, "SerialNum": vd.SerialNum, "MvlanProfile": mvp})
				return
			}
		} else {
			logger.Errorw(ctx, "Volt Device not found. Stopping Update Mvlan Profile processing for device", log.Fields{"SerialNo": deviceID, "MvlanProfile": mvp})
			return
		}
	}

	//Update the groups based on static channels added & removed
	if mvp.containsStaticChannels() {
		addedStaticChannels, removedStaticChannels, _ = mvp.getStaticChannelDiff()
		logger.Debugw(ctx, "Update Task - Static Group Changes", log.Fields{"Added": addedStaticChannels, "Removed": removedStaticChannels})

		if len(addedStaticChannels) > 0 || len(removedStaticChannels) > 0 {
			mvp.updateStaticGroups(deviceID, []net.IP{}, removedStaticChannels)
		}
	}
	mvp.GroupsUpdated(deviceID)
	if len(addedStaticChannels) > 0 {
		mvp.updateStaticGroups(deviceID, addedStaticChannels, []net.IP{})
	}

	/* Need to handle if SSM params are modified for groups */
	for key := range mvp.Groups {
		_, _, commonChannels := mvp.getGroupChannelDiff(mvp.Groups[key], mvp.oldGroups[key])
		if mvp.checkStaticGrpSSMProxyDiff(mvp.oldProxy[key], mvp.Proxy[key]) {
			if mvp.Groups[key].IsStatic {
				/* Static group proxy modified, need to trigger membership report with new mode/src-list for existing channels */
				mvp.updateStaticGroups(deviceID, commonChannels, []net.IP{})
			} else {
				/* Dynamic group proxy modified, need to trigger membership report with new mode/src-list for existing channels */
				mvp.updateDynamicGroups(deviceID, commonChannels, []net.IP{})
			}
		}
	}

	mvp.SetUpdateStatus(serialNo, NoOp)

	if deviceID == "" || !mvp.isUpdateInProgress() {
		mvp.oldGroups = nil
	}
	if err := mvp.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": mvp.Name})
	}
	logger.Debugw(ctx, "Updated MVLAN Profile", log.Fields{"VLAN": mvp.Mvlan, "Name": mvp.Name, "Grp IPs": mvp.Groups})
}

//checkStaticGrpSSMProxyDiff- return true if the proxy of oldGroup is modified in newGroup
func (mvp *MvlanProfile) checkStaticGrpSSMProxyDiff(oldProxy *MCGroupProxy, newProxy *MCGroupProxy) bool {

	if oldProxy == nil && newProxy == nil {
		return false
	}
	if (oldProxy == nil && newProxy != nil) ||
		(oldProxy != nil && newProxy == nil) {
		return true
	}

	if oldProxy.Mode != newProxy.Mode {
		return true
	}

	oldSrcLst := oldProxy.SourceList
	newSrcLst := newProxy.SourceList
	oLen := len(oldSrcLst)
	nLen := len(newSrcLst)
	if oLen != nLen {
		return true
	}

	visited := make([]bool, nLen)

	/* check if any new IPs added in the src list, return true if present */
	for i := 0; i < nLen; i++ {
		found := false
		element := newSrcLst[i]
		for j := 0; j < oLen; j++ {
			if visited[j] {
				continue
			}
			if element.Equal(oldSrcLst[j]) {
				visited[j] = true
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	visited = make([]bool, nLen)
	/* check if any IPs removed from existing  src list, return true if removed */
	for i := 0; i < oLen; i++ {
		found := false
		element := oldSrcLst[i]
		for j := 0; j < nLen; j++ {
			if visited[j] {
				continue
			}
			if element.Equal(newSrcLst[j]) {
				visited[j] = true
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

// ProcessMode process the received mode and updated the igp
func (igc *IgmpGroupChannel) ProcessMode(port string, incl bool) {
	/* Update the mode in igp if the mode has changed */
	igp := igc.GetReceiver(port)
	if igp.Exclude && incl {
		igp.Exclude = !incl
		if igc.Exclude > 0 {
			igc.Exclude--
		}
	} else if !incl && !igp.Exclude {
		igp.Exclude = !incl
		igc.Exclude++
	}
}

func (ig *IgmpGroup) removeExpiredGroupFromDevice() {
	ig.PendingPoolLock.Lock()
	defer ig.PendingPoolLock.Unlock()

	for device, timer := range ig.PendingGroupForDevice {

		// To ensure no race-condition between the expiry time and the new Join,
		// ensure the group exists in pending pool before deletion
		groupExistsInPendingPool := true

		if !time.Now().After(timer) {
			continue
		}

		// Check if the IgmpGroup obj has no active member across any device
		// If Yes, then this group is part of global pending pool (IgmpPendingPool), hence if expired,
		// Remove only the IgmpGroup obj referenced to this device from global pool also.
		if ig.NumDevicesActive() == 0 {
			groupExistsInPendingPool = GetApplication().RemoveGroupFromPendingPool(device, ig)
		}

		// Remove the group entry from device and remove the IgmpDev Obj
		// from IgmpGrp Pending pool
		if groupExistsInPendingPool {
			ig.DeleteIgmpGroupDevice(device)
		}
	}
}

//DeleteIgmpGroupDevice - removes the IgmpGroupDevice obj from IgmpGroup and database
func (ig *IgmpGroup) DeleteIgmpGroupDevice(device string) {

	logger.Infow(ctx, "Deleting IgmpGroupDevice from IG Pending Pool", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String(), "PendingDevices": len(ig.Devices)})

	igd := ig.Devices[device]
	igd.DelMcGroup(true)
	delete(ig.Devices, device)
	delete(ig.PendingGroupForDevice, device)
	_ = db.DelIgmpDevice(igd.Mvlan, igd.GroupName, igd.GroupAddr, igd.Device)

	//If the group is not associated to any other device, then the entire Igmp Group obj itself can be removed
	if ig.NumDevicesAll() == 0 {
		logger.Infow(ctx, "Deleting IgmpGroup as all pending groups has expired", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String(), "PendingDevices": len(ig.Devices)})
		GetApplication().DelIgmpGroup(ig)
		return
	}
	if err := ig.WriteToDb(); err != nil {
		logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
	}
}

//UpdateActiveChannelSubscriberAlarm - Updates the Active Channel Subscriber Alarm
func (mvp *MvlanProfile) UpdateActiveChannelSubscriberAlarm() {
	va := GetApplication()
	logger.Debugw(ctx, "Update of Active Channel Subscriber Alarm", log.Fields{"Mvlan": mvp.Mvlan})
	for srNo := range mvp.DevicesList {
		d := va.GetDeviceBySerialNo(srNo)
		if d == nil {
			logger.Warnw(ctx, "Device info not found", log.Fields{"Device_SrNo": srNo, "Mvlan": mvp.Mvlan})
			return
		}
		d.Ports.Range(func(key, value interface{}) bool {
			//port := key.(string)
			vp := value.(*VoltPort)
			if vp.Type != VoltPortTypeAccess {
				return true
			}
			if mvp.MaxActiveChannels > vp.ActiveChannels && vp.ChannelPerSubAlarmRaised {
				serviceName := GetMcastServiceForSubAlarm(vp, mvp)
				logger.Debugw(ctx, "Clearing-SendActiveChannelPerSubscriberAlarm-due-to-update", log.Fields{"ActiveChannels": vp.ActiveChannels, "ServiceName": serviceName})
				vp.ChannelPerSubAlarmRaised = false
			} else if mvp.MaxActiveChannels < vp.ActiveChannels && !vp.ChannelPerSubAlarmRaised {
				/* When the max active channel count is reduced via update, we raise an alarm.
				   But the previous excess channels still exist until a leave or expiry */
				serviceName := GetMcastServiceForSubAlarm(vp, mvp)
				logger.Debugw(ctx, "Raising-SendActiveChannelPerSubscriberAlarm-due-to-update", log.Fields{"ActiveChannels": vp.ActiveChannels, "ServiceName": serviceName})
				vp.ChannelPerSubAlarmRaised = true
			}
			return true
		})
	}
}

//TriggerAssociatedFlowDelete - Re-trigger delete for pending delete flows
func (mvp *MvlanProfile) TriggerAssociatedFlowDelete(device string) bool {
	mvp.mvpFlowLock.Lock()

	cookieList := []uint64{}
	flowMap := mvp.PendingDeleteFlow[device]

	for cookie := range flowMap {
		cookieList = append(cookieList, convertToUInt64(cookie))
	}
	mvp.mvpFlowLock.Unlock()

	if len(cookieList) == 0 {
		return false
	}

	for _, cookie := range cookieList {
		if vd := GetApplication().GetDevice(device); vd != nil {
			flow := &of.VoltFlow{}
			flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
			subFlow := of.NewVoltSubFlow()
			subFlow.Cookie = cookie
			flow.SubFlows[cookie] = subFlow
			logger.Infow(ctx, "Retriggering Vnet Delete Flow", log.Fields{"Device": device, "Mvlan": mvp.Mvlan.String(), "Cookie": cookie})
			err := mvp.DelFlows(vd, flow)
			if err != nil {
				logger.Warnw(ctx, "De-Configuring IGMP Flow for device failed ", log.Fields{"Device": device, "err": err})
			}
		}
	}
	return true
}

// JsonMarshal wrapper function for json Marshal MvlanProfile
func (mvp *MvlanProfile) JsonMarshal() ([]byte, error) {
	return json.Marshal(MvlanProfile{
		Name:                mvp.Name,
		Mvlan:               mvp.Mvlan,
		PonVlan:             mvp.PonVlan,
		Groups:              mvp.Groups,
		Proxy:               mvp.Proxy,
		Version:             mvp.Version,
		IsPonVlanPresent:    mvp.IsPonVlanPresent,
		IsChannelBasedGroup: mvp.IsChannelBasedGroup,
		DevicesList:         mvp.DevicesList,
		MaxActiveChannels:   mvp.MaxActiveChannels,
		PendingDeleteFlow:   mvp.PendingDeleteFlow,
		DeleteInProgress:    mvp.DeleteInProgress,
		IgmpServVersion:     mvp.IgmpServVersion,
	})
}
