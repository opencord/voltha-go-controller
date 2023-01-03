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
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"
	common "voltha-go-controller/internal/pkg/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"voltha-go-controller/database"
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"
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
	// AllSystemsMulticastGroupIP
	AllSystemsMulticastGroupIP = net.ParseIP("224.0.0.1")
	// igmpSrcMac for the proxy
	igmpSrcMac string
)

func init() {
	RegisterPacketHandler(IGMP, ProcessIgmpPacket)
}

// ProcessIgmpPacket : CallBack function registered with application to handle IGMP packetIn
func ProcessIgmpPacket(cntx context.Context, device string, port string, pkt gopacket.Packet) {
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

//AddToPendingPool - adds Igmp Device obj to pending pool
func AddToPendingPool(cntx context.Context, device string, groupKey string) bool {

	logger.Infow(ctx, "Add Device to IgmpGroup Pending Pool", log.Fields{"Device": device, "GroupKey": groupKey})
	if grp, ok := GetApplication().IgmpGroups.Load(groupKey); ok {
		ig := grp.(*IgmpGroup)
		ig.PendingPoolLock.Lock()
		logger.Infow(ctx, "Adding Device to IgmpGroup Pending Pool", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String()})
		ig.PendingGroupForDevice[device] = time.Now().Add(time.Duration(GroupExpiryTime) * time.Minute)
		ig.PendingPoolLock.Unlock()
		if err := ig.WriteToDb(cntx); err != nil {
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

// RestoreIgmpGroupsFromDb to restore igmp groups from database
func (va *VoltApplication) RestoreIgmpGroupsFromDb(cntx context.Context) {

	groups, _ := db.GetIgmpGroups(cntx)
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
		ig.RestoreDevices(cntx)

		if ig.NumDevicesActive() == 0 {
			va.AddGroupToPendingPool(&ig)
		}
		logger.Infow(ctx, "Restored Groups", log.Fields{"igGroupID": ig.GroupID, "igGroupName": ig.GroupName, "igMvlan": ig.Mvlan})
	}
}

// AddIgmpGroup : When the first IGMP packet is received, the MVLAN profile is identified
// for the IGMP group and grp obj is obtained from the available pending pool of groups.
// If not, new group obj will be created based on available group IDs
func (va *VoltApplication) AddIgmpGroup(cntx context.Context, mvpName string, gip net.IP, device string) *IgmpGroup {

	var ig *IgmpGroup
	if mvp, grpName := va.GetMvlanProfileForMcIP(mvpName, gip); mvp != nil {
		if ig = va.GetGroupFromPendingPool(mvp.Mvlan, device); ig != nil {
			logger.Infow(ctx, "Igmp Group obtained from global pending pool", log.Fields{"MvlanProfile": mvpName, "GroupID": ig.GroupID, "Device": device, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String()})
			oldKey := mvp.generateGroupKey(ig.GroupName, ig.GroupAddr.String())
			ig.IgmpGroupReInit(cntx, grpName, gip)
			ig.IsGroupStatic = mvp.Groups[grpName].IsStatic
			ig.UpdateIgmpGroup(cntx, oldKey, ig.getKey())
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
		if err := ig.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
		}
		return ig
	}
	logger.Errorw(ctx, "GetMvlan Pro failed", log.Fields{"Group": gip})
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

// DelIgmpGroup : When the last subscriber leaves the IGMP group across all the devices
// the IGMP group is removed.
func (va *VoltApplication) DelIgmpGroup(cntx context.Context, ig *IgmpGroup) {

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
				_ = db.DelIgmpGroup(cntx, grpKey)
			} else {
				logger.Infow(ctx, "Skipping IgmpGroup Device. Pending Igmp Group Devices present", log.Fields{"GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String(), "PendingDevices": len(ig.Devices)})
				va.AddGroupToPendingPool(ig)
				if err := ig.WriteToDb(cntx); err != nil {
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
func (va *VoltApplication) ProcessIgmpv2Pkt(cntx context.Context, device string, port string, pkt gopacket.Packet) {
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
			ig.AddReceiver(cntx, device, port, igmpv2.GroupAddress, nil, IgmpVersion2, dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
			ig.IgmpGroupLock.Unlock()
		} else {
			// Create the IGMP group and then add the receiver to the group
			if ig := va.AddIgmpGroup(cntx, vpv.MvlanProfileName, igmpv2.GroupAddress, device); ig != nil {
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
				ig.AddReceiver(cntx, device, port, igmpv2.GroupAddress, nil, IgmpVersion2, dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
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
			ig.DelReceiver(cntx, device, port, igmpv2.GroupAddress, nil, ponPortID)
			ig.IgmpGroupLock.Unlock()
			if ig.NumDevicesActive() == 0 {
				va.DelIgmpGroup(cntx, ig)
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
			va.processIgmpQueries(cntx, device, pktVlan, IgmpVersion2)
		} else {
			if ig := va.GetIgmpGroup(pktVlan, igmpv2.GroupAddress); ig != nil {
				ig.IgmpGroupLock.Lock()
				igd, ok := ig.Devices[device]
				if ok {
					igd.ProcessQuery(cntx, igmpv2.GroupAddress, IgmpVersion2)
				} else {
					logger.Warnw(ctx, "IGMP Device not found", log.Fields{"Device": device, "Group": igmpv2.GroupAddress})
				}
				ig.IgmpGroupLock.Unlock()
			}
		}
	}
}

// ProcessIgmpv3Pkt : Process IGMPv3 packet
func (va *VoltApplication) ProcessIgmpv3Pkt(cntx context.Context, device string, port string, pkt gopacket.Packet) {
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
					ig.AddReceiver(cntx, device, port, group.MulticastAddress, &group, IgmpVersion3,
						dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
					ig.IgmpGroupLock.Unlock()
				} else {
					// Create the IGMP group and then add the receiver to the group
					logger.Infow(ctx, "IGMP Join received for new group", log.Fields{"Addr": group.MulticastAddress, "Port": port})
					if ig := va.AddIgmpGroup(cntx, vpv.MvlanProfileName, group.MulticastAddress, device); ig != nil {
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
						ig.AddReceiver(cntx, device, port, group.MulticastAddress, &group, IgmpVersion3,
							dot1Q.VLANIdentifier, dot1Q.Priority, ponPortID)
						ig.IgmpGroupLock.Unlock()
					} else {
						logger.Warnw(ctx, "IGMP Group Creation Failed", log.Fields{"Addr": group.MulticastAddress})
					}
				}
			} else if ig != nil {
				logger.Infow(ctx, "IGMP Leave received for existing group", log.Fields{"Addr": group.MulticastAddress, "Port": port})
				ig.IgmpGroupLock.Lock()
				ig.DelReceiver(cntx, device, port, group.MulticastAddress, &group, ponPortID)
				ig.IgmpGroupLock.Unlock()
				if ig.NumDevicesActive() == 0 {
					va.DelIgmpGroup(cntx, ig)
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
			va.processIgmpQueries(cntx, device, pktVlan, IgmpVersion3)
		} else {
			if ig := va.GetIgmpGroup(pktVlan, igmpv3.GroupAddress); ig != nil {
				ig.IgmpGroupLock.Lock()
				igd, ok := ig.Devices[device]
				if ok {
					igd.ProcessQuery(cntx, igmpv3.GroupAddress, IgmpVersion3)
				} else {
					logger.Warnw(ctx, "IGMP Device not found", log.Fields{"Device": device, "Group": igmpv3.GroupAddress})
				}
				ig.IgmpGroupLock.Unlock()
			}
		}
	}
}

// processIgmpQueries to process the igmp queries
func (va *VoltApplication) processIgmpQueries(cntx context.Context, device string, pktVlan of.VlanType, version uint8) {
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
			igd.ProcessQuery(cntx, net.ParseIP(groupAddr), version)
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
func (va *VoltApplication) IgmpProcessPkt(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	igmpl := pkt.Layer(layers.LayerTypeIGMP)
	if igmpl == nil {
		logger.Error(ctx, "Invalid IGMP packet arrived as IGMP packet")
		return
	}
	if igmp, ok := igmpl.(*layers.IGMPv1or2); ok {
		// This is an IGMPv2 packet.
		logger.Debugw(ctx, "IGMPv2 Packet Received", log.Fields{"IPAddr": igmp.GroupAddress})
		va.ProcessIgmpv2Pkt(cntx, device, port, pkt)
		return
	}
	if igmpv3, ok := igmpl.(*layers.IGMP); ok {
		logger.Debugw(ctx, "IGMPv3 Packet Received", log.Fields{"NumOfGroups": igmpv3.NumberOfGroupRecords})
		va.ProcessIgmpv3Pkt(cntx, device, port, pkt)
	}
}

// IgmpPacketInd for igmp packet indication
func (va *VoltApplication) IgmpPacketInd(device string, port string, pkt gopacket.Packet) {
	pt := NewIgmpPacketTask(device, port, pkt)
	va.IgmpTasks.AddTask(pt)
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
func (va *VoltApplication) RestoreMvlansFromDb(cntx context.Context) {
	mvlans, _ := db.GetMvlans(cntx)
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
func (va *VoltApplication) UpdateMvlanProfile(cntx context.Context, name string, vlan of.VlanType, groups map[string][]string, activeChannelCount int, proxy map[string]common.MulticastGroupProxy) error {

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
			if err := mvp.WriteToDb(cntx); err != nil {
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
	if err := mvp.WriteToDb(cntx); err != nil {
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
func (va *VoltApplication) AddMcastConfig(cntx context.Context, MvlanProfileID string, IgmpProfileID string, IgmpProxyIP string, OltSerialNum string) error {
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
	if err := mcastCfg.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "McastConfig Write to DB failed", log.Fields{"OltSerialNum": mcastCfg.OltSerialNum, "MvlanProfileID": mcastCfg.MvlanProfileID})
	}
	va.addOltToMvlan(cntx, MvlanProfileID, OltSerialNum)

	return nil
}

func (va *VoltApplication) addOltToMvlan(cntx context.Context, MvlanProfileID string, OltSerialNum string) {
	var mvp *MvlanProfile
	if mvpIntf, ok := va.MvlanProfilesByName.Load(MvlanProfileID); ok {
		servVersion := IgmpVersion0
		mvp = mvpIntf.(*MvlanProfile)
		mvp.DevicesList[OltSerialNum] = NoOp
		mvp.IgmpServVersion[OltSerialNum] = &servVersion
		if err := mvp.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
		}
		mvp.pushIgmpMcastFlows(cntx, OltSerialNum)
	}
}

func (va *VoltApplication) delOltFromMvlan(cntx context.Context, MvlanProfileID string, OltSerialNum string) {
	var mvp *MvlanProfile
	if mvpIntf, ok := va.MvlanProfilesByName.Load(MvlanProfileID); ok {
		mvp = mvpIntf.(*MvlanProfile)
		//Delete from mvp list
		mvp.removeIgmpMcastFlows(cntx, OltSerialNum)
		delete(mvp.DevicesList, OltSerialNum)
		if err := mvp.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
		}
	}
}

// DelMcastConfig for addition of a MVLAN profile
func (va *VoltApplication) DelMcastConfig(cntx context.Context, MvlanProfileID string, IgmpProfileID string, IgmpProxyIP string, OltSerialNum string) {

	va.delOltFromMvlan(cntx, MvlanProfileID, OltSerialNum)
	va.deleteMcastConfig(OltSerialNum, MvlanProfileID)
	_ = db.DelMcastConfig(cntx, McastConfigKey(OltSerialNum, MvlanProfileID))
	if d := va.GetDeviceBySerialNo(OltSerialNum); d != nil {
		if mvp := va.GetMvlanProfileByName(MvlanProfileID); mvp != nil {
			va.RemoveGroupsFromPendingPool(cntx, d.Name, mvp.Mvlan)
		}
	}
}

// DelAllMcastConfig for deletion of all mcast config
func (va *VoltApplication) DelAllMcastConfig(cntx context.Context, OltSerialNum string) error {

	deleteIndividualMcastConfig := func(key interface{}, value interface{}) bool {
		mcastCfg := value.(*McastConfig)
		if mcastCfg.OltSerialNum == OltSerialNum {
			va.DelMcastConfig(cntx, mcastCfg.MvlanProfileID, mcastCfg.IgmpProfileID, mcastCfg.IgmpProxyIP.String(), mcastCfg.OltSerialNum)
		}
		return true
	}
	va.McastConfigMap.Range(deleteIndividualMcastConfig)
	return nil
}

// UpdateMcastConfig for addition of a MVLAN profile
func (va *VoltApplication) UpdateMcastConfig(cntx context.Context, MvlanProfileID string, IgmpProfileID string, IgmpProxyIP string, OltSerialNum string) error {

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

	if err := mcastCfg.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "McastConfig Write to DB failed", log.Fields{"OltSerialNum": mcastCfg.OltSerialNum, "MvlanProfileID": mcastCfg.MvlanProfileID})
	}

	return nil
}

// WriteToDb is utility to write Mcast config Info to database
func (mc *McastConfig) WriteToDb(cntx context.Context) error {
	mc.Version = database.PresentVersionMap[database.McastConfigPath]
	b, err := json.Marshal(mc)
	if err != nil {
		return err
	}
	if err1 := db.PutMcastConfig(cntx, McastConfigKey(mc.OltSerialNum, mc.MvlanProfileID), string(b)); err1 != nil {
		return err1
	}
	return nil
}

// RestoreMcastConfigsFromDb to read from the DB and restore Mcast configs
func (va *VoltApplication) RestoreMcastConfigsFromDb(cntx context.Context) {
	mcastConfigs, _ := db.GetMcastConfigs(cntx)
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
func (va *VoltApplication) AddMvlanProfile(cntx context.Context, name string, mvlan of.VlanType, ponVlan of.VlanType,
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
				return va.UpdateMvlanProfile(cntx, name, mvlan, groups, activeChannelsPerPon, proxy)
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

	if err := mvp.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Mvlan profile Write to DB failed", log.Fields{"ProfileName": mvp.Name})
	}

	return nil
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

// IgmpTick for igmp tick info
func (va *VoltApplication) IgmpTick(cntx context.Context) {
	tickCount++
	if (tickCount % 1000) == 0 {
		logger.Debugw(ctx, "Time @ Tick", log.Fields{"Tick": tickCount, "Time": time.Now()})
	}
	igmptick := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		if ig.NumDevicesActive() != 0 {
			if tickCount%10 == ig.Hash()%10 {
				ig.IgmpGroupLock.Lock()
				ig.Tick(cntx)
				ig.IgmpGroupLock.Unlock()
				if ig.NumDevicesActive() == 0 {
					va.DelIgmpGroup(cntx, ig)
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
func (va *VoltApplication) AddIgmpProfile(cntx context.Context, igmpProfileConfig *common.IGMPConfig) error {
	var igmpProfile *IgmpProfile

	if igmpProfileConfig.ProfileID == DefaultIgmpProfID {
		logger.Info(ctx, "Updating default IGMP profile")
		return va.UpdateIgmpProfile(cntx, igmpProfileConfig)
	}

	igmpProfile = va.checkIgmpProfileMap(igmpProfileConfig.ProfileID)
	if igmpProfile == nil {
		igmpProfile = newIgmpProfile(igmpProfileConfig)
	} else {
		logger.Errorw(ctx, "IGMP profile already exists", log.Fields{"IgmpProfile": igmpProfileConfig.ProfileID})
		return errors.New("IGMP Profile already exists")
	}

	va.storeIgmpProfileMap(igmpProfileConfig.ProfileID, igmpProfile)

	if err := igmpProfile.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp profile Write to DB failed", log.Fields{"profileID": igmpProfile.ProfileID})
	}

	return nil
}

// checkIgmpProfileMap to get Igmp Profile. If not found return nil
func (va *VoltApplication) checkIgmpProfileMap(name string) *IgmpProfile {
	if igmpProfileIntf, ok := va.IgmpProfilesByName.Load(name); ok {
		return igmpProfileIntf.(*IgmpProfile)
	}
	return nil
}

func (va *VoltApplication) resetIgmpProfileToDefault(cntx context.Context) {
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

	if err := igmpProf.WriteToDb(cntx); err != nil {
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

// TODO - DelIgmpProfile for deleting IGMP Profile based on profile Id
// func (va *VoltApplication) DelIgmpProfile(cntx context.Context, igmpProfileConfig *common.IGMPConfig) error {
// 	// Deletion of default igmp profile is blocked from submgr. Keeping additional check for safety.
// 	if igmpProfileConfig.ProfileID == DefaultIgmpProfID {
// 		logger.Info(ctx, "Resetting default IGMP profile")
// 		va.resetIgmpProfileToDefault(cntx)
// 		return nil
// 	}
// 	igmpProfile := va.checkIgmpProfileMap(igmpProfileConfig.ProfileID)
// 	if igmpProfile == nil {
// 		logger.Warnw(ctx, "Igmp Profile not found. Unable to delete", log.Fields{"Profile ID": igmpProfileConfig.ProfileID})
// 		return nil
// 	}

// 	va.deleteIgmpProfileMap(igmpProfileConfig.ProfileID)

// 	_ = db.DelIgmpProfile(cntx, igmpProfileConfig.ProfileID)

// 	return nil
// }

// DelIgmpProfile for deleting IGMP Profile based on profile Id
func (va *VoltApplication) DelIgmpProfile(cntx context.Context, profileID string) error {
	// Deletion of default igmp profile is blocked from submgr. Keeping additional check for safety.
	if profileID == DefaultIgmpProfID {
		logger.Info(ctx, "Resetting default IGMP profile")
		va.resetIgmpProfileToDefault(cntx)
		return nil
	}
	igmpProfile := va.checkIgmpProfileMap(profileID)
	if igmpProfile == nil {
		logger.Warnw(ctx, "Igmp Profile not found. Unable to delete", log.Fields{"Profile ID": profileID})
		return nil
	}

	va.deleteIgmpProfileMap(profileID)

	err := db.DelIgmpProfile(cntx, profileID)
	if err != nil {
		logger.Errorw(ctx, "Failed to delete Igmp profile from DB", log.Fields{"Error": err})
		return err
	}

	return nil
}

//UpdateIgmpProfile for addition of IGMP Profile
func (va *VoltApplication) UpdateIgmpProfile(cntx context.Context, igmpProfileConfig *common.IGMPConfig) error {
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

	if err := igmpProfile.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp profile Write to DB failed", log.Fields{"profileID": igmpProfile.ProfileID})
	}

	return nil
}

// RestoreIGMPProfilesFromDb to read from the DB and restore IGMP Profiles
func (va *VoltApplication) RestoreIGMPProfilesFromDb(cntx context.Context) {
	// Loading IGMP profiles
	igmpProfiles, _ := db.GetIgmpProfiles(cntx)
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

// DelMvlanProfile for deletion of a MVLAN group
func (va *VoltApplication) DelMvlanProfile(cntx context.Context, name string) error {
	if mvpIntf, ok := va.MvlanProfilesByName.Load(name); ok {
		mvp := mvpIntf.(*MvlanProfile)

		if len(mvp.DevicesList) == 0 {
			mvp.DeleteInProgress = true
			mvp.DelFromDb(cntx)
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

	if queryPkt, err := Igmpv2QueryPacket(AllSystemsMulticastGroupIP, cVlan, *proxyIP, pbit, proxyCfg.MaxResp); err == nil {
		if err := cntlr.GetController().PacketOutReq(device, port, port, queryPkt, false); err != nil {
			logger.Warnw(ctx, "General Igmpv2 Query Failed to send", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
		} else {
			logger.Debugw(ctx, "General Igmpv2 Query Sent", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
		}
	}
	if getVersion(proxyCfg.IgmpVerToServer) == IgmpVersion3 {
		if queryPkt, err := Igmpv3QueryPacket(AllSystemsMulticastGroupIP, cVlan, *proxyIP, pbit, proxyCfg.MaxResp); err == nil {
			if err := cntlr.GetController().PacketOutReq(device, port, port, queryPkt, false); err != nil {
				logger.Warnw(ctx, "General Igmpv3 Query Failed to send", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
			} else {
				logger.Debugw(ctx, "General Igmpv3 Query Sent", log.Fields{"Device": device, "Port": port, "Packet": queryPkt, "Pbit": pbit})
			}
		}
	}
}

// ReceiverDownInd to send receiver down indication
func (va *VoltApplication) ReceiverDownInd(cntx context.Context, device string, port string) {
	logger.Infow(ctx, " Receiver Indication: DOWN", log.Fields{"device": device, "port": port})

	ponPortID := va.GetPonPortID(device, port)

	del := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		ig.IgmpGroupLock.Lock()
		ig.DelReceiveronDownInd(cntx, device, port, ponPortID)
		ig.IgmpGroupLock.Unlock()
		if ig.NumDevicesActive() == 0 {
			va.DelIgmpGroup(cntx, ig)
		}
		return true
	}
	va.IgmpGroups.Range(del)
}
