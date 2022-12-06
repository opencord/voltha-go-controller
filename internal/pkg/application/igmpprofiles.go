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
	"strconv"
	"strings"
	"sync"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

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
func (mvp *MvlanProfile) WriteToDb(cntx context.Context) error {

        if mvp.DeleteInProgress {
                logger.Warnw(ctx, "Skipping Redis Update for MvlanProfile, MvlanProfile delete in progress", log.Fields{"Mvlan": mvp.Mvlan})
                return nil
        }

        mvp.Version = database.PresentVersionMap[database.MvlanPath]
        b, err := json.Marshal(mvp)
        if err != nil {
                return err
        }
        if err1 := db.PutMvlan(cntx, uint16(mvp.Mvlan), string(b)); err1 != nil {
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
func (mvp *MvlanProfile) DelFromDb(cntx context.Context) {
        _ = db.DelMvlan(cntx, uint16(mvp.Mvlan))
}

//DelFlows - Triggers flow deletion after registering for flow indication event
func (mvp *MvlanProfile) DelFlows(cntx context.Context, device *VoltDevice, flow *of.VoltFlow) error {
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
        if err := mvp.WriteToDb(cntx); err != nil {
                logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": mvp.Name})
        }
        return cntlr.GetController().DelFlows(cntx, device.NniPort, device.Name, flow)
}

//FlowRemoveSuccess - Process flow success indication
func (mvp *MvlanProfile) FlowRemoveSuccess(cntx context.Context, cookie string, device string) {
        mvp.mvpFlowLock.Lock()
        defer mvp.mvpFlowLock.Unlock()

        logger.Infow(ctx, "Mvlan Flow Remove Success Notification", log.Fields{"MvlanProfile": mvp.Name, "Cookie": cookie, "Device": device})

        if _, ok := mvp.PendingDeleteFlow[device]; ok {
                delete(mvp.PendingDeleteFlow[device], cookie)
        }

        if err := mvp.WriteToDb(cntx); err != nil {
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

// IsStaticGroup to check if group is static
func (mvp *MvlanProfile) IsStaticGroup(groupName string) bool {
        return mvp.Groups[groupName].IsStatic
}

// generateGroupKey to generate group key
func (mvp *MvlanProfile) generateGroupKey(name string, ipAddr string) string {
        if mvp.IsChannelBasedGroup {
                return mvp.Mvlan.String() + "_" + ipAddr
        }
        return mvp.Mvlan.String() + "_" + name
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

//pushIgmpMcastFlows - Adds all IGMP related flows (generic DS flow & static group flows)
func (mvp *MvlanProfile) pushIgmpMcastFlows(cntx context.Context, OLTSerialNum string) {

        mvp.mvpLock.RLock()
        defer mvp.mvpLock.RUnlock()

        if mvp.DevicesList[OLTSerialNum] == Nil {
                logger.Infow(ctx, "Mvlan Profile not configure for device", log.Fields{"Device": OLTSerialNum, "Mvlan": mvp.Mvlan})
                return
        }

        d, _ := GetApplication().GetDeviceBySerialNo(OLTSerialNum)
        if d == nil {
                logger.Warnw(ctx, "Skipping Igmp & Mcast Flow processing: Device Not Found", log.Fields{"Device_SrNo": OLTSerialNum, "Mvlan": mvp.Mvlan})
                return
        }

        p := d.GetPort(d.NniPort)

        if p != nil && p.State == PortStateUp {
                logger.Infow(ctx, "NNI Port Status is: UP & Vlan Enabled", log.Fields{"Device": d, "port": p})

                //Push Igmp DS Control Flows
                err := mvp.ApplyIgmpDSFlowForMvp(cntx, d.Name)
                if err != nil {
                        logger.Errorw(ctx, "DS IGMP Flow Add Failed for device",
                                log.Fields{"Reason": err.Error(), "device": d.Name})
                }

                //Trigger Join for static channels
                if channelList, containsStatic := mvp.getAllStaticChannels(); containsStatic {
                        mvp.ProcessStaticGroup(cntx, d.Name, channelList, true)
                } else {
                        logger.Infow(ctx, "No Static Channels Present", log.Fields{"mvp": mvp.Name, "Mvlan": mvp.Mvlan})
                }
        }
}
//removeIgmpMcastFlows - Removes all IGMP related flows (generic DS flow & static group flows)
func (mvp *MvlanProfile) removeIgmpMcastFlows(cntx context.Context, oltSerialNum string) {

        mvp.mvpLock.RLock()
        defer mvp.mvpLock.RUnlock()

        if d, _ := GetApplication().GetDeviceBySerialNo(oltSerialNum); d != nil {
                p := d.GetPort(d.NniPort)
                if p != nil {
                        logger.Infow(ctx, "NNI Port Status is: UP", log.Fields{"Device": d, "port": p})

                        // ***Do not change the order***
                        // When Vlan is disabled, the process end is determined by the DS Igmp flag in device

                        //Trigger Leave for static channels
                        if channelList, containsStatic := mvp.getAllStaticChannels(); containsStatic {
                                mvp.ProcessStaticGroup(cntx, d.Name, channelList, false)
                        } else {
                                logger.Infow(ctx, "No Static Channels Present", log.Fields{"mvp": mvp.Name, "Mvlan": mvp.Mvlan})
                        }

                        //Remove all dynamic members for the Mvlan Profile
                        GetApplication().IgmpGroups.Range(func(key, value interface{}) bool {
                                ig := value.(*IgmpGroup)
                                if ig.Mvlan == mvp.Mvlan {
                                        igd := ig.Devices[d.Name]
                                        ig.DelIgmpGroupDevice(cntx, igd)
                                        if ig.NumDevicesActive() == 0 {
                                                GetApplication().DelIgmpGroup(cntx, ig)
                                        }
                                }
                                return true
                        })

                        //Remove DS Igmp trap flow
                        err := mvp.RemoveIgmpDSFlowForMvp(cntx, d.Name)
                        if err != nil {
                                logger.Errorw(ctx, "DS IGMP Flow Del Failed", log.Fields{"Reason": err.Error(), "device": d.Name})
                        }
                }
        }
}

// ApplyIgmpDSFlowForMvp to apply Igmp DS flow for mvlan.
func (mvp *MvlanProfile) ApplyIgmpDSFlowForMvp(cntx context.Context, device string) error {
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
                        err = cntlr.GetController().AddFlows(cntx, d.NniPort, device, flows)
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
func (mvp *MvlanProfile) RemoveIgmpDSFlowForMvp(cntx context.Context, device string) error {

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

                err = mvp.DelFlows(cntx, d, flows)
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
func (mvp *MvlanProfile) updateStaticGroups(cntx context.Context, deviceID string, added []net.IP, removed []net.IP) {

        //Update static group configs for all associated devices
        updateGroups := func(key interface{}, value interface{}) bool {
                d := value.(*VoltDevice)

                if mvp.DevicesList[d.SerialNum] == Nil {
                        logger.Infow(ctx, "Mvlan Profile not configure for device", log.Fields{"Device": d, "Profile Device List": mvp.DevicesList})
                        return true
                }
                //TODO if mvp.IsChannelBasedGroup {
                mvp.ProcessStaticGroup(cntx, d.Name, added, true)
                mvp.ProcessStaticGroup(cntx, d.Name, removed, false)
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
func (mvp *MvlanProfile) updateDynamicGroups(cntx context.Context, deviceID string, added []net.IP, removed []net.IP) {

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
                                if igd, ok := ig.getIgmpGroupDevice(cntx, d.Name); ok {
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
                                                        if change, _ := igc.ProcessSources(cntx, port, ip, incl); change {
                                                                groupModified = true
                                                        }
                                                        igc.ProcessMode(port, incl)

                                                        if err := igp.WriteToDb(cntx, igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
                                                                logger.Errorw(ctx, "Igmp group port Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
                                                        }
                                                }
                                                // If the group is modified as this is the first receiver or due to include/exclude list modification
                                                // send a report to the upstream multicast servers
                                                if groupModified {
                                                        logger.Debug(ctx, "Group Modified and IGMP report sent to the upstream server")
                                                        igc.SendReport(false)
                                                }
                                                if err := igc.WriteToDb(cntx); err != nil {
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
func (mvp *MvlanProfile) GroupsUpdated(cntx context.Context, deviceID string) {

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
                                                        ig.HandleGroupMigration(cntx, deviceID, channelIP)
                                                } else {
                                                        if (ig.IsGroupStatic) && mvp.IsStaticGroup(ig.GroupName) {
                                                                if ig.GroupName != mvp.GetStaticGroupName(channelIP) {
                                                                        ig.HandleGroupMigration(cntx, deviceID, channelIP)
                                                                }
                                                        }
                                                        continue
                                                }
                                        } else {
                                                logger.Debugw(ctx, "Channel Removed", log.Fields{"Channel": channel, "Group": grpName})
                                                ig.DelIgmpChannel(cntx, deviceID, net.ParseIP(channel))
                                                if ig.NumDevicesActive() == 0 {
                                                        GetApplication().DelIgmpGroup(cntx, ig)
                                                }
                                        }
                                }
                                ig.IsGroupStatic = mvp.IsStaticGroup(ig.GroupName)
                                if err := ig.WriteToDb(cntx); err != nil {
                                        logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
                                }
                                return true
                        }
                }
                logger.Debugw(ctx, "Group Removed", log.Fields{"Channel": ig.GroupAddr, "Group": grpName, "ChannelBasedGroup": ig.IsChannelBasedGroup})
                ig.DelIgmpGroup(cntx)
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

// ProcessStaticGroup - Process Static Join/Leave Req for static channels
func (mvp *MvlanProfile) ProcessStaticGroup(cntx context.Context, device string, groupAddresses []net.IP, isJoin bool) {

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
                                if ig := GetApplication().AddIgmpGroup(cntx, mvp.Name, groupAddr, device); ig != nil {
                                        ig.IgmpGroupLock.Lock()
                                        ig.AddReceiver(cntx, device, StaticPort, groupAddr, nil, getVersion(ver),
                                                0, 0, 0xFF)
                                        ig.IgmpGroupLock.Unlock()
                                } else {
                                        logger.Warnw(ctx, "Static IGMP Group Creation Failed", log.Fields{"Addr": groupAddr})
                                }
                        } else {
                                //Converting existing dynamic group to static group
                                if !mvp.IsStaticGroup(ig.GroupName) {
                                        ig.updateGroupName(cntx, ig.GroupName)
                                }
                                // Update case: If the IGMP group is already created. just add the receiver
                                logger.Infow(ctx, "Static IGMP Add received for existing group", log.Fields{"Addr": groupAddr, "Port": StaticPort})
                                ig.IgmpGroupLock.Lock()
                                ig.AddReceiver(cntx, device, StaticPort, groupAddr, nil, getVersion(ver),
                                        0, 0, 0xFF)
                                ig.IgmpGroupLock.Unlock()
                        }
                } else if ig != nil {
                        logger.Infow(ctx, "Static IGMP Del received for existing group", log.Fields{"Addr": groupAddr, "Port": StaticPort})

                        if ig.IsChannelBasedGroup {
                                grpName := mvp.GetMvlanGroup(ig.GroupAddr)
                                if grpName != "" {
                                        ig.IgmpGroupLock.Lock()
                                        ig.DelReceiver(cntx, device, StaticPort, groupAddr, nil, 0xFF)
                                        ig.IgmpGroupLock.Unlock()
                                        ig.updateGroupName(cntx, grpName)
                                } else {
                                        ig.DelIgmpGroup(cntx)
                                }
                        } else {
                                ig.IgmpGroupLock.Lock()
                                ig.DelReceiver(cntx, device, StaticPort, groupAddr, nil, 0xFF)
                                ig.IgmpGroupLock.Unlock()
                        }
                        if ig.NumDevicesActive() == 0 {
                                GetApplication().DelIgmpGroup(cntx, ig)
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
func (mvp *MvlanProfile) UpdateProfile(cntx context.Context, deviceID string) {
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
                        mvp.updateStaticGroups(cntx, deviceID, []net.IP{}, removedStaticChannels)
                }
        }
        mvp.GroupsUpdated(cntx, deviceID)
        if len(addedStaticChannels) > 0 {
                mvp.updateStaticGroups(cntx, deviceID, addedStaticChannels, []net.IP{})
        }

        /* Need to handle if SSM params are modified for groups */
        for key := range mvp.Groups {
                _, _, commonChannels := mvp.getGroupChannelDiff(mvp.Groups[key], mvp.oldGroups[key])
                if mvp.checkStaticGrpSSMProxyDiff(mvp.oldProxy[key], mvp.Proxy[key]) {
                        if mvp.Groups[key].IsStatic {
                                /* Static group proxy modified, need to trigger membership report with new mode/src-list for existing channels */
                                mvp.updateStaticGroups(cntx, deviceID, commonChannels, []net.IP{})
                        } else {
                                /* Dynamic group proxy modified, need to trigger membership report with new mode/src-list for existing channels */
                                mvp.updateDynamicGroups(cntx, deviceID, commonChannels, []net.IP{})
                        }
                }
        }

        mvp.SetUpdateStatus(serialNo, NoOp)

        if deviceID == "" || !mvp.isUpdateInProgress() {
                mvp.oldGroups = nil
        }
        if err := mvp.WriteToDb(cntx); err != nil {
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


//UpdateActiveChannelSubscriberAlarm - Updates the Active Channel Subscriber Alarm
func (mvp *MvlanProfile) UpdateActiveChannelSubscriberAlarm() {
        va := GetApplication()
        logger.Debugw(ctx, "Update of Active Channel Subscriber Alarm", log.Fields{"Mvlan": mvp.Mvlan})
        for srNo := range mvp.DevicesList {
                d, _ := va.GetDeviceBySerialNo(srNo)
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
func (mvp *MvlanProfile) TriggerAssociatedFlowDelete(cntx context.Context, device string) bool {
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
                        err := mvp.DelFlows(cntx, vd, flow)
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

// WriteToDb is utility to write Igmp Config Info to database
func (igmpProfile *IgmpProfile) WriteToDb(cntx context.Context) error {
        igmpProfile.Version = database.PresentVersionMap[database.IgmpProfPath]
        b, err := json.Marshal(igmpProfile)
        if err != nil {
                return err
        }
        if err1 := db.PutIgmpProfile(cntx, igmpProfile.ProfileID, string(b)); err1 != nil {
                return err1
        }
        return nil
}
