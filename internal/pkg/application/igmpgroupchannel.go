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

package application

import (
	"context"
	"encoding/json"
	"net"

	"github.com/google/gopacket/layers"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	common "voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/log"
)

// IgmpGroupChannel structure
type IgmpGroupChannel struct {
	CurReceivers map[string]*IgmpGroupPort `json:"-"`
	NewReceivers map[string]*IgmpGroupPort `json:"-"`
	proxyCfg     **IgmpProfile
	IgmpProxyIP  **net.IP `json:"-"`
	ServVersion  *uint8
	Device       string
	GroupName    string
	GroupAddr    net.IP
	ExcludeList  []net.IP
	IncludeList  []net.IP `json:"-"`
	Exclude      int
	GroupID      uint32
	Mvlan        of.VlanType
	Version      uint8
}

// NewIgmpGroupChannel is constructor for a channel. The default IGMP version is set to 3
// as the protocol defines the way to manage backward compatibility
// The implementation handles simultaneous presence of lower versioned
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
func (igc *IgmpGroupChannel) RestorePorts(cntx context.Context) {
	igc.migrateIgmpPorts(cntx)
	ports, _ := db.GetIgmpRcvrs(cntx, igc.Mvlan, igc.GroupAddr, igc.Device)
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
	if err := igc.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
}

// WriteToDb is utility to write IGMPGroupChannel Info to database
func (igc *IgmpGroupChannel) WriteToDb(cntx context.Context) error {
	b, err := json.Marshal(igc)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpChannel(cntx, igc.Mvlan, igc.GroupName, igc.Device, igc.GroupAddr, string(b)); err1 != nil {
		return err1
	}
	logger.Info(ctx, "IGC Updated")
	return nil
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

// computeExclList computes intersection of previous & current src list
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
func (igc *IgmpGroupChannel) ProcessSources(cntx context.Context, port string, ip []net.IP, incl bool) (bool, bool) {
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
			   Only if there is any modification in the src list by proxy config update only then we need to update */
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
	if err := igp.WriteToDb(cntx, igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
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
func (igc *IgmpGroupChannel) AddReceiver(cntx context.Context, port string, group *layers.IGMPv3GroupRecord, cvlan uint16, pbit uint8) bool {
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
				igc.AddMcFlow(cntx)
				logger.Debugw(ctx, "Added New Flow", log.Fields{"Group": igc.GroupAddr.String(), "Port": port})
			}
			if !incl {
				igc.Exclude++
			}
		}
	}

	// Process the include/exclude list which may end up modifying the group
	if change, _ := igc.ProcessSources(cntx, port, ip, incl); change {
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

	if err := igc.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	if err := igp.WriteToDb(cntx, igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
		logger.Errorw(ctx, "Igmp group port Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	return isNewReceiver
}

// DelReceiver is called when Query expiry happened for a receiver. This removes the receiver from the
// the group
func (igc *IgmpGroupChannel) DelReceiver(cntx context.Context, port string, incl bool, srcList []net.IP) bool {
	// The receiver may exist either in NewReceiver list or
	// the CurReceivers list. Find and remove it from either
	// of the lists.
	logger.Debugw(ctx, "Deleting Receiver from Channel", log.Fields{"Port": port, "SrcList": srcList, "Incl": incl})
	logger.Debugw(ctx, "New Receivers", log.Fields{"New": igc.NewReceivers})
	logger.Debugw(ctx, "Current Receivers", log.Fields{"Current": igc.CurReceivers})

	receiversUpdated := false
	groupModified, receiverSrcListEmpty := igc.ProcessSources(cntx, port, srcList, incl)

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
		_ = db.DelIgmpRcvr(cntx, igc.Mvlan, igc.GroupAddr, igc.Device, port)
	}

	if igc.NumReceivers() == 0 {
		igc.DelMcFlow(cntx)
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
	if err := igc.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
	}
	logger.Infow(ctx, "Updated Receiver info for Channel", log.Fields{"Current": igc.CurReceivers, "New": igc.NewReceivers})

	return receiversUpdated
}

// DelAllReceivers deletes all receiver for the provided igmp device
func (igc *IgmpGroupChannel) DelAllReceivers(cntx context.Context) {
	logger.Infow(ctx, "Deleting All Receiver for Channel", log.Fields{"Device": igc.Device, "Channel": igc.GroupAddr.String()})
	_ = db.DelAllIgmpRcvr(cntx, igc.Mvlan, igc.GroupAddr, igc.Device)
	igc.Exclude = 0
	igc.DelMcFlow(cntx)
	igc.SendLeaveToServer()
	logger.Infow(ctx, "MC Flow deleted and Leave sent", log.Fields{"Channel": igc.GroupAddr.String(), "Device": igc.Device})
}

// Igmpv2ReportPacket build an IGMPv2 Report for the upstream servers
func (igc *IgmpGroupChannel) Igmpv2ReportPacket() ([]byte, error) {
	logger.Debugw(ctx, "Building IGMP version 2 Report", log.Fields{"Device": igc.Device})
	return IgmpReportv2Packet(igc.GroupAddr, igc.Mvlan, (*igc.proxyCfg).IgmpCos, **igc.IgmpProxyIP)
}

// Igmpv3ReportPacket build an IGMPv3 Report for the upstream servers
func (igc *IgmpGroupChannel) Igmpv3ReportPacket() ([]byte, error) {
	logger.Debugw(ctx, "Building IGMP version 3 Report", log.Fields{"Device": igc.Device, "Exclude": igc.Exclude})
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
	// igc.Version:         igmp version received from RG.
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
func (igc *IgmpGroupChannel) AddMcFlow(cntx context.Context) {
	flow, err := igc.BuildMcFlow()
	if err != nil {
		logger.Warnw(ctx, "MC Flow Build Failed", log.Fields{"Reason": err.Error()})
		return
	}
	port, _ := GetApplication().GetNniPort(igc.Device)
	_ = cntlr.GetController().AddFlows(cntx, port, igc.Device, flow)
}

// DelMcFlow deletes flow from the device when the last receiver leaves
func (igc *IgmpGroupChannel) DelMcFlow(cntx context.Context) {
	flow, err := igc.BuildMcFlow()
	if err != nil {
		logger.Warnw(ctx, "MC Flow Build Failed", log.Fields{"Reason": err.Error()})
		return
	}
	flow.ForceAction = true
	device := GetApplication().GetDevice(igc.Device)

	if mvpIntf, _ := GetApplication().MvlanProfilesByTag.Load(igc.Mvlan); mvpIntf != nil {
		mvp := mvpIntf.(*MvlanProfile)
		err := mvp.DelFlows(cntx, device, flow)
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
	//      return nil, err
	//}
	//inport, err := va.GetPortID(nni)
	//if err != nil {
	//      return nil, err
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
	// igc.Version:         igmp version received from RG.
	// igc.ServVersion: igmp version received from BNG or IgmpVerToServer present in proxy igmp conf.

	logger.Debugw(ctx, "Sending IGMP leave upstream", log.Fields{"Device": igc.Device})
	if *igc.ServVersion == IgmpVersion2 || getVersion((*igc.proxyCfg).IgmpVerToServer) == IgmpVersion2 {
		igc.IgmpLeaveToServer()
	} else {
		igc.SendReport(false)
	}
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
