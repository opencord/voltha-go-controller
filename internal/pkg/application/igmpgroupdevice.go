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
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

// IgmpGroupDevice : IGMP Group Device manages the IGMP group for all listerns on
// a single OLT. It aggregates reports received on a single group
// and performs the count. It is responsible for sending upstream
// report when the first listener joins and is responsible for
// sending responses to upstream queries
type IgmpGroupDevice struct {
	PonPortChannelMap *util.ConcurrentMap `json:"-"` // [ponPortId]*PonPortChannels
	proxyCfg          *IgmpProfile        // IgmpSrcIp from IgmpProfile is not used, it is kept for backward compatibility
	IgmpProxyIP       *net.IP             `json:"-"`
	ServVersion       *uint8
	Device            string
	SerialNo          string
	GroupName         string
	GroupChannels     sync.Map `json:"-"` // [ipAddr]*IgmpGroupChannel
	PortChannelMap    sync.Map `json:"-"` // [portName][]net.IP
	NextQueryTime     time.Time
	QueryExpiryTime   time.Time
	RecvVersionExpiry time.Time
	ServVersionExpiry time.Time
	GroupAddr         net.IP
	GroupID           uint32
	Mvlan             of.VlanType
	PonVlan           of.VlanType
	RecvVersion       uint8
	IsPonVlanPresent  bool
	GroupInstalled    bool
}

// NewIgmpGroupDevice is constructor for a device. The default IGMP version is set to 3
// as the protocol defines the way to manage backward compatibility
// The implementation handles simultaneous presence of lower versioned
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
func (igd *IgmpGroupDevice) IgmpGroupDeviceReInit(cntx context.Context, ig *IgmpGroup) {
	logger.Infow(ctx, "Reinitialize Igmp Group Device", log.Fields{"Device": igd.Device, "GroupID": ig.GroupID, "OldName": igd.GroupName, "Name": ig.GroupName, "OldAddr": igd.GroupAddr.String(), "GroupAddr": ig.GroupAddr.String()})

	if (igd.GroupName != ig.GroupName) || !igd.GroupAddr.Equal(ig.GroupAddr) {
		_ = db.DelIgmpDevice(cntx, igd.Mvlan, igd.GroupName, igd.GroupAddr, igd.Device)
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
	if err := igd.WriteToDb(cntx); err != nil {
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
func (igd *IgmpGroupDevice) updateGroupName(cntx context.Context, newGroupName string) {
	oldName := igd.GroupName
	igd.GroupName = newGroupName
	updateGroupName := func(key, value interface{}) bool {
		igc := value.(*IgmpGroupChannel)
		igc.GroupName = newGroupName
		if err := igc.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
		}
		_ = db.DelIgmpChannel(cntx, igc.Mvlan, oldName, igc.Device, igc.GroupAddr)
		return true
	}
	igd.GroupChannels.Range(updateGroupName)
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
	_ = db.DelIgmpDevice(cntx, igd.Mvlan, oldName, igd.GroupAddr, igd.Device)
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
func (igd *IgmpGroupDevice) RestoreChannel(cntx context.Context, igmpGroupChannel []byte) {
	if igc, err := NewIgmpGroupChannelFromBytes(igmpGroupChannel); err == nil {
		igc.ServVersion = igd.ServVersion
		igc.IgmpProxyIP = &igd.IgmpProxyIP
		igc.proxyCfg = &igd.proxyCfg
		igd.GroupChannels.Store(igc.GroupAddr.String(), igc)
		igc.RestorePorts(cntx)

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
func (igd *IgmpGroupDevice) RestoreChannels(cntx context.Context) {
	igd.migrateIgmpChannels(cntx)
	channels, _ := db.GetIgmpChannels(cntx, igd.Mvlan, igd.GroupName, igd.Device)
	for _, channel := range channels {
		b, ok := channel.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		igd.RestoreChannel(cntx, b)
	}
}

// WriteToDb is utility to write IGMP Group Device Info to the database
func (igd *IgmpGroupDevice) WriteToDb(cntx context.Context) error {
	b, err := json.Marshal(igd)
	if err != nil {
		return err
	}
	if err1 := db.PutIgmpDevice(cntx, igd.Mvlan, igd.GroupName, igd.GroupAddr, igd.Device, string(b)); err1 != nil {
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

// AddReceiver add the receiver to the device and perform other actions such as adding the group
// to the physical device, add members, add flows to point the MC packets to the
// group. Also, send a IGMP report upstream if there is a change in the group
func (igd *IgmpGroupDevice) AddReceiver(cntx context.Context, port string, groupAddr net.IP,
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
		igd.AddNewReceiver(cntx, port, groupAddr, group, cvlan, pbit, ponPortID)
		return
	}

	isNewReceiver := igc.AddReceiver(cntx, port, group, cvlan, pbit)
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
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
}

// AddNewReceiver to add new receiver
func (igd *IgmpGroupDevice) AddNewReceiver(cntx context.Context, port string, groupAddr net.IP, group *layers.IGMPv3GroupRecord, cvlan uint16, pbit uint8, ponPortID uint32) {
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
	igc.AddReceiver(cntx, port, group, cvlan, pbit)
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
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
func (igd *IgmpGroupDevice) DelReceiver(cntx context.Context, groupAddr net.IP, port string, group *layers.IGMPv3GroupRecord, ponPortID uint32) {
	logger.Debugw(ctx, "Deleting Receiver for Device", log.Fields{"port": port, "GroupIP": groupAddr.String()})
	var igc *IgmpGroupChannel
	var igcIntf interface{}
	var ok bool
	var srcList []net.IP
	incl := false
	mvp := GetApplication().GetMvlanProfileByTag(igd.Mvlan)

	if _, ok = mvp.Proxy[igd.GroupName]; ok {
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
	if ok := igc.DelReceiver(cntx, port, incl, srcList); !ok {
		return
	}

	if igc.NumReceivers() == 0 {
		igd.DelIgmpGroupChannel(cntx, igc)
	}
	igd.DelPortFromChannel(port, groupAddr)
	isGroupModified := igd.RemoveChannelFromChannelsPerPon(port, groupAddr, ponPortID)

	//Remove port from receiver if port has no subscription to any of the group channels
	if isGroupModified {
		igd.ModMcGroup()
	}
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
}

// DelChannelReceiver is called when Query expiry happened for a receiver. This removes the receiver from the
// the group
func (igd *IgmpGroupDevice) DelChannelReceiver(cntx context.Context, groupAddr net.IP) map[string]*IgmpGroupPort {
	portsRemoved := make(map[string]*IgmpGroupPort)
	groupModified := false
	// ifEmpty := true
	igcIntf, _ := igd.GroupChannels.Load(groupAddr.String())

	if igcIntf == nil {
		return portsRemoved
	}
	igc := igcIntf.(*IgmpGroupChannel)

	for port, igp := range igc.NewReceivers {
		_ = db.DelIgmpRcvr(cntx, igc.Mvlan, igc.GroupAddr, igc.Device, port) //TODO: Y not here
		igd.DelPortFromChannel(port, igc.GroupAddr)
		ponPortID := GetApplication().GetPonPortID(igd.Device, port)
		groupModified = igd.RemoveChannelFromChannelsPerPon(port, igc.GroupAddr, ponPortID)
		delete(igc.NewReceivers, port)
		portsRemoved[port] = igp
	}
	for port, igp := range igc.CurReceivers {
		_ = db.DelIgmpRcvr(cntx, igc.Mvlan, igc.GroupAddr, igc.Device, port)
		igd.DelPortFromChannel(port, igc.GroupAddr)
		ponPortID := GetApplication().GetPonPortID(igd.Device, port)
		groupModified = igd.RemoveChannelFromChannelsPerPon(port, igc.GroupAddr, ponPortID)
		delete(igc.CurReceivers, port)
		portsRemoved[port] = igp
	}

	igc.DelMcFlow(cntx)
	igd.DelIgmpGroupChannel(cntx, igc)
	igc.Exclude = 0
	igc.SendLeaveToServer()

	if groupModified {
		igd.ModMcGroup()
	}
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
	logger.Debugw(ctx, "Deleted the receiver Flow", log.Fields{"Num Receivers": igc.NumReceivers()})
	return portsRemoved
}

// DelIgmpGroupChannel to delete igmp group channel
func (igd *IgmpGroupDevice) DelIgmpGroupChannel(cntx context.Context, igc *IgmpGroupChannel) {
	if igc.NumReceivers() != 0 {
		igc.DelAllReceivers(cntx)
	}
	_ = db.DelIgmpChannel(cntx, igc.Mvlan, igc.GroupName, igc.Device, igc.GroupAddr)
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
//      db.DelIgmpChannel(igc.GroupName, igc.Device, igc.GroupAddr)
//      delete(igd.GroupChannels, igc.GroupAddr.String())
//      logger.Debugw(ctx, "Deleted the Channel", log.Fields{"Num Receivers": igc.NumReceivers()})
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

// DelAllChannels deletes all receiver for the provided igmp device
func (igd *IgmpGroupDevice) DelAllChannels(cntx context.Context) {
	logger.Infow(ctx, "Deleting All Channel for Device", log.Fields{"Device": igd.Device, "Group": igd.GroupName})
	delGroupChannels := func(key interface{}, value interface{}) bool {
		igc := value.(*IgmpGroupChannel)
		igd.DelIgmpGroupChannel(cntx, igc)
		return true
	}
	igd.GroupChannels.Range(delGroupChannels)
}

// ProcessQuery process query received from the upstream IGMP server
func (igd *IgmpGroupDevice) ProcessQuery(cntx context.Context, groupAddr net.IP, ver uint8) {
	logger.Debugw(ctx, "Received Query From Server", log.Fields{"Version": ver})
	if ver != *igd.ServVersion {
		igd.ServVersionExpiry = time.Now().Add(time.Duration(2*igd.proxyCfg.KeepAliveInterval) * time.Second)
		*igd.ServVersion = ver
		mvp := GetApplication().GetMvlanProfileByTag(igd.Mvlan)
		if err := mvp.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": mvp.Name})
		}
	}
	if igc, ok := igd.GroupChannels.Load(groupAddr.String()); ok {
		igc.(*IgmpGroupChannel).SendReport(true)
		return
	}
	logger.Infow(ctx, "No Members for Channel. Dropping Igmp Query", log.Fields{"Group": igd.GroupName, "Channel": groupAddr.String()})
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

// QueryExpiry processes query expiry. Upon expiry, take stock of the situation
// add either retain/release the group based on number of receivers left
func (igd *IgmpGroupDevice) QueryExpiry(cntx context.Context) {
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
				igd.DelReceiver(cntx, igc.GroupAddr, portKey, nil, ponPortID)
			}

			port.QueryTimeoutCount++
			logger.Debugw(ctx, "Expired Port TimeoutCount", log.Fields{"count": port.QueryTimeoutCount})
			if port.QueryTimeoutCount >= (*igc.proxyCfg).KeepAliveCount {
				logger.Errorw(ctx, "Expiry Timeout count exceeded. Trigger delete receiver", log.Fields{"PortKey": portKey,
					"GroupAddr": igc.GroupAddr, "Count": port.QueryTimeoutCount})
				igd.DelReceiver(cntx, igc.GroupAddr, portKey, nil, ponPortID)
				SendQueryExpiredEventGroupSpecific(portKey, igd, igc)
			} else {
				_ = port.WriteToDb(cntx, igc.Mvlan, igc.GroupAddr, igc.Device)
			}
		}
		return true
	}
	igd.GroupChannels.Range(handleQueryExp)
}
