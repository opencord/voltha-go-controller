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
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

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
func (ig *IgmpGroup) IgmpGroupReInit(cntx context.Context, name string, gip net.IP) {

	logger.Infow(ctx, "Reinitialize Igmp Group", log.Fields{"GroupID": ig.GroupID, "OldName": ig.GroupName, "Name": name, "OldAddr": ig.GroupAddr.String(), "GroupAddr": gip.String()})

	ig.GroupName = name
	if ig.IsChannelBasedGroup {
		ig.GroupAddr = gip
	} else {
		ig.GroupAddr = net.ParseIP("0.0.0.0")
	}

	for _, igd := range ig.Devices {
		igd.IgmpGroupDeviceReInit(cntx, ig)
	}
}

// updateGroupName to update group name
func (ig *IgmpGroup) updateGroupName(cntx context.Context, newGroupName string) {
	if !ig.IsChannelBasedGroup {
		logger.Errorw(ctx, "Group name update not supported for GroupChannel based group", log.Fields{"Ig": ig})
		return
	}
	oldKey := ig.getKey()
	ig.GroupName = newGroupName
	for _, igd := range ig.Devices {
		igd.updateGroupName(cntx, newGroupName)
	}
	if err := ig.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
	}
	if !ig.IsChannelBasedGroup {
		_ = db.DelIgmpGroup(cntx, oldKey)
	}
}

//HandleGroupMigration - handles migration of group members between static & dynamic
func (ig *IgmpGroup) HandleGroupMigration(cntx context.Context, deviceID string, groupAddr net.IP) {

	var group *layers.IGMPv3GroupRecord
	app := GetApplication()
	if deviceID == "" {
		logger.Infow(ctx, "Handle Group Migration Request for all devices", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "IG": ig.GroupName, "Mvlan": ig.Mvlan})
		for device := range ig.Devices {
			ig.HandleGroupMigration(cntx, device, groupAddr)
		}
	} else {
		logger.Infow(ctx, "Handle Group Migration Request", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "IG": ig.GroupName})
		var newIg *IgmpGroup
		receivers := ig.DelIgmpChannel(cntx, deviceID, groupAddr)
		if ig.NumDevicesActive() == 0 {
			app.DelIgmpGroup(cntx, ig)
		}
		if newIg = app.GetIgmpGroup(ig.Mvlan, groupAddr); newIg == nil {
			logger.Infow(ctx, "IG Group doesn't exist, creating new group", log.Fields{"DeviceID": deviceID, "GroupAddr": groupAddr, "IG": ig.GroupName, "Mvlan": ig.Mvlan})
			if newIg = app.AddIgmpGroup(cntx, app.GetMvlanProfileByTag(ig.Mvlan).Name, groupAddr, deviceID); newIg == nil {
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
			newIg.AddReceiver(cntx, deviceID, port, groupAddr, group, igp.Version, igp.CVlan, igp.Pbit, ponPort)
		}
		newIg.IgmpGroupLock.Unlock()
	}
}

// AddIgmpGroupDevice add a device to the group which happens when the first receiver of the device
// is added to the IGMP group.
func (ig *IgmpGroup) AddIgmpGroupDevice(cntx context.Context, device string, id uint32, version uint8) *IgmpGroupDevice {
	logger.Infow(ctx, "Adding Device to IGMP group", log.Fields{"Device": device, "GroupName": ig.GroupName})
	igd := NewIgmpGroupDevice(device, ig, id, version)
	ig.Devices[device] = igd
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device, "GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}
	return igd
}

// DelIgmpGroupDevice delete the device from the group which happens when we receive a leave or when
// there is not response for IGMP query from the receiver
func (ig *IgmpGroup) DelIgmpGroupDevice(cntx context.Context, igd *IgmpGroupDevice) {
	logger.Infow(ctx, "Deleting Device from IGMP group", log.Fields{"Device": igd.Device, "Name": ig.GroupName})
	va := GetApplication()
	countersToBeUpdated := false
	if igd.NumReceivers() != 0 {
		countersToBeUpdated = true
	}
	igd.DelAllChannels(cntx)

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
		_ = db.DelIgmpDevice(cntx, igd.Mvlan, ig.GroupName, ig.GroupAddr, igd.Device)
		delete(ig.Devices, igd.Device)
	}
}

// AddReceiver delete the device from the group which happens when we receive a leave or when
// there is not response for IGMP query from the receiver
func (ig *IgmpGroup) AddReceiver(cntx context.Context, device string, port string, groupIP net.IP,
	group *layers.IGMPv3GroupRecord, ver uint8, cvlan uint16, pbit uint8, ponPort uint32) {

	logger.Debugw(ctx, "Adding Receiver", log.Fields{"Port": port})
	if igd, ok := ig.getIgmpGroupDevice(cntx, device); !ok {
		igd = ig.AddIgmpGroupDevice(cntx, device, ig.GroupID, ver)
		igd.AddReceiver(cntx, port, groupIP, group, ver, cvlan, pbit, ponPort)
	} else {
		logger.Infow(ctx, "IGMP Group Receiver", log.Fields{"IGD": igd.Device})
		igd.AddReceiver(cntx, port, groupIP, group, ver, cvlan, pbit, ponPort)
	}
}

func (ig *IgmpGroup) getIgmpGroupDevice(cntx context.Context, device string) (*IgmpGroupDevice, bool) {
	ig.PendingPoolLock.Lock()
	defer ig.PendingPoolLock.Unlock()

	if _, ok := ig.PendingGroupForDevice[device]; ok {
		logger.Infow(ctx, "Removing the IgmpGroupDevice from pending pool", log.Fields{"GroupID": ig.GroupID, "Device": device, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String()})
		delete(ig.PendingGroupForDevice, device)
		if err := ig.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
		}
	}
	igd, ok := ig.Devices[device]
	return igd, ok
}

// DelReceiveronDownInd deletes a receiver which is the combination of device (OLT)
// and port on Port Down event
func (ig *IgmpGroup) DelReceiveronDownInd(cntx context.Context, device string, port string, ponPortID uint32) {
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
		igd.DelReceiver(cntx, groupAddr, port, nil, ponPortID)
	}

	if igd.NumReceivers() == 0 {
		ig.DelIgmpGroupDevice(cntx, igd)
	}
}

// DelReceiver deletes a receiver which is the combination of device (OLT)
// and port
func (ig *IgmpGroup) DelReceiver(cntx context.Context, device string, port string, groupAddr net.IP, group *layers.IGMPv3GroupRecord, ponPortID uint32) {
	logger.Debugw(ctx, "Deleting Receiver for Group", log.Fields{"Device": device, "port": port, "GroupIP": groupAddr.String()})
	if igd, ok := ig.Devices[device]; ok {
		//igd.DelReceiverForGroupAddr(groupAddr, port)
		igd.DelReceiver(cntx, groupAddr, port, group, ponPortID)
		if igd.NumReceivers() == 0 {
			ig.DelIgmpGroupDevice(cntx, igd)
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
func (ig *IgmpGroup) DelIgmpChannel(cntx context.Context, deviceID string, groupAddr net.IP) map[string]*IgmpGroupPort {
	logger.Infow(ctx, "Deleting Channel from devices", log.Fields{"Device": deviceID, "Group": ig.GroupName, "Channel": groupAddr.String()})
	if deviceID == "" {
		for device := range ig.Devices {
			ig.DelIgmpChannel(cntx, device, groupAddr)
		}
		return nil
	}
	igd := ig.Devices[deviceID]
	receivers := igd.DelChannelReceiver(cntx, groupAddr)
	if igd.NumReceivers() == 0 {
		ig.DelIgmpGroupDevice(cntx, igd)
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
func (ig *IgmpGroup) Tick(cntx context.Context) {
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
			igd.QueryExpiry(cntx)
			// This will keep it quiet till the next query time and then
			// it will be reset to a value after the query initiation time
			igd.QueryExpiryTime = igd.NextQueryTime
			logger.Debugw(ctx, "Expiry", log.Fields{"NextQuery": igd.NextQueryTime, "Expiry": igd.QueryExpiryTime})
			igdChangeCnt++
			if igd.NumReceivers() == 0 {
				ig.DelIgmpGroupDevice(cntx, igd)
				continue
			}
		}

		igdChangeCnt += igd.Tick()

		if igdChangeCnt > 0 {
			if err := igd.WriteToDb(cntx); err != nil {
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
func (ig *IgmpGroup) QueryExpiry(cntx context.Context) {
	for _, igd := range ig.Devices {
		if _, ok := GetApplication().DevicesDisc.Load(igd.Device); ok {
			igd.QueryExpiry(cntx)
			if igd.NumReceivers() == 0 {
				ig.DelIgmpGroupDevice(cntx, igd)
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
func (ig *IgmpGroup) RestoreDevices(cntx context.Context) {

	ig.migrateIgmpDevices(cntx)
	devices, _ := db.GetIgmpDevices(cntx, ig.Mvlan, ig.GroupName, ig.GroupAddr)
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
				if err := igd.WriteToDb(cntx); err != nil {
					logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device,
								"GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
				}
			}

			ig.Devices[igd.Device] = igd
			if ig.IsChannelBasedGroup {
				channel, _ := db.GetIgmpChannel(cntx, igd.Mvlan, igd.GroupName, igd.Device, igd.GroupAddr)
				igd.RestoreChannel(cntx, []byte(channel))
			} else {
				igd.RestoreChannels(cntx)
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

// WriteToDb is utility to write Igmp Group Info to database
func (ig *IgmpGroup) WriteToDb(cntx context.Context) error {
        ig.Version = database.PresentVersionMap[database.IgmpGroupPath]
        b, err := json.Marshal(ig)
        if err != nil {
                return err
        }
        if err1 := db.PutIgmpGroup(cntx, ig.getKey(), string(b)); err1 != nil {
                return err1
        }
        return nil
}

// UpdateIgmpGroup : When the pending group is allocated to new
func (ig *IgmpGroup) UpdateIgmpGroup(cntx context.Context, oldKey, newKey string) {

        //If the group is allocated to same McastGroup, no need to update the
        //IgmpGroups map
        if oldKey == newKey {
                return
        }
        logger.Infow(ctx, "Updating Igmp Group with new MVP Group Info", log.Fields{"OldKey": oldKey, "NewKey": newKey, "GroupID": ig.GroupID})

        GetApplication().IgmpGroups.Delete(oldKey)
        _ = db.DelIgmpGroup(cntx, oldKey)

        GetApplication().IgmpGroups.Store(newKey, ig)
        if err := ig.WriteToDb(cntx); err != nil {
                logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
        }
}

func (ig *IgmpGroup) removeExpiredGroupFromDevice(cntx context.Context) {
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
                        ig.DeleteIgmpGroupDevice(cntx, device)
                }
        }
}

//DeleteIgmpGroupDevice - removes the IgmpGroupDevice obj from IgmpGroup and database
func (ig *IgmpGroup) DeleteIgmpGroupDevice(cntx context.Context, device string) {

        logger.Infow(ctx, "Deleting IgmpGroupDevice from IG Pending Pool", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String(), "PendingDevices": len(ig.Devices)})

        igd := ig.Devices[device]
        igd.DelMcGroup(true)
        delete(ig.Devices, device)
        delete(ig.PendingGroupForDevice, device)
        _ = db.DelIgmpDevice(cntx, igd.Mvlan, igd.GroupName, igd.GroupAddr, igd.Device)

        //If the group is not associated to any other device, then the entire Igmp Group obj itself can be removed
        if ig.NumDevicesAll() == 0 {
                logger.Infow(ctx, "Deleting IgmpGroup as all pending groups has expired", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr.String(), "PendingDevices": len(ig.Devices)})
                GetApplication().DelIgmpGroup(cntx, ig)
                return
        }
        if err := ig.WriteToDb(cntx); err != nil {
                logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
        }
}

// DelIgmpGroup deletes all devices for the provided igmp group
func (ig *IgmpGroup) DelIgmpGroup(cntx context.Context) {
        logger.Infow(ctx, "Deleting All Device for Group", log.Fields{"Group": ig.GroupName})
        for _, igd := range ig.Devices {
                ig.DelIgmpGroupDevice(cntx, igd)
        }
        GetApplication().DelIgmpGroup(cntx, ig)
}
