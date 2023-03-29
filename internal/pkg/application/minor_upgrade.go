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
	"errors"
	"net"

	"strings"

	"voltha-go-controller/database"
	common "voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/log"

	"github.com/google/gopacket/layers"
)

type paramsUpdationFunc func(cntx context.Context, hash string, value interface{}) error

// map to store conversion functions
var updationMap = map[string]paramsUpdationFunc{
	database.VnetPath:       updateVnets,
	database.VpvPath:        updateVpvs,
	database.ServicePath:    updateServices,
	database.MvlanPath:      updateMvlans,
	database.IgmpGroupPath:  updateIgmpGroups,
	database.IgmpDevicePath: updateIgmpDevices,
	database.IgmpProfPath:   updateIgmpProfiles,
}

// UpdateDbData to update database data
func UpdateDbData(cntx context.Context, dbPath, hash string, value interface{}) error {
	if migrationFunc, ok := updationMap[dbPath]; ok {
		err := migrationFunc(cntx, hash, value)
		if err != nil {
			logger.Error(ctx, "Error in migrating data\n")
			return errors.New("Error-in-migration")
		}
	}
	return nil
}

// This function modifyies the old data as per current version requirement and also
// returns the new path on which the modified data has to be written
func updateServices(cntx context.Context, hash string, value interface{}) error {
	param := value.(*VoltService)
	param.VnetID = VnetKey(param.SVlan, param.CVlan, param.UniVlan)
	return nil
}

// This function modifyies the old data as per current version requirement and also
// returns the new path on which the modified data has to be written
func updateVnets(cntx context.Context, hash string, value interface{}) error {
	param := value.(*VoltVnet)
	newKey := VnetKey(param.SVlan, param.CVlan, param.UniVlan)
	if newKey != hash {
		// Delete the older key
		_ = db.DelVnet(cntx, hash)
	} else {
		// Update SVlan Tag Protocol id param with default valud if not present
		if param.SVlanTpid == 0 {
			param.SVlanTpid = layers.EthernetTypeDot1Q
		}
	}
	param.Name = newKey
	if param.DevicesList == nil || len(param.DevicesList) == 0 {
		param.DevicesList = append(param.DevicesList, "") // Empty OLT serial number as of now since submgr won't have proper serial num
	}
	return nil
}

// This function modifyies the old data as per current version requirement and also
// returns the new path on which the modified data has to be written
func updateVpvs(cntx context.Context, hash string, value interface{}) error {
	//var param VoltPortVnet
	param := value.(*VoltPortVnet)

	// Update SVlan Tag Protocol id param with default valud if not present
	if param.SVlanTpid == 0 {
		param.SVlanTpid = layers.EthernetTypeDot1Q
	}

	if strings.Count(hash, "-") > 1 {
		logger.Info(ctx, "Already upgraded")
		return nil
	}

	// Add the vpv under new path
	param.WriteToDb(cntx)
	// delete the older path
	fullPath := database.BasePath + database.VpvPath + hash
	if err := db.Del(cntx, fullPath); err != nil {
		logger.Errorw(ctx, "Vpv Delete from DB failed", log.Fields{"Error": err, "key": fullPath})
	}
	return nil
}

func updateMvlans(cntx context.Context, hash string, value interface{}) error {
	param := value.(*MvlanProfile)
	if param.DevicesList == nil || len(param.DevicesList) == 0 {
		param.DevicesList = make(map[string]OperInProgress) // Empty OLT serial number as of now since submgr won't have proper serial num
		if err := param.WriteToDb(cntx); err != nil {
			logger.Errorw(ctx, "Mvlan profile write to DB failed", log.Fields{"ProfileName": param.Name})
		}
	}
	if _, ok := param.Groups[common.StaticGroup]; ok {
		param.Groups[common.StaticGroup].IsStatic = true
	}
	return nil
}

// This function modifyies the old Igmp Group data as per current version requirement and also
// returns the new path on which the modified data has to be written
func updateIgmpGroups(cntx context.Context, hash string, value interface{}) error {
	ig := value.(*IgmpGroup)
	logger.Infow(ctx, "Group Data Migration", log.Fields{"ig": ig, "GroupAddr": ig.GroupAddr, "hash": hash})
	if ig.GroupAddr == nil {
		ig.GroupAddr = net.ParseIP("0.0.0.0")
	}
	if err := ig.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group Write to DB failed", log.Fields{"groupName": ig.GroupName})
	}

	return nil
}

// This function modifyies the old Igmp  Device data as per current version requirement and also
// returns the new path on which the modified data has to be written
func updateIgmpDevices(cntx context.Context, hash string, value interface{}) error {
	igd := value.(*IgmpGroupDevice)
	logger.Infow(ctx, "Group Device Migration", log.Fields{"igd": igd, "GroupAddr": igd.GroupAddr, "hash": hash})
	if igd.GroupAddr == nil {
		igd.GroupAddr = net.ParseIP("0.0.0.0")
	}
	if err := igd.WriteToDb(cntx); err != nil {
		logger.Errorw(ctx, "Igmp group device Write to DB failed", log.Fields{"Device": igd.Device,
			"GroupName": igd.GroupName, "GroupAddr": igd.GroupAddr.String()})
	}

	return nil
}

// This function modifyies the old Igmp  Profile data as per current version requirement and also
// returns the new path on which the modified data has to be written
func updateIgmpProfiles(cntx context.Context, hash string, value interface{}) error {
	igmpProfile := value.(*IgmpProfile)
	logger.Infow(ctx, "IGMP Profile Migration", log.Fields{"igmpProfile": igmpProfile, "hash": hash})
	return nil
}

func (ig *IgmpGroup) migrateIgmpDevices(cntx context.Context) {
	devices, _ := db.GetPrevIgmpDevices(cntx, ig.Mvlan, ig.GroupName)
	logger.Infow(ctx, "Migratable Devices", log.Fields{"Devices": devices})
	for _, device := range devices {
		b, ok := device.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		if igd, err := NewIgmpGroupDeviceFromBytes(b); err == nil {
			key := database.BasePath + database.IgmpDevicePath + igd.Mvlan.String() + "/" + igd.GroupName + "/" + igd.Device
			logger.Infow(ctx, "Deleting old entry", log.Fields{"Path": key, "igd": igd})
			if err := db.Del(cntx, key); err != nil {
				logger.Errorw(ctx, "Igmp Group Delete from DB failed", log.Fields{"Error": err, "key": key})
			}
			if err := UpdateDbData(cntx, database.IgmpDevicePath, key, igd); err != nil {
				logger.Warnw(ctx, "Group Device Migration failed", log.Fields{"IGD": igd, "Error": err})
			} else {
				logger.Infow(ctx, "Group Device Migrated", log.Fields{"IGD": igd})
			}
		} else {
			logger.Warnw(ctx, "Unable to decode device from database", log.Fields{"str": string(b)})
		}
	}
}

func (igd *IgmpGroupDevice) migrateIgmpChannels(cntx context.Context) {
	channels, _ := db.GetPrevIgmpChannels(cntx, igd.GroupName, igd.Device)
	logger.Infow(ctx, "Migratable Channels", log.Fields{"Channels": channels})
	for _, channel := range channels {
		b, ok := channel.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		if igc, err := NewIgmpGroupChannelFromBytes(b); err == nil {
			key := database.BasePath + database.IgmpChannelPath + igc.GroupName + "/" + igc.Device + "/" + igc.GroupAddr.String()
			logger.Infow(ctx, "Deleting old entry", log.Fields{"Path": key, "igc": igc})
			if err := db.Del(cntx, key); err != nil {
				logger.Errorw(ctx, "Igmp Group Delete from DB failed", log.Fields{"Error": err, "key": key})
			}
			if err := igc.WriteToDb(cntx); err != nil {
				logger.Errorw(ctx, "Igmp group channel Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
			}

			logger.Infow(ctx, "Group Channel Migrated", log.Fields{"IGD": igc})
		} else {
			logger.Warnw(ctx, "Unable to decode channel from database", log.Fields{"str": string(b)})
		}
	}
}

func (igc *IgmpGroupChannel) migrateIgmpPorts(cntx context.Context) {
	ports, _ := db.GetPrevIgmpRcvrs(cntx, igc.GroupAddr, igc.Device)
	logger.Infow(ctx, "Migratable Ports", log.Fields{"Ports": ports})
	for _, port := range ports {
		b, ok := port.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		if igp, err := NewIgmpGroupPortFromBytes(b); err == nil {
			key := database.BasePath + database.IgmpPortPath + igc.GroupAddr.String() + "/" + igc.Device + "/" + igp.Port
			logger.Infow(ctx, "Deleting old entry", log.Fields{"Key": key, "Igp": igp})
			if err := db.Del(cntx, key); err != nil {
				logger.Errorw(ctx, "Igmp Group port Delete from DB failed", log.Fields{"Error": err, "key": key})
			}
			if err := igp.WriteToDb(cntx, igc.Mvlan, igc.GroupAddr, igc.Device); err != nil {
				logger.Errorw(ctx, "Igmp group port Write to DB failed", log.Fields{"mvlan": igc.Mvlan, "GroupAddr": igc.GroupAddr})
			}

			logger.Infow(ctx, "Group Port Migrated", log.Fields{"IGD": igp})
		} else {
			logger.Warnw(ctx, "Unable to decode port from database", log.Fields{"str": string(b)})
		}
	}
}
