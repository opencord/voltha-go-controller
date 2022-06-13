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
	"errors"
	"net"
	"voltha-go-controller/internal/pkg/types"

	"strings"

	"github.com/google/gopacket/layers"
	"voltha-go-controller/database"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

type paramsUpdationFunc func(hash string, value interface{}) error

//map to store conversion functions
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
func UpdateDbData(dbPath, hash string, value interface{}) error {
	if migrationFunc, ok := updationMap[dbPath]; ok {
		err := migrationFunc(hash, value)
		if err != nil {
			logger.Error(ctx, "Error in migrating data\n")
			return errors.New("Error-in-migration")
		}
	}
	return nil
}

//This function modifyies the old data as per current version requirement and also
//returns the new path on which the modified data has to be written
func updateServices(hash string, value interface{}) error {
	param := value.(*VoltService)
	param.VnetID = VnetKey(param.SVlan, param.CVlan, param.UniVlan)
	return nil
}

//This function modifyies the old data as per current version requirement and also
//returns the new path on which the modified data has to be written
func updateVnets(hash string, value interface{}) error {
	param := value.(*VoltVnet)
	newKey := VnetKey(param.SVlan, param.CVlan, param.UniVlan)
	if newKey != hash {
		//Delete the older key
		db.DelVnet(hash)
	} else {
		//Update SVlan Tag Protocol id param with default valud if not present
		if param.SVlanTpid == 0 {
			param.SVlanTpid = layers.EthernetTypeDot1Q
		}
	}
	param.Name = newKey
	if param.DevicesList == nil || len(param.DevicesList) == 0 {
		param.DevicesList = append(param.DevicesList, "") //Empty OLT serial number as of now since submgr won't have proper serial num
	}
	return nil
}

//This function modifyies the old data as per current version requirement and also
//returns the new path on which the modified data has to be written
func updateVpvs(hash string, value interface{}) error {

	//var param VoltPortVnet
	param := value.(*VoltPortVnet)

	//Update SVlan Tag Protocol id param with default valud if not present
	if param.SVlanTpid == 0 {
		param.SVlanTpid = layers.EthernetTypeDot1Q
	}

	if strings.Count(hash, "-") > 1 {
		logger.Info(ctx, "Already upgraded")
		return nil
	}

	//Add the vpv under new path
	param.WriteToDb()
	//delete the older path
	fullPath := database.BasePath + database.VpvPath + hash
	db.Del(fullPath)
	return nil
}

func updateMvlans(hash string, value interface{}) error {
	param := value.(*MvlanProfile)
	if param.DevicesList == nil || len(param.DevicesList) == 0 {
		param.DevicesList = make(map[string]OperInProgress) //Empty OLT serial number as of now since submgr won't have proper serial num
		param.WriteToDb()
	}
	if _, ok := param.Groups[common.StaticGroup]; ok {
		param.Groups[common.StaticGroup].IsStatic = true
	}
	return nil
}

//This function modifyies the old Igmp Group data as per current version requirement and also
//returns the new path on which the modified data has to be written
func updateIgmpGroups(hash string, value interface{}) error {

	ig := value.(*IgmpGroup)
	logger.Infow(ctx, "Group Data Migration", log.Fields{"ig": ig, "GroupAddr": ig.GroupAddr, "hash": hash})
	if ig.GroupAddr == nil {
		ig.GroupAddr = net.ParseIP("0.0.0.0")
	}
	ig.WriteToDb()
	return nil
}

//This function modifyies the old Igmp  Device data as per current version requirement and also
//returns the new path on which the modified data has to be written
func updateIgmpDevices(hash string, value interface{}) error {
	igd := value.(*IgmpGroupDevice)
	logger.Infow(ctx, "Group Device Migration", log.Fields{"igd": igd, "GroupAddr": igd.GroupAddr, "hash": hash})
	if igd.GroupAddr == nil {
		igd.GroupAddr = net.ParseIP("0.0.0.0")
	}
	igd.WriteToDb()
	return nil
}

//This function modifyies the old Igmp  Profile data as per current version requirement and also
//returns the new path on which the modified data has to be written
func updateIgmpProfiles(hash string, value interface{}) error {
	igmpProfile := value.(*IgmpProfile)
	logger.Infow(ctx, "IGMP Profile Migration", log.Fields{"igmpProfile": igmpProfile, "hash": hash})
	return nil
}

func (ig *IgmpGroup) migrateIgmpDevices() {

	devices, _ := db.GetPrevIgmpDevices(ig.Mvlan, ig.GroupName)
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
			db.Del(key)
			UpdateDbData(database.IgmpDevicePath, key, igd)
			logger.Infow(ctx, "Group Device Migrated", log.Fields{"IGD": igd})
		} else {
			logger.Warnw(ctx, "Unable to decode device from database", log.Fields{"str": string(b)})
		}
	}
}

func (igd *IgmpGroupDevice) migrateIgmpChannels() {

	channels, _ := db.GetPrevIgmpChannels(igd.GroupName, igd.Device)
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
			db.Del(key)
			igc.WriteToDb()
			logger.Infow(ctx, "Group Channel Migrated", log.Fields{"IGD": igc})
		} else {
			logger.Warnw(ctx, "Unable to decode channel from database", log.Fields{"str": string(b)})
		}
	}
}

func (igc *IgmpGroupChannel) migrateIgmpPorts() {

	ports, _ := db.GetPrevIgmpRcvrs(igc.GroupAddr, igc.Device)
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
			db.Del(key)
			igp.WriteToDb(igc.Mvlan, igc.GroupAddr, igc.Device)
			logger.Infow(ctx, "Group Port Migrated", log.Fields{"IGD": igp})
		} else {
			logger.Warnw(ctx, "Unable to decode port from database", log.Fields{"str": string(b)})
		}
	}
}
