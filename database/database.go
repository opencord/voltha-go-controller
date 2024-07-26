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
// This implementation of database assumes that it is working for
// Open ONU adapter. Thus, it assumes some base path for all the
// database operations. For all database operations, the key passed is
// added to the database base path.

package database

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"

	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
)

var logger log.CLogger

// Database structure
type Database struct {
	kvc       kvstore.Client
	storeType string
	address   string
	//timeout   uint32
}

// Initialize the database module. The database module runs as a singleton
// object and is initialized when the adapter is created.
func Initialize(ctx context.Context, storeType string, address string, timeout int) (*Database, error) {
	var err error
	var database Database
	logger.Infow(ctx, "kv-store-type", log.Fields{"store": storeType})
	database.address = address
	database.storeType = storeType
	switch storeType {
	case "redis":
		database.kvc, err = kvstore.NewRedisClient(address, time.Duration(timeout), false)
		return &database, err
	case "etcd":
		database.kvc, err = kvstore.NewEtcdClient(ctx, address, time.Duration(timeout), log.ErrorLevel)
		return &database, err
	}
	return &database, errors.New("unsupported-kv-store")
}

// Utility function that retrieves value for a key. It is assumed that
// the information is always a string and the data retrieved is returned
// as a string

// Put to add value to database
func (db *Database) Put(ctx context.Context, fullKeyPath, value string) error {
	return db.kvc.Put(ctx, fullKeyPath, value)
}

// Get to retrieve value from database
func (db *Database) Get(ctx context.Context, key string) (string, error) {
	kv, err := db.kvc.Get(ctx, key)
	if err != nil {
		return "", err
	}
	if kv != nil {
		return string(kv.Value.([]byte)), nil
	}
	return "", errors.New("Value not found")
}

// Del to delete value from database
func (db *Database) Del(ctx context.Context, fullPath string) error {
	if err := db.kvc.Delete(ctx, fullPath); err != nil {
		logger.Errorw(ctx, "The path doesn't exist", log.Fields{"key": fullPath, "Error": err})
		return err
	}
	return nil
}

// DeleteAll to delete all value from database
func (db *Database) DeleteAll(ctx context.Context, fullPath string) error {
	if err := db.kvc.DeleteWithPrefix(ctx, fullPath); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": fullPath, "Error": err})
		return err
	}
	return nil
}

// DeleteAllUnderHashKey to delete all values under hash key
func (db *Database) DeleteAllUnderHashKey(ctx context.Context, hashKeyPrefix string) error {
	kv, err := db.kvc.List(ctx, hashKeyPrefix)
	if err != nil {
		logger.Errorw(ctx, "The key path doesn't exist", log.Fields{"key": hashKeyPrefix, "Error": err})
		return err
	}
	for key := range kv {
		if err := db.kvc.Delete(ctx, key); err != nil {
			logger.Errorw(ctx, "Delete key from DB Failed", log.Fields{"key": key, "Error": err})
		}
	}
	return nil
}

// List to list the values
func (db *Database) List(ctx context.Context, key string) (map[string]*kvstore.KVPair, error) {
	kv, err := db.kvc.List(ctx, key)
	if err != nil {
		return nil, err
	}
	if kv != nil {
		return kv, nil
	}
	return nil, errors.New("Value not found")
}

// OLT specific database items

// GetOlt to get olt info
func (db *Database) GetOlt(ctx context.Context, deviceID string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DevicePath), deviceID)
	return db.Get(ctx, key)
}

// PutOlt to add olt info
func (db *Database) PutOlt(ctx context.Context, deviceID string, value string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePath), deviceID)
	return db.kvc.Put(ctx, key, value)
}

// DelOlt to delete olt info
func (db *Database) DelOlt(ctx context.Context, deviceID string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePath), deviceID)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Flows specific database actions

// PutFlow to add flow
func (db *Database) PutFlow(ctx context.Context, deviceID string, flowID uint64, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID) + strconv.FormatUint(flowID, 10)
	return db.kvc.Put(ctx, key, value)
}

// GetFlow to get flow
func (db *Database) GetFlow(ctx context.Context, deviceID string, flowID uint64) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID) + strconv.FormatUint(flowID, 10)
	return db.Get(ctx, key)
}

// GetFlows to get multiple flows
func (db *Database) GetFlows(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID)
	return db.List(ctx, key)
}

// DelFlow to delete flow
func (db *Database) DelFlow(ctx context.Context, deviceID string, flowID uint64) error {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID) + strconv.FormatUint(flowID, 10)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Group specific database actions

// PutGroup to add group info
func (db *Database) PutGroup(ctx context.Context, deviceID string, groupID uint32, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID) + strconv.FormatUint(uint64(groupID), 10)
	return db.kvc.Put(ctx, key, value)
}

// GetGroup to get group info
func (db *Database) GetGroup(ctx context.Context, deviceID string, groupID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID) + strconv.FormatUint(uint64(groupID), 10)
	return db.Get(ctx, key)
}

// GetGroups to get multiple group info
func (db *Database) GetGroups(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID)
	logger.Infow(ctx, "key", log.Fields{"Key": key})
	return db.List(ctx, key)
}

// DelGroup to delete group info
func (db *Database) DelGroup(ctx context.Context, deviceID string, groupID uint32) error {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID) + strconv.FormatUint(uint64(groupID), 10)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllGroup to delete all group info
func (db *Database) DelAllGroup(ctx context.Context, deviceID string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID)
	if err := db.DeleteAllUnderHashKey(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the groups for device", log.Fields{"device": deviceID})
	return nil
}

// DelAllPorts to delete all ports info
func (db *Database) DelAllPorts(ctx context.Context, device string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), device)
	if err := db.DeleteAllUnderHashKey(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the ports for device", log.Fields{"device": device})
	return nil
}

// Ports specific database actions

// PutPort to add port info
func (db *Database) PutPort(ctx context.Context, deviceID string, portID uint32, value string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID) + strconv.FormatUint(uint64(portID), 10)
	return db.kvc.Put(ctx, key, value)
}

// GetPort to get port info
func (db *Database) GetPort(ctx context.Context, deviceID string, portID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID) + strconv.FormatUint(uint64(portID), 10)
	return db.Get(ctx, key)
}

// GetPorts to get multiple ports info
func (db *Database) GetPorts(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID)
	return db.List(ctx, key)
}

// DelPort to delete port info
func (db *Database) DelPort(ctx context.Context, deviceID string, portID uint32) error {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID) + strconv.FormatUint(uint64(portID), 10)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Device meter specific database actions

// PutDeviceMeter to add device meter info
func (db *Database) PutDeviceMeter(ctx context.Context, deviceID string, meterID uint32, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID) + strconv.FormatUint(uint64(meterID), 10)
	return db.kvc.Put(ctx, key, value)
}

// GetDeviceMeter to get device meter info
func (db *Database) GetDeviceMeter(ctx context.Context, deviceID string, meterID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID) + strconv.FormatUint(uint64(meterID), 10)
	return db.Get(ctx, key)
}

// GetDeviceMeters to get multiple device meter info
func (db *Database) GetDeviceMeters(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID)
	return db.List(ctx, key)
}

// DelDeviceMeter to delete device meter info
func (db *Database) DelDeviceMeter(ctx context.Context, deviceID string, meterID uint32) error {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID) + strconv.FormatUint(uint64(meterID), 10)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Service specific database actions

// GetServices to get multiple services info
func (db *Database) GetServices(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(ServicePath)
	return db.List(ctx, key)
}

// GetService to get service info
func (db *Database) GetService(ctx context.Context, name string) (string, error) {
	key := GetKeyPath(ServicePath) + name
	return db.Get(ctx, key)
}

// PutService to add service info
func (db *Database) PutService(ctx context.Context, name string, value string) error {
	key := GetKeyPath(ServicePath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelService to delete service info
func (db *Database) DelService(ctx context.Context, name string) error {
	key := GetKeyPath(ServicePath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Virtual networks specific database actions

// GetVnets to get multiple vnets info
func (db *Database) GetVnets(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(VnetPath)
	return db.List(ctx, key)
}

// GetVnet to get vnet info
func (db *Database) GetVnet(ctx context.Context, name string) (string, error) {
	key := GetKeyPath(VnetPath) + name
	return db.Get(ctx, key)
}

// PutVnet to add vnet info
func (db *Database) PutVnet(ctx context.Context, name string, value string) error {
	key := GetKeyPath(VnetPath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelVnet to delete vnet info
func (db *Database) DelVnet(ctx context.Context, name string) error {
	key := GetKeyPath(VnetPath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Virtual networks on ports specific database actions

// GetVpvs to get multiple vpvs info
func (db *Database) GetVpvs(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(VpvPath)
	return db.List(ctx, key)
}

// GetVpv to get vpv info
func (db *Database) GetVpv(ctx context.Context, port string, SVlan uint16, CVlan uint16, UniVlan uint16) (string, error) {
	name := port + fmt.Sprintf("-%v-%v-%v", SVlan, CVlan, UniVlan)
	key := GetKeyPath(VpvPath) + name
	return db.Get(ctx, key)
}

// PutVpv to add vpv info
func (db *Database) PutVpv(ctx context.Context, port string, SVlan uint16, CVlan uint16, UniVlan uint16, value string) error {
	name := port + fmt.Sprintf("-%v-%v-%v", SVlan, CVlan, UniVlan)
	key := GetKeyPath(VpvPath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelVpv to delete vpv info
func (db *Database) DelVpv(ctx context.Context, port string, SVlan uint16, CVlan uint16, UniVlan uint16) error {
	name := port + fmt.Sprintf("-%v-%v-%v", SVlan, CVlan, UniVlan)
	key := GetKeyPath(VpvPath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Virtual networks on ports specific database actions

// GetMvlans to get multiple mvlans info
func (db *Database) GetMvlans(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(MvlanPath)
	return db.List(ctx, key)
}

// GetMvlan to get mvlan info
func (db *Database) GetMvlan(ctx context.Context, mvlan uint16) (string, error) {
	name := strconv.FormatInt(int64(mvlan), 10)
	key := GetKeyPath(MvlanPath) + name
	return db.Get(ctx, key)
}

// PutMvlan to add mvlan info
func (db *Database) PutMvlan(ctx context.Context, mvlan uint16, value string) error {
	name := strconv.FormatInt(int64(mvlan), 10)
	key := GetKeyPath(MvlanPath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelMvlan to delete mvlan info
func (db *Database) DelMvlan(ctx context.Context, mvlan uint16) error {
	name := strconv.FormatInt(int64(mvlan), 10)
	key := GetKeyPath(MvlanPath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on IGMP config

// DelIGMPCfg to delete icmp config
func (db *Database) DelIGMPCfg(ctx context.Context) error {
	key := GetKeyPath(IgmpConfPath)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on IGMP Profile

// GetIgmpProfiles to get multiple igmp profile info
func (db *Database) GetIgmpProfiles(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpProfPath)
	return db.List(ctx, key)
}

// GetIgmpProfile to get igmp profile info
func (db *Database) GetIgmpProfile(ctx context.Context, name string) (string, error) {
	key := GetKeyPath(IgmpProfPath) + name
	return db.Get(ctx, key)
}

// PutIgmpProfile to put igmp profile info
func (db *Database) PutIgmpProfile(ctx context.Context, name string, value string) error {
	key := GetKeyPath(IgmpProfPath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelIgmpProfile to delete igmp profile
func (db *Database) DelIgmpProfile(ctx context.Context, name string) error {
	key := GetKeyPath(IgmpProfPath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on Mcast config Info

// GetMcastConfigs to get multiple mcast config info
func (db *Database) GetMcastConfigs(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(McastConfigPath)
	return db.List(ctx, key)
}

// GetMcastConfig to get igmp profile info
func (db *Database) GetMcastConfig(ctx context.Context, name string) (string, error) {
	key := GetKeyPath(McastConfigPath) + name
	return db.Get(ctx, key)
}

// PutMcastConfig to put igmp profile info
func (db *Database) PutMcastConfig(ctx context.Context, name string, value string) error {
	key := GetKeyPath(McastConfigPath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelMcastConfig to delete igmp profile
func (db *Database) DelMcastConfig(ctx context.Context, name string) error {
	key := GetKeyPath(McastConfigPath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on health

// GetHealth to get health info
func (db *Database) GetHealth(ctx context.Context) (string, error) {
	key := GetKeyPath(HealthPath)
	return db.Get(ctx, key)
}

// PutHealth to add health info
func (db *Database) PutHealth(ctx context.Context, value string) error {
	key := GetKeyPath(HealthPath)
	return db.kvc.Put(ctx, key, value)
}

// DelHealth to delete health info
func (db *Database) DelHealth(ctx context.Context) error {
	key := GetKeyPath(HealthPath)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Meters

// GetMeters to get multiple meters info
func (db *Database) GetMeters(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(MeterPath)
	return db.List(ctx, key)
}

// GetMeter to get meter info
func (db *Database) GetMeter(ctx context.Context, name string) (string, error) {
	key := GetKeyPath(MeterPath) + name
	return db.Get(ctx, key)
}

// PutMeter to add meter info
func (db *Database) PutMeter(ctx context.Context, name string, value string) error {
	key := GetKeyPath(MeterPath) + name
	return db.kvc.Put(ctx, key, value)
}

// DelMeter to delete meter info
func (db *Database) DelMeter(ctx context.Context, name string) error {
	key := GetKeyPath(MeterPath) + name
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllMeter to delete meter info
func (db *Database) DelAllMeter(ctx context.Context, device string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), device)
	if err := db.DeleteAllUnderHashKey(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the meters for device", log.Fields{"device": device})
	return nil
}

// IGMP groups

// GetIgmpGroups to get multiple igmp groups info
func (db *Database) GetIgmpGroups(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpGroupPath)
	return db.List(ctx, key)
}

// GetIgmpGroup to get igmp group info
func (db *Database) GetIgmpGroup(ctx context.Context, id string) (string, error) {
	key := GetKeyPath(IgmpGroupPath) + id
	return db.Get(ctx, key)
}

// PutIgmpGroup to add igmp group info
func (db *Database) PutIgmpGroup(ctx context.Context, id string, value string) error {
	key := GetKeyPath(IgmpGroupPath) + id
	return db.kvc.Put(ctx, key, value)
}

// DelIgmpGroup to delete igmp group info
func (db *Database) DelIgmpGroup(ctx context.Context, id string) error {
	key := GetKeyPath(IgmpGroupPath) + id
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// IGMP group devices

// GetAllIgmpDevices to get multiple igmp devices info
func (db *Database) GetAllIgmpDevices(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpDevicePath)
	return db.List(ctx, key)
}

// GetPrevIgmpDevices to get previous igmp devices
func (db *Database) GetPrevIgmpDevices(ctx context.Context, mvlan of.VlanType, gid string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/"
	return db.List(ctx, key)
}

// GetIgmpDevices to get igmp devices
func (db *Database) GetIgmpDevices(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/"
	return db.List(ctx, key)
}

// GetIgmpDevice to get igmp device
func (db *Database) GetIgmpDevice(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP, device string) (string, error) {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/" + device
	return db.Get(ctx, key)
}

// PutIgmpDevice to add igmp device
func (db *Database) PutIgmpDevice(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP, device string, value string) error {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/" + device
	return db.kvc.Put(ctx, key, value)
}

// DelIgmpDevice to delete igmp device
func (db *Database) DelIgmpDevice(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP, device string) error {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/" + device
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// IGMP group channels

// GetAllIgmpChannels to get all igmp channels
func (db *Database) GetAllIgmpChannels(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpChannelPath)
	return db.List(ctx, key)
}

// GetPrevIgmpChannels to get previous igmp channels
func (db *Database) GetPrevIgmpChannels(ctx context.Context, gName, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpChannelPath) + gName + "/" + device + "/"
	return db.List(ctx, key)
}

// GetIgmpChannels to get multiple igmp channels
func (db *Database) GetIgmpChannels(ctx context.Context, mvlan of.VlanType, gName, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/"
	return db.List(ctx, key)
}

// GetIgmpChannel to get igmp channel
func (db *Database) GetIgmpChannel(ctx context.Context, mvlan of.VlanType, gName string, device string, gip net.IP) (string, error) {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/" + gip.String()
	return db.Get(ctx, key)
}

// PutIgmpChannel to add igmp channel info
func (db *Database) PutIgmpChannel(ctx context.Context, mvlan of.VlanType, gName string, device string, gip net.IP, value string) error {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/" + gip.String()
	return db.kvc.Put(ctx, key, value)
}

// DelIgmpChannel to delete igmp channel info
func (db *Database) DelIgmpChannel(ctx context.Context, mvlan of.VlanType, gName string, device string, gip net.IP) error {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/" + gip.String()
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// IGMP group receivers

// GetAllIgmpRcvrs to get all igmp receivers info
func (db *Database) GetAllIgmpRcvrs(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpPortPath)
	return db.List(ctx, key)
}

// GetPrevIgmpRcvrs to get previous igmp receivers info
func (db *Database) GetPrevIgmpRcvrs(ctx context.Context, gip net.IP, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpPortPath) + gip.String() + "/" + device + "/"
	return db.List(ctx, key)
}

// GetIgmpRcvrs to get multiple igmp receivers info
func (db *Database) GetIgmpRcvrs(ctx context.Context, mvlan of.VlanType, gip net.IP, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/"
	return db.List(ctx, key)
}

// GetIgmpRcvr to get igmp receiver info
func (db *Database) GetIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string, rcvr string) (string, error) {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/" + rcvr
	return db.Get(ctx, key)
}

// PutIgmpRcvr to add igmp receiver info
func (db *Database) PutIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string, rcvr string, value string) error {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/" + rcvr
	return db.kvc.Put(ctx, key, value)
}

// DelIgmpRcvr to delete igmp receiver info
func (db *Database) DelIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string, rcvr string) error {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/" + rcvr
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllIgmpRcvr to delete all igmp receiver info
func (db *Database) DelAllIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string) error {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/"
	if err := db.DeleteAll(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllRoutesForDevice to delete all routes for device
func (db *Database) DelAllRoutesForDevice(ctx context.Context, device string) error {
	/* service/vgc/v1/devices/<deviceID>/flows/ */
	logger.Infow(ctx, "Deleting all the flows for device", log.Fields{"device": device})
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), device)
	if err := db.DeleteAllUnderHashKey(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// PutNbDevicePort to add device port info
func (db *Database) PutNbDevicePort(ctx context.Context, device string, ponPortID uint32, value string) {
	key := GetKeyPath(NbDevicePath) + device + "/pon-port/" + fmt.Sprintf("%v", ponPortID)

	if err := db.kvc.Put(ctx, key, value); err != nil {
		logger.Warnw(ctx, "Put Device Port failed", log.Fields{"key": key})
	}
}

// GetServices to get multiple services info
func (db *Database) GetDeviceConfig(ctx context.Context) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(DeviceConfigPath)
	return db.List(ctx, key)
}

// PutSBDeviceConfig to add device info
func (db *Database) PutDeviceConfig(ctx context.Context, serialNum string, value string) error {
	key := GetKeyPath(DeviceConfigPath) + serialNum

	if err := db.kvc.Put(ctx, key, value); err != nil {
		logger.Warnw(ctx, "Put Device Config failed", log.Fields{"key": key})
		return errorcodes.ErrFailedToUpdateDB
	}
	return nil
}

// DelNbDevicePort to delete device port
func (db *Database) DelNbDevicePort(ctx context.Context, device string, ponPortID uint32) {
	key := GetKeyPath(NbDevicePath) + device + "/pon-port/" + fmt.Sprintf("%v", ponPortID)

	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete Device Port failed", log.Fields{"key": key})
	}
}

// GetAllNbPorts to get all ports info
func (db *Database) GetAllNbPorts(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(NbDevicePath) + deviceID + "/pon-port/"
	return db.List(ctx, key)
}

//Functions for migration database

// GetMigrationInfo to get migration info
func (db *Database) GetMigrationInfo(ctx context.Context) (string, error) {
	key := GetKeyPath(MigrationInfoPath)
	return db.Get(ctx, key)
}

// PutMigrationInfo to add migration info
func (db *Database) PutMigrationInfo(ctx context.Context, value string) error {
	key := GetKeyPath(MigrationInfoPath)
	return db.kvc.Put(ctx, key, value)
}

// DelMigrationInfo to delete migration info
func (db *Database) DelMigrationInfo(ctx context.Context) error {
	key := GetKeyPath(MigrationInfoPath)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

//PON counters

// GetAllPonCounters to get all pon counters info
func (db *Database) GetAllPonCounters(ctx context.Context, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(PonCounterPath) + device
	return db.List(ctx, key)
}

// GetPonCounter to get pon counter info
func (db *Database) GetPonCounter(ctx context.Context, device, ponID string) (string, error) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID
	return db.Get(ctx, key)
}

// PutPonCounter to add pon counter info
func (db *Database) PutPonCounter(ctx context.Context, device, ponID, value string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID
	return db.kvc.Put(ctx, key, value)
}

// DelPonCounter to delete pon counter info
func (db *Database) DelPonCounter(ctx context.Context, device, ponID string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

//PON Channel counters

// GetAllPonChannelCounters to get all pon channel counters
func (db *Database) GetAllPonChannelCounters(ctx context.Context, device, ponID string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath
	return db.List(ctx, key)
}

// GetPonChannelCounter to get pon channel counter
func (db *Database) GetPonChannelCounter(ctx context.Context, device, ponID, channel string) (string, error) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath + channel
	return db.Get(ctx, key)
}

// PutPonChannelCounter to add pon channel counter
func (db *Database) PutPonChannelCounter(ctx context.Context, device, ponID, channel, value string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath + channel
	return db.kvc.Put(ctx, key, value)
}

// DelPonChannelCounter to delete pon channel counter
func (db *Database) DelPonChannelCounter(ctx context.Context, device, ponID, channel string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath + channel
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllPONCounters to delete all pon channel counters
func (db *Database) DelAllPONCounters(ctx context.Context, device string) error {
	key := GetKeyPath(PonCounterPath) + device + "/"
	return db.DeleteAll(ctx, key)
}

// DelPONCounters to delete pon counters
func (db *Database) DelPONCounters(ctx context.Context, device string, ponID string) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/"
	if err := db.DeleteAll(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete Pon counters failed", log.Fields{"key": key})
	}
	//DeletePonCounter(device, ponID)
}

// PutOltIgmpCounters to add Olt Igmp counter info
func (db *Database) PutOltIgmpCounters(ctx context.Context, device, value string) error {
	key := GetKeyPath(OltIgmpCounterPath) + device
	return db.kvc.Put(ctx, key, value)
}

// GetOltIgmpCounter to get Olt Igmp counter info
func (db *Database) GetOltIgmpCounter(ctx context.Context, device string) (string, error) {
	key := GetKeyPath(OltIgmpCounterPath) + device
	return db.Get(ctx, key)
}

//Service Channel counters

// GetAllServiceChannelCounters to get all service channel counters info
func (db *Database) GetAllServiceChannelCounters(ctx context.Context, serviceName string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath
	return db.List(ctx, key)
}

// GetServiceChannelCounter to get service channel counter info
func (db *Database) GetServiceChannelCounter(ctx context.Context, serviceName, channel string) (string, error) {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath + channel
	return db.Get(ctx, key)
}

// PutServiceChannelCounter to add service channel counter
func (db *Database) PutServiceChannelCounter(ctx context.Context, serviceName, channel, value string) error {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath + channel
	return db.kvc.Put(ctx, key, value)
}

// DelServiceChannelCounter to delete service channel counter
func (db *Database) DelServiceChannelCounter(ctx context.Context, serviceName, channel string) error {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath + channel
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllServiceChannelCounter to delete all service channel counter
func (db *Database) DelAllServiceChannelCounter(ctx context.Context, serviceName string) error {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath
	return db.DeleteAllUnderHashKey(ctx, key)
}

// OltExists to know if the ONU is added to the database
func (db *Database) OltExists(ctx context.Context, deviceID string) bool {
	if _, err := db.GetOlt(ctx, deviceID); err != nil {
		return false
	}
	return true
}

// PutFlowHash to add flowhash for the device
func (db *Database) PutFlowHash(ctx context.Context, deviceID string, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID)
	return db.kvc.Put(ctx, key, value)
}

// GetFlowHash gets the flow hash for the device
func (db *Database) GetFlowHash(ctx context.Context, deviceID string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID)
	return db.Get(ctx, key)
}

// PutPortAlarmProfile to add port alarm profile
func (db *Database) PutPortAlarmProfile(ctx context.Context, portAlarmProfileID string, value string) {
	key := GetKeyPath(PortAlarmProfilePath) + fmt.Sprintf("%v", portAlarmProfileID)
	if err := db.kvc.Put(ctx, key, value); err != nil {
		logger.Warnw(ctx, "Put PortAlarmProfile failed", log.Fields{"key": key})
	}
}

// DelPortAlarmProfile to delete port alarm profile
func (db *Database) DelPortAlarmProfile(ctx context.Context, portAlarmProfileID string) {
	key := GetKeyPath(PortAlarmProfilePath) + fmt.Sprintf("%v", portAlarmProfileID)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete PortAlarmProfile failed", log.Fields{"key": key})
	}
}

// GetPortAlarmProfile to get port alarm profile
func (db *Database) GetPortAlarmProfile(ctx context.Context, portAlarmProfileID string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(PortAlarmProfilePath) + fmt.Sprintf("%v", portAlarmProfileID)
	return db.List(ctx, key)
}

// PutPortAlarmData to add port alarm data
func (db *Database) PutPortAlarmData(ctx context.Context, deviceID string, portID uint32, value string) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID) + fmt.Sprintf("%v", portID)
	if err := db.kvc.Put(ctx, key, value); err != nil {
		logger.Warnw(ctx, "Put PortAlarmData failed", log.Fields{"key": key})
	}
}

// DelPortAlarmData to delete port alarm data
func (db *Database) DelPortAlarmData(ctx context.Context, deviceID string, portID uint32) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID) + fmt.Sprintf("%v", portID)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete PortAlarmData failed", log.Fields{"key": key})
	}
}

// GetPortAlarmData to get port alarm data
func (db *Database) GetPortAlarmData(ctx context.Context, deviceID string, portID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID) + fmt.Sprintf("%v", portID)
	return db.Get(ctx, key)
}

// GetAllPortAlarmData to get port alarm data for all ports
func (db *Database) GetAllPortAlarmData(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID)
	return db.List(ctx, key)
}

// PutSubAlarmData to add subscriber alarm data
func (db *Database) PutSubAlarmData(ctx context.Context, deviceID string, portName string, value string) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID) + fmt.Sprintf("%v", portName)
	if err := db.kvc.Put(ctx, key, value); err != nil {
		logger.Warnw(ctx, "Put Subscriber AlarmData failed", log.Fields{"key": key})
	}
}

// DelSubAlarmData to delete subscriber alarm data
func (db *Database) DelSubAlarmData(ctx context.Context, deviceID string, portName string) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID) + fmt.Sprintf("%v", portName)
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete Subscriber AlarmData failed", log.Fields{"key": key})
	}
}

// GetSubAlarmData to get subscriber alarm data
func (db *Database) GetSubAlarmData(ctx context.Context, deviceID string, portName string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID) + fmt.Sprintf("%v", portName)
	return db.Get(ctx, key)
}

// GetAllSubAlarmData to get sub alarm data for all subscribers
func (db *Database) GetAllSubAlarmData(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID)
	return db.List(ctx, key)
}

// Migrate Service req specific database actions

// PutMigrateServicesReq to add MigrateServicesReq info
func (db *Database) PutMigrateServicesReq(ctx context.Context, deviceID string, vnet string, value string) error {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID) + vnet
	return db.kvc.Put(ctx, key, value)
}

// GetMigrateServicesReq to get MigrateServicesReq info
func (db *Database) GetMigrateServicesReq(ctx context.Context, deviceID string, vnet string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID) + vnet
	return db.Get(ctx, key)
}

// GetAllMigrateServicesReq to get multiple MigrateServicesReq info
func (db *Database) GetAllMigrateServicesReq(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID)
	return db.List(ctx, key)
}

// DelMigrateServicesReq to delete MigrateServicesReq info
func (db *Database) DelMigrateServicesReq(ctx context.Context, deviceID string, vnet string) error {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID) + vnet
	if err := db.kvc.Delete(ctx, key); err != nil {
		logger.Errorw(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllMigrateServicesReq to delete all MigrateServicesReq info
func (db *Database) DelAllMigrateServicesReq(ctx context.Context, deviceID string) error {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID)
	if err := db.DeleteAllUnderHashKey(ctx, key); err != nil {
		logger.Warnw(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the Update Vnet Requests for device", log.Fields{"device": deviceID})
	return nil
}

// PutOltFlowService to add OltFlowService info
func (db *Database) PutOltFlowService(ctx context.Context, value string) error {
	key := GetKeyPath(OltFlowServicePath)

	if err := db.kvc.Put(ctx, key, value); err != nil {
		logger.Warnw(ctx, "Put OltFlowService failed", log.Fields{"key": key})
		return err
	}
	return nil
}

// GetOltFlowService to get OltFlowService info
func (db *Database) GetOltFlowService(ctx context.Context) (string, error) {
	key := GetKeyPath(OltFlowServicePath)
	return db.Get(ctx, key)
}
func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}
