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
// This implementation of database assumes that it is working for
// Open ONU adapter. Thus, it assumes some base path for all the
// database operations. For all database operations, the key passed is
// added to the database base path.

package database

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"
	"fmt"

	"voltha-go-controller/internal/pkg/of"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

var logger log.CLogger
var ctx = context.TODO()

// Database structure
type Database struct {
	storeType string
	address   string
	timeout   uint32
	kvc       kvstore.Client
}

// Initialize the database module. The database module runs as a singleton
// object and is initialized when the adapter is created.
func Initialize(storeType string, address string, timeout int) (*Database, error) {
	var err error
	var database Database
	logger.Infow(ctx, "kv-store-type", log.Fields{"store": storeType})
	database.address = address
	database.storeType = storeType
	switch storeType {
	case "redis":
		database.kvc, err = kvstore.NewRedisClient(address, time.Duration(timeout), false)
		return &database, err
	}
	return &database, errors.New("unsupported-kv-store")
}

// Utility function that retrieves value for a key. It is assumed that
// the information is always a string and the data retrieved is returned
// as a string

// Put to add value to database
func (db *Database) Put(fullKeyPath, value string) error {
	return db.kvc.Put(context.Background(), fullKeyPath, value)
}

// Get to retrieve value from database
func (db *Database) Get(key string) (string, error) {
	kv, err := db.kvc.Get(context.Background(), key)
	if err != nil {
		return "", err
	}
	if kv != nil {
		return string(kv.Value.([]byte)), nil
	}
	return "", errors.New("Value not found")
}

// Del to delete value from database
func (db *Database) Del(fullPath string) error {
	if err := db.kvc.Delete(context.Background(), fullPath); err != nil {
		logger.Errorf(ctx, "The path doesn't exist", log.Fields{"key": fullPath, "Error": err})
		return err
	}
	return nil
}

// DeleteAll to delete all value from database
func (db *Database) DeleteAll(fullPath string) error {
	if err := db.kvc.DeleteWithPrefix(context.Background(), fullPath); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": fullPath, "Error": err})
		return err
	}
	return nil
}

// DeleteAllUnderHashKey to delete all values under hash key
func (db *Database) DeleteAllUnderHashKey(hashKeyPrefix string) error {
	if err := db.kvc.Delete(context.Background(), hashKeyPrefix); err != nil {
		logger.Errorf(ctx, "The key path doesn't exist", log.Fields{"key": hashKeyPrefix, "Error": err})
		return err
	}
	return nil
}

// List to list the values
func (db *Database) List(key string) (map[string]*kvstore.KVPair, error) {
	kv, err := db.kvc.List(context.Background(), key)
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
func (db *Database) GetOlt(deviceID string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DevicePath), deviceID)
	return db.Get(key)
}

// PutOlt to add olt info
func (db *Database) PutOlt(deviceID string, value string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePath), deviceID)
	return db.kvc.Put(context.Background(), key, value)
}

// DelOlt to delete olt info
func (db *Database) DelOlt(deviceID string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePath), deviceID)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Flows specific database actions

// PutFlow to add flow
func (db *Database) PutFlow(deviceID string, flowID uint64, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID) + strconv.FormatUint(flowID, 10)
	return db.kvc.Put(context.Background(), key, value)
}

// GetFlow to get flow
func (db *Database) GetFlow(deviceID string, flowID uint64) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID) + strconv.FormatUint(flowID, 10)
	return db.Get(key)
}

// GetFlows to get multiple flows
func (db *Database) GetFlows(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID)
	return db.List(key)
}

// DelFlow to delete flow
func (db *Database) DelFlow(deviceID string, flowID uint64) error {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID) + strconv.FormatUint(flowID, 10)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Group specific database actions

// PutGroup to add group info
func (db *Database) PutGroup(deviceID string, groupID uint32, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID) + strconv.FormatUint(uint64(groupID), 10)
	return db.kvc.Put(context.Background(), key, value)
}

// GetGroup to get group info
func (db *Database) GetGroup(deviceID string, groupID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID) + strconv.FormatUint(uint64(groupID), 10)
	return db.Get(key)
}

// GetGroups to get multiple group info
func (db *Database) GetGroups(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID)
	logger.Infow(ctx, "key", log.Fields{"Key": key})
	return db.List(key)
}

// DelGroup to delete group info
func (db *Database) DelGroup(deviceID string, groupID uint32) error {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID) + strconv.FormatUint(uint64(groupID), 10)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllGroup to delete all group info
func (db *Database) DelAllGroup(deviceID string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceGroupPath), deviceID)
	if err := db.DeleteAllUnderHashKey(key); err != nil {
		logger.Warnf(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the groups for device", log.Fields{"device": deviceID})
	return nil
}

// DelAllPorts to delete all ports info
func (db *Database) DelAllPorts(device string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), device)
	if err := db.DeleteAllUnderHashKey(key); err != nil {
		logger.Warnf(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the ports for device", log.Fields{"device": device})
	return nil
}

// Ports specific database actions

// PutPort to add port info
func (db *Database) PutPort(deviceID string, portID uint32, value string) error {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID) + strconv.FormatUint(uint64(portID), 10)
	return db.kvc.Put(context.Background(), key, value)
}

// GetPort to get port info
func (db *Database) GetPort(deviceID string, portID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID) + strconv.FormatUint(uint64(portID), 10)
	return db.Get(key)
}

// GetPorts to get multiple ports info
func (db *Database) GetPorts(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID)
	return db.List(key)
}

// DelPort to delete port info
func (db *Database) DelPort(deviceID string, portID uint32) error {
	key := fmt.Sprintf(GetKeyPath(DevicePortPath), deviceID) + strconv.FormatUint(uint64(portID), 10)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Device meter specific database actions

// PutDeviceMeter to add device meter info
func (db *Database) PutDeviceMeter(deviceID string, meterID uint32, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID) + strconv.FormatUint(uint64(meterID), 10)
	return db.kvc.Put(context.Background(), key, value)
}

// GetDeviceMeter to get device meter info
func (db *Database) GetDeviceMeter(deviceID string, meterID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID) + strconv.FormatUint(uint64(meterID), 10)
	return db.Get(key)
}

// GetDeviceMeters to get multiple device meter info
func (db *Database) GetDeviceMeters(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID)
	return db.List(key)
}

// DelDeviceMeter to delete device meter info
func (db *Database) DelDeviceMeter(deviceID string, meterID uint32) error {
	key := fmt.Sprintf(GetKeyPath(DeviceMeterPath), deviceID) + strconv.FormatUint(uint64(meterID), 10)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Service specific database actions

// GetServices to get multiple services info
func (db *Database) GetServices() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(ServicePath)
	return db.List(key)
}

// GetService to get service info
func (db *Database) GetService(name string) (string, error) {
	key := GetKeyPath(ServicePath) + name
	return db.Get(key)
}

// PutService to add service info
func (db *Database) PutService(name string, value string) error {
	key := GetKeyPath(ServicePath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelService to delete service info
func (db *Database) DelService(name string) error {
	key := GetKeyPath(ServicePath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Virtual networks specific database actions

// GetVnets to get multiple vnets info
func (db *Database) GetVnets() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(VnetPath)
	return db.List(key)
}

// GetVnet to get vnet info
func (db *Database) GetVnet(name string) (string, error) {
	key := GetKeyPath(VnetPath) + name
	return db.Get(key)
}

// PutVnet to add vnet info
func (db *Database) PutVnet(name string, value string) error {
	key := GetKeyPath(VnetPath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelVnet to delete vnet info
func (db *Database) DelVnet(name string) error {
	key := GetKeyPath(VnetPath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Virtual networks on ports specific database actions

// GetVpvs to get multiple vpvs info
func (db *Database) GetVpvs() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(VpvPath)
	return db.List(key)
}

// GetVpv to get vpv info
func (db *Database) GetVpv(port string, SVlan uint16, CVlan uint16, UniVlan uint16) (string, error) {
	name := port + fmt.Sprintf("-%v-%v-%v", SVlan, CVlan, UniVlan)
	key := GetKeyPath(VpvPath) + name
	return db.Get(key)
}

// PutVpv to add vpv info
func (db *Database) PutVpv(port string, SVlan uint16, CVlan uint16, UniVlan uint16, value string) error {
	name := port + fmt.Sprintf("-%v-%v-%v", SVlan, CVlan, UniVlan)
	key := GetKeyPath(VpvPath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelVpv to delete vpv info
func (db *Database) DelVpv(port string, SVlan uint16, CVlan uint16, UniVlan uint16) error {
	name := port + fmt.Sprintf("-%v-%v-%v", SVlan, CVlan, UniVlan)
	key := GetKeyPath(VpvPath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Virtual networks on ports specific database actions

// GetMvlans to get multiple mvlans info
func (db *Database) GetMvlans() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(MvlanPath)
	return db.List(key)
}

// GetMvlan to get mvlan info
func (db *Database) GetMvlan(mvlan uint16) (string, error) {
	name := strconv.FormatInt(int64(mvlan), 10)
	key := GetKeyPath(MvlanPath) + name
	return db.Get(key)
}

// PutMvlan to add mvlan info
func (db *Database) PutMvlan(mvlan uint16, value string) error {
	name := strconv.FormatInt(int64(mvlan), 10)
	key := GetKeyPath(MvlanPath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelMvlan to delete mvlan info
func (db *Database) DelMvlan(mvlan uint16) error {
	name := strconv.FormatInt(int64(mvlan), 10)
	key := GetKeyPath(MvlanPath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on IGMP config

// DelIGMPCfg to delete icmp config
func (db *Database) DelIGMPCfg() error {
	key := GetKeyPath(IgmpConfPath)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on IGMP Profile

// GetIgmpProfiles to get multiple igmp profile info
func (db *Database) GetIgmpProfiles() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpProfPath)
	return db.List(key)
}

// GetIgmpProfile to get igmp profile info
func (db *Database) GetIgmpProfile(name string) (string, error) {
	key := GetKeyPath(IgmpProfPath) + name
	return db.Get(key)
}

// PutIgmpProfile to put igmp profile info
func (db *Database) PutIgmpProfile(name string, value string) error {
	key := GetKeyPath(IgmpProfPath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelIgmpProfile to delete igmp profile
func (db *Database) DelIgmpProfile(name string) error {
	key := GetKeyPath(IgmpProfPath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on Mcast config Info

// GetMcastConfigs to get multiple mcast config info
func (db *Database) GetMcastConfigs() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(McastConfigPath)
	return db.List(key)
}

// GetMcastConfig to get igmp profile info
func (db *Database) GetMcastConfig(name string) (string, error) {
	key := GetKeyPath(McastConfigPath) + name
	return db.Get(key)
}

// PutMcastConfig to put igmp profile info
func (db *Database) PutMcastConfig(name string, value string) error {
	key := GetKeyPath(McastConfigPath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelMcastConfig to delete igmp profile
func (db *Database) DelMcastConfig(name string) error {
	key := GetKeyPath(McastConfigPath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// database specific actions on health

// GetHealth to get health info
func (db *Database) GetHealth() (string, error) {
	key := GetKeyPath(HealthPath)
	return db.Get(key)
}

// PutHealth to add health info
func (db *Database) PutHealth(value string) error {
	key := GetKeyPath(HealthPath)
	return db.kvc.Put(context.Background(), key, value)
}

// DelHealth to delete health info
func (db *Database) DelHealth() error {
	key := GetKeyPath(HealthPath)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// Meters

// GetMeters to get multiple meters info
func (db *Database) GetMeters() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(MeterPath)
	return db.List(key)
}

// GetMeter to get meter info
func (db *Database) GetMeter(name string) (string, error) {
	key := GetKeyPath(MeterPath) + name
	return db.Get(key)
}

// PutMeter to add meter info
func (db *Database) PutMeter(name string, value string) error {
	key := GetKeyPath(MeterPath) + name
	return db.kvc.Put(context.Background(), key, value)
}

// DelMeter to delete meter info
func (db *Database) DelMeter(name string) error {
	key := GetKeyPath(MeterPath) + name
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllMeter to delete meter info
func (db *Database) DelAllMeter(device string) error {
	key := GetKeyPath(DevicePath) + device + "/" + MeterPath
	if err := db.DeleteAllUnderHashKey(key); err != nil {
		logger.Warnf(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the meters for device", log.Fields{"device": device})
	return nil
}

// IGMP groups

// GetIgmpGroups to get multiple igmp groups info
func (db *Database) GetIgmpGroups() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpGroupPath)
	return db.List(key)
}

// GetIgmpGroup to get igmp group info
func (db *Database) GetIgmpGroup(id string) (string, error) {
	key := GetKeyPath(IgmpGroupPath) + id
	return db.Get(key)
}

// PutIgmpGroup to add igmp group info
func (db *Database) PutIgmpGroup(id string, value string) error {
	key := GetKeyPath(IgmpGroupPath) + id
	return db.kvc.Put(context.Background(), key, value)
}

// DelIgmpGroup to delete igmp group info
func (db *Database) DelIgmpGroup(id string) error {
	key := GetKeyPath(IgmpGroupPath) + id
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Warnf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// IGMP group devices

// GetAllIgmpDevices to get multiple igmp devices info
func (db *Database) GetAllIgmpDevices() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpDevicePath)
	return db.List(key)
}

// GetPrevIgmpDevices to get previous igmp devices
func (db *Database) GetPrevIgmpDevices(mvlan of.VlanType, gid string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/"
	return db.List(key)
}

// GetIgmpDevices to get igmp devices
func (db *Database) GetIgmpDevices(mvlan of.VlanType, gid string, gip net.IP) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/"
	return db.List(key)
}

// GetIgmpDevice to get igmp device
func (db *Database) GetIgmpDevice(mvlan of.VlanType, gid string, gip net.IP, device string) (string, error) {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/" + device
	return db.Get(key)
}

// PutIgmpDevice to add igmp device
func (db *Database) PutIgmpDevice(mvlan of.VlanType, gid string, gip net.IP, device string, value string) error {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/" + device
	return db.kvc.Put(context.Background(), key, value)
}

// DelIgmpDevice to delete igmp device
func (db *Database) DelIgmpDevice(mvlan of.VlanType, gid string, gip net.IP, device string) error {
	key := GetKeyPath(IgmpDevicePath) + mvlan.String() + "/" + gid + "/" + gip.String() + "/" + device
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Warnf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// IGMP group channels

// GetAllIgmpChannels to get all igmp channels
func (db *Database) GetAllIgmpChannels() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpChannelPath)
	return db.List(key)
}

// GetPrevIgmpChannels to get previous igmp channels
func (db *Database) GetPrevIgmpChannels(gName, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpChannelPath) + gName + "/" + device + "/"
	return db.List(key)
}

// GetIgmpChannels to get multiple igmp channels
func (db *Database) GetIgmpChannels(mvlan of.VlanType, gName, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/"
	return db.List(key)
}

// GetIgmpChannel to get igmp channel
func (db *Database) GetIgmpChannel(mvlan of.VlanType, gName string, device string, gip net.IP) (string, error) {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/" + gip.String()
	return db.Get(key)
}

// PutIgmpChannel to add igmp channel info
func (db *Database) PutIgmpChannel(mvlan of.VlanType, gName string, device string, gip net.IP, value string) error {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/" + gip.String()
	return db.kvc.Put(context.Background(), key, value)
}

// DelIgmpChannel to delete igmp channel info
func (db *Database) DelIgmpChannel(mvlan of.VlanType, gName string, device string, gip net.IP) error {
	key := GetKeyPath(IgmpChannelPath) + mvlan.String() + "/" + gName + "/" + device + "/" + gip.String()
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Warnf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// IGMP group receivers

// GetAllIgmpRcvrs to get all igmp receivers info
func (db *Database) GetAllIgmpRcvrs() (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpPortPath)
	return db.List(key)
}

// GetPrevIgmpRcvrs to get previous igmp receivers info
func (db *Database) GetPrevIgmpRcvrs(gip net.IP, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpPortPath) + gip.String() + "/" + device + "/"
	return db.List(key)
}

// GetIgmpRcvrs to get multiple igmp receivers info
func (db *Database) GetIgmpRcvrs(mvlan of.VlanType, gip net.IP, device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/"
	return db.List(key)
}

// GetIgmpRcvr to get igmp receiver info
func (db *Database) GetIgmpRcvr(mvlan of.VlanType, gip net.IP, device string, rcvr string) (string, error) {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/" + rcvr
	return db.Get(key)
}

// PutIgmpRcvr to add igmp receiver info
func (db *Database) PutIgmpRcvr(mvlan of.VlanType, gip net.IP, device string, rcvr string, value string) error {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/" + rcvr
	return db.kvc.Put(context.Background(), key, value)
}

// DelIgmpRcvr to delete igmp receiver info
func (db *Database) DelIgmpRcvr(mvlan of.VlanType, gip net.IP, device string, rcvr string) error {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/" + rcvr
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Warnf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllIgmpRcvr to delete all igmp receiver info
func (db *Database) DelAllIgmpRcvr(mvlan of.VlanType, gip net.IP, device string) error {
	key := GetKeyPath(IgmpPortPath) + mvlan.String() + "/" + gip.String() + "/" + device + "/"
	if err := db.DeleteAll(key); err != nil {
		logger.Warnf(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllRoutesForDevice to delete all routes for device
func (db *Database) DelAllRoutesForDevice(device string) error {
	/* service/vgc/v1/devices/<deviceID>/flows/ */
	logger.Infow(ctx, "Deleting all the flows for device", log.Fields{"device": device})
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), device)
	if err := db.DeleteAllUnderHashKey(key); err != nil {
		logger.Warnf(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// PutNbDevicePort to add device port info
func (db *Database) PutNbDevicePort(device string, ponPortID uint32, value string) {
	key := GetKeyPath(NbDevicePath) + device + "/pon-port/" + fmt.Sprintf("%v", ponPortID)

	db.kvc.Put(context.Background(), key, value)
}

// DelNbDevicePort to delete device port
func (db *Database) DelNbDevicePort(device string, ponPortID uint32) {
	key := GetKeyPath(NbDevicePath) + device + "/pon-port/" + fmt.Sprintf("%v", ponPortID)

	db.kvc.Delete(context.Background(), key)
}

// GetAllNbPorts to get all ports info
func (db *Database) GetAllNbPorts(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(NbDevicePath) + deviceID + "/pon-port/"
	return db.List(key)
}

//Functions for migration database

// GetMigrationInfo to get migration info
func (db *Database) GetMigrationInfo() (string, error) {
	key := GetKeyPath(MigrationInfoPath)
	return db.Get(key)
}

// PutMigrationInfo to add migration info
func (db *Database) PutMigrationInfo(value string) error {
	key := GetKeyPath(MigrationInfoPath)
	return db.kvc.Put(context.Background(), key, value)
}

// DelMigrationInfo to delete migration info
func (db *Database) DelMigrationInfo() error {
	key := GetKeyPath(MigrationInfoPath)
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

//PON counters

// GetAllPonCounters to get all pon counters info
func (db *Database) GetAllPonCounters(device string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(PonCounterPath) + device
	return db.List(key)
}

// GetPonCounter to get pon counter info
func (db *Database) GetPonCounter(device, ponID string) (string, error) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID
	return db.Get(key)
}

// PutPonCounter to add pon counter info
func (db *Database) PutPonCounter(device, ponID, value string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID
	return db.kvc.Put(context.Background(), key, value)
}

// DelPonCounter to delete pon counter info
func (db *Database) DelPonCounter(device, ponID string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

//PON Channel counters

// GetAllPonChannelCounters to get all pon channel counters
func (db *Database) GetAllPonChannelCounters(device, ponID string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath
	return db.List(key)
}

// GetPonChannelCounter to get pon channel counter
func (db *Database) GetPonChannelCounter(device, ponID, channel string) (string, error) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath + channel
	return db.Get(key)
}

// PutPonChannelCounter to add pon channel counter
func (db *Database) PutPonChannelCounter(device, ponID, channel, value string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath + channel
	return db.kvc.Put(context.Background(), key, value)
}

// DelPonChannelCounter to delete pon channel counter
func (db *Database) DelPonChannelCounter(device, ponID, channel string) error {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/" + ChannelCounterPath + channel
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllPONCounters to delete all pon channel counters
func (db *Database) DelAllPONCounters(device string) error {
	key := GetKeyPath(PonCounterPath) + device + "/"
	return db.DeleteAll(key)
}

// DelPONCounters to delete pon counters
func (db *Database) DelPONCounters(device string, ponID string) {
	key := GetKeyPath(PonCounterPath) + device + "/" + ponID + "/"
	db.DeleteAll(key)
	//DeletePonCounter(device, ponID)
}

// PutOltIgmpCounters to add Olt Igmp counter info
func (db *Database) PutOltIgmpCounters(device, value string) error {
	key := GetKeyPath(OltIgmpCounterPath) + device
	return db.kvc.Put(context.Background(), key, value)
}

// GetOltIgmpCounter to get Olt Igmp counter info
func (db *Database) GetOltIgmpCounter(device string) (string, error) {
	key := GetKeyPath(OltIgmpCounterPath) + device
	return db.Get(key)
}

//Service Channel counters

// GetAllServiceChannelCounters to get all service channel counters info
func (db *Database) GetAllServiceChannelCounters(serviceName string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath
	return db.List(key)
}

// GetServiceChannelCounter to get service channel counter info
func (db *Database) GetServiceChannelCounter(serviceName, channel string) (string, error) {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath + channel
	return db.Get(key)
}

// PutServiceChannelCounter to add service channel counter
func (db *Database) PutServiceChannelCounter(serviceName, channel, value string) error {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath + channel
	return db.kvc.Put(context.Background(), key, value)
}

// DelServiceChannelCounter to delete service channel counter
func (db *Database) DelServiceChannelCounter(serviceName, channel string) error {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath + channel
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllServiceChannelCounter to delete all service channel counter
func (db *Database) DelAllServiceChannelCounter(serviceName string) error {
	key := GetKeyPath(ServiceCounterPath) + serviceName + "/" + ChannelCounterPath
	return db.DeleteAllUnderHashKey(key)
}

// OltExists to know if the ONU is added to the database
func (db *Database) OltExists(deviceID string) bool {
	if _, err := db.GetOlt(deviceID); err != nil {
		return false
	}
	return true

}

// PutFlowHash to add flowhash for the device
func (db *Database) PutFlowHash(deviceID string, value string) error {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID)
	return db.kvc.Put(context.Background(), key, value)
}

// GetFlowHash gets the flow hash for the device
func (db *Database) GetFlowHash(deviceID string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(DeviceFlowPath), deviceID)
	return db.Get(key)
}

// PutPortAlarmProfile to add port alarm profile
func (db *Database) PutPortAlarmProfile(portAlarmProfileID string, value string) {
	key := GetKeyPath(PortAlarmProfilePath) + fmt.Sprintf("%v", portAlarmProfileID)
	db.kvc.Put(context.Background(), key, value)
}

// DelPortAlarmProfile to delete port alarm profile
func (db *Database) DelPortAlarmProfile(portAlarmProfileID string) {
	key := GetKeyPath(PortAlarmProfilePath) + fmt.Sprintf("%v", portAlarmProfileID)
	db.kvc.Delete(context.Background(), key)
}

// GetPortAlarmProfile to get port alarm profile
func (db *Database) GetPortAlarmProfile(portAlarmProfileID string) (map[string]*kvstore.KVPair, error) {
	key := GetKeyPath(PortAlarmProfilePath) + fmt.Sprintf("%v", portAlarmProfileID)
	return db.List(key)
}

// PutPortAlarmData to add port alarm data
func (db *Database) PutPortAlarmData(deviceID string, portID uint32, value string) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID) + fmt.Sprintf("%v", portID)
	db.kvc.Put(context.Background(), key, value)
}

// DelPortAlarmData to delete port alarm data
func (db *Database) DelPortAlarmData(deviceID string, portID uint32) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID) + fmt.Sprintf("%v", portID)
	db.kvc.Delete(context.Background(), key)
}

// GetPortAlarmData to get port alarm data
func (db *Database) GetPortAlarmData(deviceID string, portID uint32) (string, error) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID) + fmt.Sprintf("%v", portID)
	return db.Get(key)
}

// GetAllPortAlarmData to get port alarm data for all ports
func (db *Database) GetAllPortAlarmData(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(PortAlarmDataPath), deviceID)
	return db.List(key)
}

// PutSubAlarmData to add subscriber alarm data
func (db *Database) PutSubAlarmData(deviceID string, portName string, value string) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID) + fmt.Sprintf("%v", portName)
	db.kvc.Put(context.Background(), key, value)
}

// DelSubAlarmData to delete subscriber alarm data
func (db *Database) DelSubAlarmData(deviceID string, portName string) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID) + fmt.Sprintf("%v", portName)
	db.kvc.Delete(context.Background(), key)
}

// GetSubAlarmData to get subscriber alarm data
func (db *Database) GetSubAlarmData(deviceID string, portName string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID) + fmt.Sprintf("%v", portName)
	return db.Get(key)
}

// GetAllSubAlarmData to get sub alarm data for all subscribers
func (db *Database) GetAllSubAlarmData(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(SubAlarmDataPath), deviceID)
	return db.List(key)
}

// Migrate Service req specific database actions

// PutMigrateServicesReq to add MigrateServicesReq info
func (db *Database) PutMigrateServicesReq(deviceID string, vnet string, value string) error {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID) + vnet
	return db.kvc.Put(context.Background(), key, value)
}

// GetMigrateServicesReq to get MigrateServicesReq info
func (db *Database) GetMigrateServicesReq(deviceID string, vnet string) (string, error) {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID) + vnet
	return db.Get(key)
}

// GetAllMigrateServicesReq to get multiple MigrateServicesReq info
func (db *Database) GetAllMigrateServicesReq(deviceID string) (map[string]*kvstore.KVPair, error) {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID)
	return db.List(key)
}

// DelMigrateServicesReq to delete MigrateServicesReq info
func (db *Database) DelMigrateServicesReq(deviceID string, vnet string) error {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID) + vnet
	if err := db.kvc.Delete(context.Background(), key); err != nil {
		logger.Errorf(ctx, "The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	return nil
}

// DelAllMigrateServicesReq to delete all MigrateServicesReq info
func (db *Database) DelAllMigrateServicesReq(deviceID string) error {
	key := fmt.Sprintf(GetKeyPath(ServicesMigrateReqPath), deviceID)
	if err := db.DeleteAllUnderHashKey(key); err != nil {
		logger.Warnf(ctx, "Delete All failed: The key doesn't exist", log.Fields{"key": key, "Error": err})
		return err
	}
	logger.Infow(ctx, "Deleting all the Update Vnet Requests for device", log.Fields{"device": deviceID})
	return nil
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.RegisterPackage(log.JSON, log.ErrorLevel, log.Fields{})
	if err != nil {
		panic(err)
	}
}
