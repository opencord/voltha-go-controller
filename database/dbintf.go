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

package database

import (
	"net"

	"voltha-go-controller/internal/pkg/of"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
)

var dbObj DBIntf

// DBIntf defines db related methods
type DBIntf interface {
	Get(key string) (string, error)
	Put(fullKeyPath string, value string) error
	Del(path string)
	List(key string) (map[string]*kvstore.KVPair, error)
	DeleteAll(path string) error
	DeleteAllUnderHashKey(hashKeyPrefix string) error
	GetOlt(deviceID string) (string, error)
	PutOlt(deviceID string, value string) error
	DelOlt(deviceID string)
	GetFlow(deviceID string, flowID uint64) (string, error)
	GetFlows(deviceID string) (map[string]*kvstore.KVPair, error)
	PutFlow(deviceID string, flowID uint64, value string) error
	DelFlow(deviceID string, flowID uint64)
	PutGroup(deviceID string, groupID uint32, value string) error
	GetGroup(deviceID string, groupID uint32) (string, error)
	GetGroups(deviceID string) (map[string]*kvstore.KVPair, error)
	DelGroup(deviceID string, groupID uint32)
	DelAllGroup(string)
	DelAllPorts(deviceID string)
	DelPort(deviceID string, portID uint32)
	PutPort(deviceID string, portID uint32, value string) error
	GetPort(deviceID string, portID uint32) (string, error)
	GetPorts(deviceID string) (map[string]*kvstore.KVPair, error)
	PutDeviceMeter(deviceID string, meterID uint32, value string) error
	GetDeviceMeter(deviceID string, meterID uint32) (string, error)
	GetDeviceMeters(deviceID string) (map[string]*kvstore.KVPair, error)
	DelDeviceMeter(deviceID string, meterID uint32)
	GetService(name string) (string, error)
	GetServices() (map[string]*kvstore.KVPair, error)
	PutService(name string, value string) error
	DelService(name string)
	GetVnets() (map[string]*kvstore.KVPair, error)
	GetVnet(name string) (string, error)
	PutVnet(name string, value string) error
	DelVnet(name string)
	GetVpvs() (map[string]*kvstore.KVPair, error)
	GetVpv(port string, SVlan uint16, CVlan uint16, UniVlan uint16) (string, error)
	PutVpv(port string, SVlan uint16, CVlan uint16, UniVlan uint16, value string) error
	DelVpv(port string, SVlan uint16, CVlan uint16, UniVlan uint16)
	GetMvlans() (map[string]*kvstore.KVPair, error)
	GetMvlan(mvlan uint16) (string, error)
	PutMvlan(mvlan uint16, value string) error
	DelMvlan(mvlan uint16)
	DelIGMPCfg()
	GetHealth() (string, error)
	PutHealth(value string) error
	DelHealth()
	GetMeters() (map[string]*kvstore.KVPair, error)
	GetMeter(name string) (string, error)
	PutMeter(name string, value string) error
	DelMeter(name string)
	DelAllMeter(device string)
	GetIgmpGroups() (map[string]*kvstore.KVPair, error)
	GetIgmpGroup(id string) (string, error)
	PutIgmpGroup(id string, value string) error
	DelIgmpGroup(id string)
	GetAllIgmpDevices() (map[string]*kvstore.KVPair, error)
	GetPrevIgmpDevices(mvlan of.VlanType, gid string) (map[string]*kvstore.KVPair, error)
	GetIgmpDevices(mvlan of.VlanType, gid string, gip net.IP) (map[string]*kvstore.KVPair, error)
	GetIgmpDevice(mvlan of.VlanType, gid string, gip net.IP, device string) (string, error)
	PutIgmpDevice(mvlan of.VlanType, gid string, gip net.IP, device string, value string) error
	DelIgmpDevice(mvlan of.VlanType, gid string, gip net.IP, device string)
	GetAllIgmpChannels() (map[string]*kvstore.KVPair, error)
	GetPrevIgmpChannels(gname string, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpChannels(mvlan of.VlanType, gname string, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpChannel(mvlan of.VlanType, gName string, device string, gip net.IP) (string, error)
	PutIgmpChannel(mvlan of.VlanType, gName string, device string, gip net.IP, value string) error
	DelIgmpChannel(mvlan of.VlanType, gName string, device string, gip net.IP)
	GetAllIgmpRcvrs() (map[string]*kvstore.KVPair, error)
	GetPrevIgmpRcvrs(gip net.IP, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpRcvrs(mvlan of.VlanType, gip net.IP, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpRcvr(mvlan of.VlanType, gip net.IP, device string, rcvr string) (string, error)
	PutIgmpRcvr(mvlan of.VlanType, gip net.IP, device string, rcvr string, value string) error
	DelIgmpRcvr(mvlan of.VlanType, gip net.IP, device string, rcvr string)
	DelAllIgmpRcvr(mvlan of.VlanType, gip net.IP, device string)
	DelAllRoutesForDevice(device string)
	DelNbDevicePort(device string, ponPortID uint32)
	GetAllNbPorts(deviceID string) (map[string]*kvstore.KVPair, error)
	GetMigrationInfo() (string, error)
	PutMigrationInfo(value string) error
	DelMigrationInfo()
	GetAllPonCounters(device string) (map[string]*kvstore.KVPair, error)
	GetPonCounter(device string, ponID string) (string, error)
	PutPonCounter(device string, ponID string, value string) error
	DelPonCounter(device string, ponID string)
	GetAllPonChannelCounters(device string, ponID string) (map[string]*kvstore.KVPair, error)
	GetPonChannelCounter(device string, ponID string, channel string) (string, error)
	PutNbDevicePort(device string, ponPortID uint32, value string)
	PutPonChannelCounter(device string, ponID string, channel string, value string) error
	DelPonChannelCounter(device string, ponID string, channel string)
	DelAllPONCounters(device string)
	DelPONCounters(device string, ponID string)
	GetAllServiceChannelCounters(serviceName string) (map[string]*kvstore.KVPair, error)
	GetServiceChannelCounter(serviceName string, channel string) (string, error)
	PutServiceChannelCounter(serviceName string, channel string, value string) error
	DelServiceChannelCounter(serviceName string, channel string)
	DelAllServiceChannelCounter(serviceName string)
	PutOltIgmpCounters(device string, value string) error
	GetOltIgmpCounter(device string) (string, error)
	PutFlowHash(deviceID string, value string) error
	GetFlowHash(deviceID string) (string, error)
	OltExists(deviceID string) bool
	GetIgmpProfiles() (map[string]*kvstore.KVPair, error)
	GetIgmpProfile(name string) (string, error)
	PutIgmpProfile(name string, value string) error
	DelIgmpProfile(name string)
	GetMcastConfigs() (map[string]*kvstore.KVPair, error)
	GetMcastConfig(name string) (string, error)
	PutMcastConfig(name string, value string) error
	DelMcastConfig(name string)
	PutPortAlarmProfile(portAlarmProfileID string, value string)
	GetPortAlarmProfile(portAlarmProfileID string) (map[string]*kvstore.KVPair, error)
	DelPortAlarmProfile(portAlarmProfileID string)
	PutPortAlarmData(deviceID string, portID uint32, value string)
	GetPortAlarmData(deviceID string, portID uint32) (string, error)
	DelPortAlarmData(deviceID string, portID uint32)
	GetAllPortAlarmData(deviceID string) (map[string]*kvstore.KVPair, error)
	PutSubAlarmData(deviceID string, portName string, value string)
	GetSubAlarmData(deviceID string, portName string) (string, error)
	DelSubAlarmData(deviceID string, portName string)
	GetAllSubAlarmData(deviceID string) (map[string]*kvstore.KVPair, error)
	PutMigrateServicesReq(deviceID string, vlan string, value string) error
	GetMigrateServicesReq(deviceID string, vlan string) (string, error)
	GetAllMigrateServicesReq(deviceID string) (map[string]*kvstore.KVPair, error)
	DelMigrateServicesReq(deviceID string, vlan string)
	DelAllMigrateServicesReq(deviceID string)
}

//GetDatabase - returns databse operation based on configuration
func GetDatabase() DBIntf {
	return dbObj
}

//SetDatabase - sets the DB object based on the type
func SetDatabase(df DBIntf) {
	dbObj = df
}
