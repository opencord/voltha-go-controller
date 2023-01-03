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
	"context"
	"net"

	"voltha-go-controller/internal/pkg/of"

	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
)

var dbObj DBIntf

// DBIntf defines db related methods
type DBIntf interface {
	Get(ctx context.Context, key string) (string, error)
	Put(ctx context.Context, fullKeyPath string, value string) error
	Del(ctx context.Context, path string) error
	List(ctx context.Context, key string) (map[string]*kvstore.KVPair, error)
	DeleteAll(ctx context.Context, path string) error
	DeleteAllUnderHashKey(ctx context.Context, hashKeyPrefix string) error
	GetOlt(ctx context.Context, deviceID string) (string, error)
	PutOlt(ctx context.Context, deviceID string, value string) error
	DelOlt(ctx context.Context, deviceID string) error
	GetFlow(ctx context.Context, deviceID string, flowID uint64) (string, error)
	GetFlows(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	PutFlow(ctx context.Context, deviceID string, flowID uint64, value string) error
	DelFlow(ctx context.Context, deviceID string, flowID uint64) error
	PutGroup(ctx context.Context, deviceID string, groupID uint32, value string) error
	GetGroup(ctx context.Context, deviceID string, groupID uint32) (string, error)
	GetGroups(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	DelGroup(ctx context.Context, deviceID string, groupID uint32) error
	DelAllGroup(ctx context.Context, deviceID string) error
	DelAllPorts(ctx context.Context, deviceID string) error
	DelPort(ctx context.Context, deviceID string, portID uint32) error
	PutPort(ctx context.Context, deviceID string, portID uint32, value string) error
	GetPort(ctx context.Context, deviceID string, portID uint32) (string, error)
	GetPorts(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	PutDeviceMeter(ctx context.Context, deviceID string, meterID uint32, value string) error
	GetDeviceMeter(ctx context.Context, deviceID string, meterID uint32) (string, error)
	GetDeviceMeters(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	DelDeviceMeter(ctx context.Context, deviceID string, meterID uint32) error
	GetService(ctx context.Context, name string) (string, error)
	GetServices(ctx context.Context) (map[string]*kvstore.KVPair, error)
	PutService(ctx context.Context, name string, value string) error
	DelService(ctx context.Context, name string) error
	GetVnets(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetVnet(ctx context.Context, name string) (string, error)
	PutVnet(ctx context.Context, name string, value string) error
	DelVnet(ctx context.Context, name string) error
	GetVpvs(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetVpv(ctx context.Context, port string, SVlan uint16, CVlan uint16, UniVlan uint16) (string, error)
	PutVpv(ctx context.Context, port string, SVlan uint16, CVlan uint16, UniVlan uint16, value string) error
	DelVpv(ctx context.Context, port string, SVlan uint16, CVlan uint16, UniVlan uint16) error
	GetMvlans(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetMvlan(ctx context.Context, mvlan uint16) (string, error)
	PutMvlan(ctx context.Context, mvlan uint16, value string) error
	DelMvlan(ctx context.Context, mvlan uint16) error
	DelIGMPCfg(ctx context.Context) error
	GetHealth(ctx context.Context) (string, error)
	PutHealth(ctx context.Context, value string) error
	DelHealth(ctx context.Context) error
	GetMeters(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetMeter(ctx context.Context, name string) (string, error)
	PutMeter(ctx context.Context, name string, value string) error
	DelMeter(ctx context.Context, name string) error
	DelAllMeter(ctx context.Context, device string) error
	GetIgmpGroups(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetIgmpGroup(ctx context.Context, id string) (string, error)
	PutIgmpGroup(ctx context.Context, id string, value string) error
	DelIgmpGroup(ctx context.Context, id string) error
	GetAllIgmpDevices(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetPrevIgmpDevices(ctx context.Context, mvlan of.VlanType, gid string) (map[string]*kvstore.KVPair, error)
	GetIgmpDevices(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP) (map[string]*kvstore.KVPair, error)
	GetIgmpDevice(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP, device string) (string, error)
	PutIgmpDevice(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP, device string, value string) error
	DelIgmpDevice(ctx context.Context, mvlan of.VlanType, gid string, gip net.IP, device string) error
	GetAllIgmpChannels(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetPrevIgmpChannels(ctx context.Context, gname string, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpChannels(ctx context.Context, mvlan of.VlanType, gname string, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpChannel(ctx context.Context, mvlan of.VlanType, gName string, device string, gip net.IP) (string, error)
	PutIgmpChannel(ctx context.Context, mvlan of.VlanType, gName string, device string, gip net.IP, value string) error
	DelIgmpChannel(ctx context.Context, mvlan of.VlanType, gName string, device string, gip net.IP) error
	GetAllIgmpRcvrs(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetPrevIgmpRcvrs(ctx context.Context, gip net.IP, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpRcvrs(ctx context.Context, mvlan of.VlanType, gip net.IP, device string) (map[string]*kvstore.KVPair, error)
	GetIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string, rcvr string) (string, error)
	PutIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string, rcvr string, value string) error
	DelIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string, rcvr string) error
	DelAllIgmpRcvr(ctx context.Context, mvlan of.VlanType, gip net.IP, device string) error
	DelAllRoutesForDevice(ctx context.Context, device string) error
	DelNbDevicePort(ctx context.Context, device string, ponPortID uint32)
	GetAllNbPorts(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	GetMigrationInfo(ctx context.Context) (string, error)
	PutMigrationInfo(ctx context.Context, value string) error
	DelMigrationInfo(ctx context.Context) error
	GetAllPonCounters(ctx context.Context, device string) (map[string]*kvstore.KVPair, error)
	GetPonCounter(ctx context.Context, device string, ponID string) (string, error)
	PutPonCounter(ctx context.Context, device string, ponID string, value string) error
	DelPonCounter(ctx context.Context, device string, ponID string) error
	GetAllPonChannelCounters(ctx context.Context, device string, ponID string) (map[string]*kvstore.KVPair, error)
	GetPonChannelCounter(ctx context.Context, device string, ponID string, channel string) (string, error)
	PutNbDevicePort(ctx context.Context, device string, ponPortID uint32, value string)
	GetDeviceConfig(ctx context.Context) (map[string]*kvstore.KVPair, error)
	PutDeviceConfig(ctx context.Context, serialNum string, value string) error
	PutPonChannelCounter(ctx context.Context, device string, ponID string, channel string, value string) error
	DelPonChannelCounter(ctx context.Context, device string, ponID string, channel string) error
	DelAllPONCounters(ctx context.Context, device string) error
	DelPONCounters(ctx context.Context, device string, ponID string)
	GetAllServiceChannelCounters(ctx context.Context, serviceName string) (map[string]*kvstore.KVPair, error)
	GetServiceChannelCounter(ctx context.Context, serviceName string, channel string) (string, error)
	PutServiceChannelCounter(ctx context.Context, serviceName string, channel string, value string) error
	DelServiceChannelCounter(ctx context.Context, serviceName string, channel string) error
	DelAllServiceChannelCounter(ctx context.Context, serviceName string) error
	PutOltIgmpCounters(ctx context.Context, device string, value string) error
	GetOltIgmpCounter(ctx context.Context, device string) (string, error)
	PutFlowHash(ctx context.Context, deviceID string, value string) error
	GetFlowHash(ctx context.Context, deviceID string) (string, error)
	OltExists(ctx context.Context, deviceID string) bool
	GetIgmpProfiles(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetIgmpProfile(ctx context.Context, name string) (string, error)
	PutIgmpProfile(ctx context.Context, name string, value string) error
	DelIgmpProfile(ctx context.Context, name string) error
	GetMcastConfigs(ctx context.Context) (map[string]*kvstore.KVPair, error)
	GetMcastConfig(ctx context.Context, name string) (string, error)
	PutMcastConfig(ctx context.Context, name string, value string) error
	DelMcastConfig(ctx context.Context, name string) error
	PutPortAlarmProfile(ctx context.Context, portAlarmProfileID string, value string)
	GetPortAlarmProfile(ctx context.Context, portAlarmProfileID string) (map[string]*kvstore.KVPair, error)
	DelPortAlarmProfile(ctx context.Context, portAlarmProfileID string)
	PutPortAlarmData(ctx context.Context, deviceID string, portID uint32, value string)
	GetPortAlarmData(ctx context.Context, deviceID string, portID uint32) (string, error)
	DelPortAlarmData(ctx context.Context, deviceID string, portID uint32)
	GetAllPortAlarmData(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	PutSubAlarmData(ctx context.Context, deviceID string, portName string, value string)
	GetSubAlarmData(ctx context.Context, deviceID string, portName string) (string, error)
	DelSubAlarmData(ctx context.Context, deviceID string, portName string)
	GetAllSubAlarmData(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	PutMigrateServicesReq(ctx context.Context, deviceID string, vlan string, value string) error
	GetMigrateServicesReq(ctx context.Context, deviceID string, vlan string) (string, error)
	GetAllMigrateServicesReq(ctx context.Context, deviceID string) (map[string]*kvstore.KVPair, error)
	DelMigrateServicesReq(ctx context.Context, deviceID string, vlan string) error
	DelAllMigrateServicesReq(ctx context.Context, deviceID string) error
	PutOltFlowService(ctx context.Context, value string) error
	GetOltFlowService(ctx context.Context) (string, error)
}

//GetDatabase - returns databse operation based on configuration
func GetDatabase() DBIntf {
	return dbObj
}

//SetDatabase - sets the DB object based on the type
func SetDatabase(df DBIntf) {
	dbObj = df
}
