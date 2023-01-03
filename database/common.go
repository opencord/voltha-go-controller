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

import "fmt"

const (
	// PresentVersion represnts the Present version
	// Modify this as we give Major version releases
	PresentVersion = "v1"
	// PreviousVersion represnts the Previous version
	PreviousVersion = "v1"
)

//These are present path where different database elements are store in database
//In case any of these paths change, update the present and previous version
const (
	BasePath               string = "service/vgc/%s/"
	ServicePath            string = "services/"
	DevicePath             string = "devices/%s/"
	DevicePortPath         string = DevicePath + "ports/"
	DeviceFlowPath         string = DevicePath + "flows/"
	DeviceGroupPath        string = DevicePath + "groups/"
	DeviceMeterPath        string = DevicePath + "meters/"
	VnetPath               string = "vnets/"
	VpvPath                string = "vpvs/"
	MvlanPath              string = "mvlans/"
	MeterPath              string = "meters/"
	IgmpConfPath           string = "igmp/conf/"
	IgmpGroupPath          string = "igmp/groups/"
	IgmpDevicePath         string = "igmp/devices/"
	IgmpChannelPath        string = "igmp/channels/"
	IgmpPortPath           string = "igmp/ports/"
	IgmpProfPath           string = "igmp/prof/"
	McastConfigPath        string = "igmp/mcastconfig/"
	MigrationInfoPath      string = "data/migration/"
	LogLevelPath           string = "log-level/"
	HealthPath             string = "health/"
	PonCounterPath         string = "pon-counter/"
	OltIgmpCounterPath     string = "olt-igmp-counter/"
	ChannelCounterPath     string = "channel-counter/"
	ServiceCounterPath     string = "service-counter/"
	NbDevicePath           string = "nb-device/"
	DeviceFlowHashPath     string = DevicePath + "flowhash"
	PortAlarmProfilePath   string = "port-alarm-profile/"
	PortAlarmDataPath      string = DevicePortPath + "portalarmdata/"
	SubAlarmDataPath       string = DevicePath + "sub-alarm-data/"
	ServicesMigrateReqPath string = DevicePath + "migrateServicesReq/"
	DeviceConfigPath       string = "device-config/"
)

//PresentVersionMap - map of present version for all database tables
var PresentVersionMap = map[string]string{
	ServicePath:            "v3",
	DevicePath:             "v1",
	DevicePortPath:         "v1",
	DeviceFlowPath:         "v1",
	DeviceGroupPath:        "v1",
	DeviceMeterPath:        "v1",
	VnetPath:               "v3",
	VpvPath:                "v3",
	MvlanPath:              "v3",
	MeterPath:              "v1",
	IgmpConfPath:           "v2",
	IgmpGroupPath:          "v1",
	IgmpDevicePath:         "v1",
	IgmpChannelPath:        "v1",
	IgmpPortPath:           "v1",
	IgmpProfPath:           "v1",
	McastConfigPath:        "v1",
	MigrationInfoPath:      "v1",
	LogLevelPath:           "v1",
	HealthPath:             "v1",
	PonCounterPath:         "v1",
	OltIgmpCounterPath:     "v1",
	ChannelCounterPath:     "v1",
	ServiceCounterPath:     "v1",
	NbDevicePath:           "v1",
	DeviceFlowHashPath:     "v1",
	PortAlarmProfilePath:   "v1",
	PortAlarmDataPath:      "v1",
	SubAlarmDataPath:       "v1",
	ServicesMigrateReqPath: "v1",
	DeviceConfigPath:       "v1",
}

//PreviousVersionMap - map of previous version for all database tables
var PreviousVersionMap = map[string]string{
	ServicePath:            "v2",
	DevicePath:             "v1",
	DevicePortPath:         "v1",
	DeviceFlowPath:         "v1",
	DeviceGroupPath:        "v1",
	DeviceMeterPath:        "v1",
	VnetPath:               "v2",
	VpvPath:                "v2",
	MvlanPath:              "v2",
	MeterPath:              "v1",
	IgmpConfPath:           "v1",
	IgmpGroupPath:          "v1",
	IgmpDevicePath:         "v1",
	IgmpChannelPath:        "v1",
	IgmpPortPath:           "v1",
	IgmpProfPath:           "v1",
	McastConfigPath:        "v1",
	MigrationInfoPath:      "v1",
	LogLevelPath:           "v1",
	HealthPath:             "v1",
	PonCounterPath:         "v1",
	OltIgmpCounterPath:     "v1",
	ChannelCounterPath:     "v1",
	ServiceCounterPath:     "v1",
	NbDevicePath:           "v1",
	DeviceFlowHashPath:     "v1",
	PortAlarmProfilePath:   "v1",
	PortAlarmDataPath:      "v1",
	SubAlarmDataPath:       "v1",
	ServicesMigrateReqPath: "v1",
	DeviceConfigPath:       "v1",
}

//DBVersionMap - Version of tables present in DB
var DBVersionMap = PreviousVersionMap

// GetModuleKeypath returns the DB keypath for particular module along with version
func GetModuleKeypath(key, ver string) string {
	return fmt.Sprintf(BasePath, ver) + key
}

// GetKeyPath returns the base path for the given key along with version
func GetKeyPath(key string) string {
	return fmt.Sprintf(BasePath, PresentVersionMap[key]) + key
}
