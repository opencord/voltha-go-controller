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
	"errors"
	"fmt"
	"sync"
	common "voltha-go-controller/internal/pkg/types"

	"github.com/google/gopacket/layers"

	"voltha-go-controller/database"
	"voltha-go-controller/log"
)

const (
	// MigrationComplete Represents the Migration Complete
	MigrationComplete = "Completed"
	// MigrationInProgress Represents the Migration Inprogress
	MigrationInProgress = "InProgress"
	// MigrationFailed  Represents the Migration Failed
	MigrationFailed = "Failed"
	// StatusNone for no operations
	StatusNone = "NONE"
	// ModuleToBeDeleted - module where old version is deleted
	ModuleToBeDeleted = "ModuleToBeDeleted"
)

// DataMigration represents the Version and Status info for Major Version Upgrade.
type DataMigration struct {
	ModuleVer map[string]string // eg. "service": "v1"
	Version   string
	Status    string
}

type paramsMigrationFunc func(context.Context, []byte) string

// map to store conversion functions
var migrationMap = map[string]paramsMigrationFunc{
	database.ServicePath:        MigrateServices,
	database.DevicePath:         MigrateDevices,
	database.DevicePortPath:     MigrateDevicePorts,
	database.DeviceFlowPath:     MigrateDeviceFlows,
	database.DeviceGroupPath:    MigrateDeviceGroups,
	database.DeviceMeterPath:    MigrateDeviceMeters,
	database.VnetPath:           MigrateVnets,
	database.VpvPath:            MigrateVpvs,
	database.MvlanPath:          MigrateMvlans,
	database.MeterPath:          MigrateMeters,
	database.IgmpConfPath:       MigrateIgmpConfs,
	database.IgmpGroupPath:      MigrateIgmpGroups,
	database.IgmpDevicePath:     MigrateIgmpDevices,
	database.IgmpChannelPath:    MigrateIgmpChannels,
	database.IgmpPortPath:       MigrateIgmpPorts,
	database.IgmpProfPath:       MigrateIgmpProfs,
	database.McastConfigPath:    MigrateMcastConfs,
	database.LogLevelPath:       MigrateLogLevels,
	database.HealthPath:         MigrateHealth,
	database.PonCounterPath:     MigratePonCounters,
	database.ChannelCounterPath: MigrateChannelCounters,
	database.ServiceCounterPath: MigrateServiceCounters,
	database.NbDevicePath:       MigrateNbDevices,
	database.DeviceFlowHashPath: MigrateDeviceFlowHash,
}

// WriteToDb write a meter profile to DB
func (md *DataMigration) WriteToDb(cntx context.Context) error {
	b, err := json.Marshal(md)
	if err != nil {
		return err
	}
	if err1 := db.PutMigrationInfo(cntx, string(b)); err1 != nil {
		return err1
	}
	return nil
}

// DelFromDb delete a meter profile from DB
func (md *DataMigration) DelFromDb(cntx context.Context) {
	logger.Info(ctx, "Received Delete from Db")
	if err := db.DelMigrationInfo(cntx); err != nil {
		logger.Warnw(ctx, "DelMigrationInfo Failed", log.Fields{"Error": err})
	}
}

// GetMigrationInfo to get data migration info
func GetMigrationInfo(cntx context.Context, dmInfo *DataMigration) error {
	logger.Info(ctx, "Get Migration Info")
	var migrationInfo string
	var err error
	if db == nil {
		db = database.GetDatabase()
	}
	if migrationInfo, err = db.GetMigrationInfo(cntx); err != nil {
		return err
	}
	err = json.Unmarshal([]byte(migrationInfo), &dmInfo)
	if err != nil {
		logger.Warn(ctx, "Unmarshal of migrationinfo failed")
		return err
	}
	return nil
}

// CheckIfMigrationRequired Checks if Migration is Completed
// Only Data Migration and Reboot would be handled in the Below function
// When Roll back happens just Delete of DB keys has to happen
// which will be done once delete key request is received from MSM
func CheckIfMigrationRequired(ctx context.Context) bool {
	logger.Info(ctx, "Check If Migration Required")
	Migrate := new(DataMigration)
	var NoDataInDB bool
	err := GetMigrationInfo(ctx, Migrate)
	logger.Debugw(ctx, "Migration data", log.Fields{"DataMigration": Migrate})
	// No DB entry represents N version Bring Up for the First time
	if err != nil {
		NoDataInDB = true
		logger.Warn(ctx, "Failed to read the Migration Data from DB ")
	}
	// Covers N version bringup and Reboot Scenarios
	if NoDataInDB {
		logger.Info(ctx, "Data Migration Not Required")
		Migrate.Version = database.PresentVersion
		Migrate.Status = MigrationComplete
		Migrate.ModuleVer = database.PresentVersionMap
		if err := Migrate.WriteToDb(ctx); err != nil {
			logger.Warnw(ctx, "DB Write failed for Migration Path", log.Fields{"error": err})
		}
		// MigrateProbestatus has to be Updated to Complete when No Migration is Required
		logger.Debugw(ctx, "Migration Probe Status", log.Fields{"Migration Probe": Migrate.Status})
		// probe.UpdateDBMigrationStatus(ctx, true)
		return false
		// Migration required when vgc moves to Higher Versions
	} else if Migrate.ModuleVer == nil {
		// This case will hit when DataMigration is present with old schema
		// and DataMigration schema has changed.
		// In this case compare previous and current version configured in the models.
		for key, currVer := range database.PresentVersionMap {
			if currVer > database.PreviousVersionMap[key] {
				logger.Infow(ctx, "DB Migration needed for", log.Fields{"comp": key})
				return true
			}
		}
	} else {
		var isVersionChanged bool
		// Compare the current version with previous version present in DB.
		// This case will also hit in case of POD restart.
		for key, currVer := range database.PresentVersionMap {
			if dbVer := Migrate.ModuleVer[key]; dbVer != "" {
				if currVer > dbVer {
					logger.Infow(ctx, "DB Migration needed for", log.Fields{"comp": key})
					isVersionChanged = true
				}
			}
		}
		database.DBVersionMap = Migrate.ModuleVer // Store DB data

		if isVersionChanged {
			return true
		}
	}

	// In case Service Reboots/Rolls Back then Probe Success to MSM
	logger.Debugw(ctx, "Migration Probe Status", log.Fields{"Migration Probe": Migrate.Status})
	//probe.UpdateDBMigrationStatus(ctx, true)
	return false
}

// InitiateDataMigration Migrates the DB data
// depending on the bool value returned by CheckIfMigrationDone
func InitiateDataMigration(ctx context.Context) {
	logger.Info(ctx, "Initiate Data Migration")
	var err error
	Migrate := new(DataMigration)
	var migrationWG sync.WaitGroup

	// Keeping it outside to avoid race condition where the
	// wait check is reached before the go toutine for data migraiton is triggered
	migrationWG.Add(1)

	go func() {
		logger.Debug(ctx, "Started Go Routine for data migration")
		err = MigrateDBData(ctx)
		if err != nil {
			logger.Errorw(ctx, "Failed to Migrate the Data", log.Fields{"error": err})
			Migrate.Status = MigrationFailed
			if err = Migrate.WriteToDb(ctx); err != nil {
				logger.Errorw(ctx, "DB Write failed to Migration Path", log.Fields{"error": err})
			}
		}
		logger.Debug(ctx, "Completed Go Routine for data migration")
		migrationWG.Done()

		Migrate.Version = database.PresentVersion
		Migrate.Status = MigrationInProgress
		Migrate.ModuleVer = database.PresentVersionMap
		if err = Migrate.WriteToDb(ctx); err != nil {
			logger.Errorw(ctx, "DB Write failed for Migration Path", log.Fields{"error": err})
			return
		}
	}()
	// Failure Senario can be Exceptions, incase of panic Update the status as failed
	defer func() {
		if err := recover(); err != nil {
			logger.Errorw(ctx, "Migration failure due to Exception happened", log.Fields{"reason": err})
			Migrate.Status = MigrationFailed
			if err := Migrate.WriteToDb(ctx); err != nil {
				logger.Errorw(ctx, "DB Write failed for Migration Path", log.Fields{"error": err})
			}
			//probe.UpdateDBMigrationStatus(ctx, false)
			return
		}
	}()
	// Wait for all the Db data  migration to complete
	migrationWG.Wait()
	//probe.UpdateDBMigrationStatus(ctx, true)
	Migrate.Status = MigrationComplete
	if err := Migrate.WriteToDb(ctx); err != nil {
		logger.Errorw(ctx, "DB Write failed for Migration Path", log.Fields{"error": err})
	}
	logger.Infow(ctx, "Migration completed successfully", log.Fields{"Status": Migrate.Status})
}

// MigrateDBData to migrate database data
func MigrateDBData(cntx context.Context) error {
	logger.Info(ctx, "Migrate DB Data")
	var err error
	for module, currentVersion := range database.PresentVersionMap {
		if currentVersion == database.DBVersionMap[module] {
			logger.Infow(ctx, "No Data Migration required for module", log.Fields{"Table": module, "Version": currentVersion})
			continue
		}

		if _, ok := migrationMap[module]; ok {
			switch module {
			case database.DeviceFlowPath,
				database.DevicePortPath,
				database.DeviceMeterPath,
				database.DeviceGroupPath,
				database.DeviceFlowHashPath:
				err = FetchAndMigrateDeviceDBData(module)
			default:
				err = FetchAndMigrateDBData(cntx, module)
			}
		} else {
			logger.Infow(ctx, "No Data Migration handling found for module", log.Fields{"Table": module, "Version": currentVersion})
		}

		if err != nil {
			return fmt.Errorf("error in data migration for module %s : %w", module, err)
		}
	}
	return nil
}

// FetchAndMigrateDeviceDBData fetchs the data from database and migrte the same to latest versions and store ot back ot database
func FetchAndMigrateDeviceDBData(module string) error {
	return fmt.Errorf("data migration not implemented for device db data %s : %w", module, nil)
}

// FetchAndMigrateDBData fetchs the data from database and migrte the same to latest versions and store ot back ot database
func FetchAndMigrateDBData(cntx context.Context, module string) error {
	logger.Infow(ctx, "Fetch And Migrate DB Data", log.Fields{"Module": module})
	previousPath := database.GetModuleKeypath(module, database.PreviousVersionMap[module])
	dbPathKeysValueMap, err := db.List(cntx, previousPath)
	if err != nil {
		logger.Warnw(ctx, "failed to Fetch the Keys from Redis", log.Fields{"error": err})
		// No return required, Data might not be present in DB
		return nil
	}
	if len(dbPathKeysValueMap) == 0 {
		logger.Warnw(ctx, "No data present in DB for the path", log.Fields{"dbPath": module})
		return nil
	}

	// Fetch each Path from previous version and store to present version after data migration changes
	for hash, value := range dbPathKeysValueMap {
		logger.Debugw(ctx, "DB path", log.Fields{"hash": hash})
		// convert the value to a specific type based on the dbPath
		b, ok := value.Value.([]byte)
		if !ok {
			return errors.New("Error-in-migration, The value type is not []byt")
		}

		presentParams := migrationMap[module](cntx, b)
		logger.Infow(ctx, "Migrated data", log.Fields{"presentParams": presentParams})
		if "" == presentParams {
			return errors.New("Error-in-migration")
		} else if ModuleToBeDeleted == presentParams {
			return nil
		}
		presentPath := database.GetKeyPath(module) + hash
		logger.Infow(ctx, "Before writing to DB", log.Fields{"presentParams": presentParams})
		if err := db.Put(cntx, presentPath, presentParams); err != nil {
			logger.Errorw(ctx, "Update Params failed", log.Fields{"key": presentPath, "presentparams": presentParams})
			return err
		}
	}
	return nil
}

// MigrateServices modifyies the old data as per current version requirement and updates the database
func MigrateServices(cntx context.Context, data []byte) string {
	logger.Info(ctx, "Migrate Services")
	var vs VoltService
	var updatedData, updatedData1 []byte
	var vsmap map[string]interface{}
	var err1 error

	err := json.Unmarshal(data, &vsmap)
	if err != nil {
		logger.Warnw(ctx, "Unmarshal of VPV failed", log.Fields{"error": err})
		return ""
	}
	// changes to handle change in data type of MacLearning parameter
	if updatedData1, err1 = json.Marshal(&vsmap); err1 != nil {
		logger.Warnw(ctx, "Marshal of Service failed", log.Fields{"Error": err1.Error()})
		return ""
	}

	if err2 := json.Unmarshal(updatedData1, &vs); err != nil {
		logger.Warnw(ctx, "Unmarshal-failed", log.Fields{"err": err2})
		return ""
	}

	if vsmap["MacLearning"] == true {
		vs.MacLearning = Learn
	}

	// Migration
	vs.PendingFlows = make(map[string]bool)
	vs.AssociatedFlows = make(map[string]bool)
	vs.DeleteInProgress = false
	vs.PonPort = 0xFF
	if updatedData, err = vs.JSONMarshal(); err != nil {
		logger.Warnw(ctx, "Marshal of Service failed", log.Fields{"Error": err.Error()})
		return ""
	}
	logger.Infow(ctx, "Service Migrated", log.Fields{"Service": vs.Name, "PresentVersion": database.PresentVersionMap[database.ServicePath]})
	return string(updatedData)
}

// MigrateDevices modifyies the old data as per current version requirement and updates the database
func MigrateDevices(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Devices")
	return ""
}

// MigrateDevicePorts modifyies the old data as per current version requirement and updates the database
func MigrateDevicePorts(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Ports")
	return ""
}

// MigrateDeviceFlows modifyies the old data as per current version requirement and updates the database
func MigrateDeviceFlows(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Flows")
	return ""
}

// MigrateDeviceGroups modifyies the old data as per current version requirement and updates the database
func MigrateDeviceGroups(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Groups")
	return ""
}

// MigrateDeviceMeters modifyies the old data as per current version requirement and updates the database
func MigrateDeviceMeters(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Meters")
	return ""
}

// MigrateDeviceFlowHash modifyies the old data as per current version requirement and updates the database
func MigrateDeviceFlowHash(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for FlowHash")
	return ""
}

// MigrateVnets modifyies the old data as per current version requirement and updates the database
func MigrateVnets(cntx context.Context, data []byte) string {
	logger.Info(ctx, "Migrate Vnets")
	var vnet VoltVnet
	var updatedData []byte

	err := json.Unmarshal(data, &vnet)
	if err != nil {
		logger.Warnw(ctx, "Unmarshal of VNET failed", log.Fields{"error": err})
		return ""
	}

	if vnet.SVlanTpid == 0 {
		vnet.SVlanTpid = layers.EthernetTypeDot1Q
	}
	// MacLeanring parameter was not stored in vnets in 2.7 release.
	if vnet.DhcpRelay || vnet.ArpLearning {
		vnet.MacLearning = Learn
	} else if !vnet.DhcpRelay && !vnet.ArpLearning {
		vnet.MacLearning = MacLearningNone
	}
	vnet.PendingDeleteFlow = make(map[string]map[string]bool)
	vnet.DeleteInProgress = false
	if updatedData, err = vnet.JSONMarshal(); err != nil {
		logger.Warnw(ctx, "Marshal of Vnet failed", log.Fields{"Error": err.Error()})
		return ""
	}
	logger.Infow(ctx, "Vnet Migrated", log.Fields{"Vnet Name": vnet.Name, "PresentVersion": database.PresentVersionMap[database.VnetPath]})
	return string(updatedData)
}

// MigrateVpvs modifyies the old data as per current version requirement and updates the database
func MigrateVpvs(cntx context.Context, data []byte) string {
	logger.Info(ctx, "Migrate Vpvs")
	var vpv VoltPortVnet
	var updatedData, updatedData1 []byte
	var vpvmap map[string]interface{}
	var err1 error
	var usFlowsApplied, dsFlowsApplied bool

	err := json.Unmarshal(data, &vpvmap)
	if err != nil {
		logger.Warnw(ctx, "Unmarshal of VPV failed", log.Fields{"error": err})
		return ""
	}
	// changes to handle change in data type of MacLearning parameter
	if updatedData1, err1 = json.Marshal(&vpvmap); err1 != nil {
		logger.Warnw(ctx, "Marshal of Service failed", log.Fields{"Error": err1.Error()})
		return ""
	}

	if err2 := json.Unmarshal(updatedData1, &vpv); err != nil {
		logger.Warnw(ctx, "Unmarshal-failed", log.Fields{"err": err2})
	}

	if vpvmap["MacLearning"] == true {
		vpv.MacLearning = Learn
	}
	if vpvmap["UsFlowsApplied"] == true {
		usFlowsApplied = true
	}

	if vpvmap["DsFlowsApplied"] == true {
		dsFlowsApplied = true
	}

	if usFlowsApplied && dsFlowsApplied {
		vpv.FlowsApplied = true
	}
	// Migration
	if vpv.SVlanTpid == 0 {
		vpv.SVlanTpid = layers.EthernetTypeDot1Q
	}
	vpv.VnetName = VnetKey(vpv.SVlan, vpv.CVlan, vpv.UniVlan)
	vpv.PendingDeleteFlow = make(map[string]bool)
	vpv.PonPort = 0xFF

	if updatedData, err = vpv.JSONMarshal(); err != nil {
		logger.Warnw(ctx, "Marshal of VPV failed", log.Fields{"Error": err.Error()})
		return ""
	}
	logger.Infow(ctx, "VPV Migrated", log.Fields{"Device": vpv.Device, "port": vpv.Port, "SVlan": vpv.SVlan,
		"CVlan": vpv.CVlan, "UniVlan": vpv.UniVlan, "PresentVersion": database.PresentVersionMap[database.VpvPath]})
	return string(updatedData)
}

// MigrateMvlans modifyies the old data as per current version requirement and updates the database
func MigrateMvlans(cntx context.Context, data []byte) string {
	logger.Info(ctx, "Migrate Mvlans")
	var mvp MvlanProfile
	var updatedData []byte

	err := json.Unmarshal(data, &mvp)
	if err != nil {
		logger.Warn(ctx, "Unmarshal of VPV failed")
		return ""
	}
	// Mvlan Migration
	mvp.IgmpServVersion = make(map[string]*uint8)
	for srNo := range mvp.DevicesList {
		var servVersion uint8
		mvp.IgmpServVersion[srNo] = &servVersion
	}

	if updatedData, err = mvp.JSONMarshal(); err != nil {
		logger.Warnw(ctx, "Marshal of Mvlan Profile failed", log.Fields{"Error": err.Error()})
		return ""
	}
	logger.Infow(ctx, "Mvlan Profile Migrated", log.Fields{"MvlanProfileName": mvp.Name, "PresentVersion": database.PresentVersionMap[database.MvlanPath]})
	return string(updatedData)
}

// MigrateMeters modifyies the old data as per current version requirement and updates the database
func MigrateMeters(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Meters")
	return ""
}

// MigrateIgmpConfs modifyies the old data as per current version requirement and updates the database
func MigrateIgmpConfs(cntx context.Context, data []byte) string {
	logger.Info(ctx, "Migrate IgmpConfs")
	var igmpProfile IgmpProfile

	err := json.Unmarshal(data, &igmpProfile)
	if err != nil {
		logger.Warn(ctx, "Unmarshal of IGMP failed")
		return ""
	}
	if err := igmpProfile.WriteToDb(cntx); err != nil {
		logger.Warnw(ctx, "Igmp profile Write to DB failed", log.Fields{"profileID": igmpProfile.ProfileID})
	}

	logger.Infow(ctx, "Igmp Conf Migrated", log.Fields{"Profile": igmpProfile, "PresentVersion": database.PresentVersionMap[database.VpvPath]})
	return ModuleToBeDeleted
}

// MigrateIgmpGroups modifyies the old data as per current version requirement and updates the database
func MigrateIgmpGroups(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for IGMP Groups")
	return ""
}

// MigrateIgmpDevices modifyies the old data as per current version requirement and updates the database
func MigrateIgmpDevices(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for IGMP Device")
	return ""
}

// MigrateIgmpChannels modifyies the old data as per current version requirement and updates the database
func MigrateIgmpChannels(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for IGMP Channels")
	return ""
}

// MigrateIgmpPorts modifyies the old data as per current version requirement and updates the database
func MigrateIgmpPorts(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for IGMP Ports")
	return ""
}

// MigrateIgmpProfs modifyies the old data as per current version requirement and updates the database
func MigrateIgmpProfs(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for IGMP Profs")
	return ""
}

// MigrateMcastConfs modifyies the old data as per current version requirement and updates the database
func MigrateMcastConfs(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Mcast Confs")
	return ""
}

// MigrateLogLevels modifyies the old data as per current version requirement and updates the database
func MigrateLogLevels(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Log Levels")
	return ""
}

// MigrateHealth modifyies the old data as per current version requirement and updates the database
func MigrateHealth(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Health")
	return ""
}

// MigratePonCounters modifyies the old data as per current version requirement and updates the database
func MigratePonCounters(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Pon Counters")
	return ""
}

// MigrateChannelCounters modifyies the old data as per current version requirement and updates the database
func MigrateChannelCounters(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Channel Counters")
	return ""
}

// MigrateServiceCounters modifyies the old data as per current version requirement and updates the database
func MigrateServiceCounters(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for Service Counters")
	return ""
}

// MigrateNbDevices modifyies the old data as per current version requirement and updates the database
func MigrateNbDevices(cntx context.Context, data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for NB Devices")
	return ""
}

// MigrateFlowHash modifyies the old data as per current version requirement and updates the database
func MigrateFlowHash(data []byte) string {
	logger.Error(ctx, "Data Migration not implemented for FLow Hash")
	return ""
}

// DeleteDbPathKeys Deleted the paths from DB
func DeleteDbPathKeys(cntx context.Context, keyPath string) error {
	logger.Infow(ctx, "Deleting paths for version", log.Fields{"Path": keyPath})

	// Delete all the keys
	err := db.DeleteAll(cntx, keyPath)
	if err != nil && err.Error() != common.ErrEntryNotFound.Error() {
		logger.Errorw(ctx, "Delete Key failed", log.Fields{"error": err})
		return err
	}
	return nil
}
