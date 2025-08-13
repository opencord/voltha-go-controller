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

package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"encoding/hex"

	"voltha-go-controller/database"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/tasks"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/pkg/vpagent"

	"voltha-go-controller/log"
)

var logger log.CLogger
var ctx = context.TODO()

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}

var db database.DBIntf

type VoltControllerInterface interface {
	GetDevice(id string) (*Device, error)
	GetAllPendingFlows() ([]*of.VoltSubFlow, error)
	GetAllFlows() ([]*of.VoltSubFlow, error)
	GetFlows(deviceID string) ([]*of.VoltSubFlow, error)
	GetFlow(deviceID string, cookie uint64) (*of.VoltSubFlow, error)
	GetGroups(cntx context.Context, id uint32) (*of.Group, error)
	GetGroupList() ([]*of.Group, error)
	GetMeterInfo(cntx context.Context, id uint32) (map[string]*of.Meter, error)
	GetAllMeterInfo() (map[string][]*of.Meter, error)
	GetTaskList(device string) []tasks.Task
}

// VoltController structure
//
//nolint:govet
type VoltController struct {
	ctx                     context.Context
	app                     intf.App
	BlockedDeviceList       *util.ConcurrentMap
	deviceTaskQueue         *util.ConcurrentMap
	vagent                  map[string]*vpagent.VPAgent
	Devices                 sync.Map
	rebootInProgressDevices map[string]string
	deviceLock              sync.RWMutex
	rebootLock              sync.Mutex
	deviceTableSyncDuration time.Duration // Time interval between each cycle of audit task
	maxFlowRetryDuration    time.Duration // Maximum duration for which flows will be retried upon failures
	maxFlowRetryAttempts    int64         // maxFlowRetryAttempt = maxFlowRetryDuration / deviceTableSyncDuration
	RebootFlow              bool
}

var vcontroller *VoltController

// NewController is the constructor for VoltController
func NewController(ctx context.Context, app intf.App) intf.IVPClientAgent {
	var controller VoltController

	controller.rebootInProgressDevices = make(map[string]string)
	controller.deviceLock = sync.RWMutex{}
	controller.ctx = ctx
	controller.app = app
	controller.BlockedDeviceList = util.NewConcurrentMap()
	controller.deviceTaskQueue = util.NewConcurrentMap()
	db = database.GetDatabase()
	vcontroller = &controller
	return &controller
}

// SetDeviceTableSyncDuration - sets interval between device table sync up activity
// duration - in minutes
func (v *VoltController) SetDeviceTableSyncDuration(duration int) {
	v.deviceTableSyncDuration = time.Duration(duration) * time.Second
}

// SetMaxFlowRetryDuration - sets max flow retry interval
func (v *VoltController) SetMaxFlowRetryDuration(duration int) {
	v.maxFlowRetryDuration = time.Duration(duration) * time.Second
}

// SetMaxFlowRetryAttempts - sets max flow retry attempts
func (v *VoltController) SetMaxFlowRetryAttempts() {
	v.maxFlowRetryAttempts = int64((v.maxFlowRetryDuration / v.deviceTableSyncDuration))
}

// GetDeviceTableSyncDuration - returns configured device table sync duration
func (v *VoltController) GetDeviceTableSyncDuration() time.Duration {
	return v.deviceTableSyncDuration
}

// GetMaxFlowRetryAttempt - returns max flow retry attempst
func (v *VoltController) GetMaxFlowRetryAttempt() int64 {
	return v.maxFlowRetryAttempts
}

// AddDevice to add device
func (v *VoltController) AddDevice(cntx context.Context, config *intf.VPClientCfg) intf.IVPClient {
	d := NewDevice(cntx, config.DeviceID, config.SerialNum, config.VolthaClient, config.SouthBoundID, config.MfrDesc, config.HwDesc, config.SwDesc)
	v.Devices.Store(config.DeviceID, d)
	v.app.AddDevice(cntx, d.ID, d.SerialNum, config.SouthBoundID)

	d.RestoreMetersFromDb(cntx)
	d.RestoreGroupsFromDb(cntx)
	d.RestoreFlowsFromDb(cntx)
	d.RestorePortsFromDb(cntx)
	d.ConnectInd(context.TODO(), intf.DeviceDisc)
	d.packetOutChannel = config.PacketOutChannel

	logger.Debugw(ctx, "Added device", log.Fields{"Device": config.DeviceID, "SerialNo": d.SerialNum, "State": d.State})

	return d
}

// DelDevice to delete device
func (v *VoltController) DelDevice(cntx context.Context, id string) {
	var device *Device
	d, ok := v.Devices.Load(id)
	if ok {
		v.Devices.Delete(id)
		device, ok = d.(*Device)
		if ok {
			device.Delete()
		}
	}
	v.app.DelDevice(cntx, id)
	device.cancel() // To stop the device tables sync routine
	logger.Debugw(ctx, "Deleted device", log.Fields{"Device": id})
}

// AddControllerTask - add task to controller queue
func (v *VoltController) AddControllerTask(device string, task tasks.Task) {
	var taskQueueIntf interface{}
	var taskQueue *tasks.Tasks
	var found bool
	if taskQueueIntf, found = v.deviceTaskQueue.Get(device); !found {
		taskQueue = tasks.NewTasks(context.TODO())
		v.deviceTaskQueue.Set(device, taskQueue)
	} else {
		taskQueue = taskQueueIntf.(*tasks.Tasks)
	}
	taskQueue.AddTask(task)
	logger.Debugw(ctx, "Task Added to Controller Task List", log.Fields{"Len": taskQueue.NumPendingTasks(), "Total": taskQueue.TotalTasks()})
}

// AddNewDevice - called when new device is discovered. This will be
// processed as part of controller queue
func (v *VoltController) AddNewDevice(config *intf.VPClientCfg) {
	adt := NewAddDeviceTask(config)
	v.AddControllerTask(config.DeviceID, adt)
}

// GetDevice to get device info
func (v *VoltController) GetDevice(id string) (*Device, error) {
	var device *Device
	d, ok := v.Devices.Load(id)
	if !ok {
		return nil, errorCodes.ErrDeviceNotFound
	}
	device, ok = d.(*Device)
	if ok {
		return device, nil
	}
	return nil, errorCodes.ErrDeviceNotFound
}

// IsRebootInProgressForDevice to check if reboot is in progress for the device
func (v *VoltController) IsRebootInProgressForDevice(device string) bool {
	v.rebootLock.Lock()
	defer v.rebootLock.Unlock()
	_, ok := v.rebootInProgressDevices[device]
	return ok
}

// SetRebootInProgressForDevice to set reboot in progress for the device
func (v *VoltController) SetRebootInProgressForDevice(device string) bool {
	v.rebootLock.Lock()
	defer v.rebootLock.Unlock()
	_, ok := v.rebootInProgressDevices[device]
	if ok {
		return true
	}
	v.rebootInProgressDevices[device] = device
	logger.Warnw(ctx, "Setted Reboot-In-Progress flag", log.Fields{"Device": device})

	d, err := v.GetDevice(device)
	if err == nil {
		d.ResetCache()
	} else {
		logger.Errorw(ctx, "Failed to get device", log.Fields{"Device": device, "Error": err})
	}

	return true
}

// ReSetRebootInProgressForDevice to reset reboot in progress for the device
func (v *VoltController) ReSetRebootInProgressForDevice(device string) bool {
	v.rebootLock.Lock()
	defer v.rebootLock.Unlock()
	_, ok := v.rebootInProgressDevices[device]
	if !ok {
		return true
	}
	delete(v.rebootInProgressDevices, device)
	logger.Warnw(ctx, "Resetted Reboot-In-Progress flag", log.Fields{"Device": device})
	return true
}

// DeviceRebootInd is device reboot indication
func (v *VoltController) DeviceRebootInd(cntx context.Context, dID string, srNo string, sbID string) {
	v.app.DeviceRebootInd(cntx, dID, srNo, sbID)
	_ = db.DelAllRoutesForDevice(cntx, dID)
	_ = db.DelAllGroup(cntx, dID)
	_ = db.DelAllMeter(cntx, dID)
	_ = db.DelAllPONCounters(cntx, dID)
}

// DeviceDisableInd is device deactivation indication
func (v *VoltController) DeviceDisableInd(cntx context.Context, dID string) {
	v.app.DeviceDisableInd(cntx, dID)
}

// TriggerPendingProfileDeleteReq - trigger pending profile delete requests
func (v *VoltController) TriggerPendingProfileDeleteReq(cntx context.Context, device string) {
	v.app.TriggerPendingProfileDeleteReq(cntx, device)
}

// TriggerPendingMigrateServicesReq - trigger pending services migration requests
func (v *VoltController) TriggerPendingMigrateServicesReq(cntx context.Context, device string) {
	v.app.TriggerPendingMigrateServicesReq(cntx, device)
}

// SetAuditFlags to set the audit flags
func (v *VoltController) SetAuditFlags(device *Device) {
	v.app.SetRebootFlag(true)
	device.auditInProgress = true
}

// ResetAuditFlags to reset the audit flags
func (v *VoltController) ResetAuditFlags(device *Device) {
	v.app.SetRebootFlag(false)
	device.auditInProgress = false
}

// ProcessFlowModResultIndication - send flow mod result notification
func (v *VoltController) ProcessFlowModResultIndication(cntx context.Context, flowStatus intf.FlowStatus) {
	v.app.ProcessFlowModResultIndication(cntx, flowStatus)
}

func (v *VoltController) CheckAndDeactivateService(ctx context.Context, flow *of.VoltSubFlow, devSerialNum string, devID string) {
	v.app.CheckAndDeactivateService(ctx, flow, devSerialNum, devID)
}

// AddVPAgent to add the vpagent
func (v *VoltController) AddVPAgent(vep string, vpa *vpagent.VPAgent) {
	v.vagent[vep] = vpa
}

// VPAgent to get vpagent info
func (v *VoltController) VPAgent(vep string) (*vpagent.VPAgent, error) {
	vpa, ok := v.vagent[vep]
	if ok {
		return vpa, nil
	}
	return nil, errors.New("VPA Not Registered")
}

// PacketOutReq for packet out request
func (v *VoltController) PacketOutReq(device string, inport string, outport string, pkt []byte, isCustomPkt bool) error {
	logger.Debugw(ctx, "Packet Out Req", log.Fields{"Device": device, "OutPort": outport})
	d, err := v.GetDevice(device)
	if err != nil {
		return err
	}
	logger.Debugw(ctx, "Packet Out Pkt", log.Fields{"Pkt": hex.EncodeToString(pkt)})
	return d.PacketOutReq(inport, outport, pkt, isCustomPkt)
}

// AddFlows to add flows
func (v *VoltController) AddFlows(cntx context.Context, port string, device string, flow *of.VoltFlow) error {
	d, err := v.GetDevice(device)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": device})
		return err
	}
	devPort := d.GetPortByName(port)
	if devPort == nil {
		logger.Errorw(ctx, "Port Not Found", log.Fields{"Device": device})
		return errorCodes.ErrPortNotFound
	}
	if d.ctx == nil {
		// FIXME: Application should know the context before it could submit task. Handle at application level
		logger.Errorw(ctx, "Context is missing. AddFlow Operation Not added to Task", log.Fields{"Device": device})
		return errorCodes.ErrInvalidParamInRequest
	}

	var isMigrationRequired bool
	if flow.MigrateCookie {
		// flow migration to new cookie must be done only during the audit. Migration for all subflows must be done if
		// atlease one subflow with old cookie found in the device.
		for _, subFlow := range flow.SubFlows {
			if isMigrationRequired = d.IsFlowPresentWithOldCookie(subFlow); isMigrationRequired {
				break
			}
		}
	}

	if isMigrationRequired {
		// In this case, the flow is updated in local cache and db here.
		// Actual flow deletion and addition at voltha will happen during flow tables audit.
		for _, subFlow := range flow.SubFlows {
			logger.Debugw(ctx, "Cookie Migration Required", log.Fields{"OldCookie": subFlow.OldCookie, "NewCookie": subFlow.Cookie})
			if err := d.DelFlowWithOldCookie(cntx, subFlow); err != nil {
				logger.Errorw(ctx, "Delete flow with old cookie failed", log.Fields{"Error": err, "OldCookie": subFlow.OldCookie})
			}
			if err := d.AddFlow(cntx, subFlow); err != nil {
				logger.Errorw(ctx, "Flow Add Failed", log.Fields{"Error": err, "Cookie": subFlow.Cookie})
			}
		}
	} else {
		flow.Command = of.CommandAdd
		d.UpdateFlows(flow, devPort)
		for cookie := range flow.SubFlows {
			logger.Debugw(ctx, "Flow Add added to queue", log.Fields{"Cookie": cookie, "Device": device, "Port": port})
		}
	}
	return nil
}

// DelFlows to delete flows
// delFlowsOnlyInDevice flag indicates that flows should be deleted only in DB/device and should not be forwarded to core
func (v *VoltController) DelFlows(cntx context.Context, port string, device string, flow *of.VoltFlow, delFlowsOnlyInDevice bool) error {
	d, err := v.GetDevice(device)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": device})
		return err
	}
	devPort := d.GetPortByName(port)
	if devPort == nil {
		logger.Errorw(ctx, "Port Not Found", log.Fields{"Device": device})
		return errorCodes.ErrPortNotFound
	}
	if d.ctx == nil {
		// FIXME: Application should know the context before it could submit task. Handle at application level
		logger.Errorw(ctx, "Context is missing. DelFlow Operation Not added to Task", log.Fields{"Device": device})
		return errorCodes.ErrInvalidParamInRequest
	}

	var isMigrationRequired bool
	if flow.MigrateCookie {
		// flow migration to new cookie must be done only during the audit. Migration for all subflows must be done if
		// atlease one subflow with old cookie found in the device.
		for _, subFlow := range flow.SubFlows {
			if isMigrationRequired = d.IsFlowPresentWithOldCookie(subFlow); isMigrationRequired {
				break
			}
		}
	}

	if isMigrationRequired {
		// In this case, the flow is deleted from local cache and db here.
		// Actual flow deletion at voltha will happen during flow tables audit.
		for _, subFlow := range flow.SubFlows {
			logger.Debugw(ctx, "Old Cookie delete Required", log.Fields{"OldCookie": subFlow.OldCookie})
			if err := d.DelFlowWithOldCookie(cntx, subFlow); err != nil {
				logger.Errorw(ctx, "DelFlowWithOldCookie failed", log.Fields{"OldCookie": subFlow.OldCookie, "Error": err})
			}
		}
	} else {
		// Delete flows only in DB/device when Port Delete has come. Do not send flows to core during Port Delete
		if delFlowsOnlyInDevice {
			for cookie, subFlow := range flow.SubFlows {
				err := d.DelFlow(ctx, subFlow)
				logger.Debugw(ctx, "Flow Deleted from device/DB", log.Fields{"Cookie": cookie, "Device": device, "Port": port, "Error": err})
			}
		} else {
			flow.Command = of.CommandDel
			d.UpdateFlows(flow, devPort)
			for cookie := range flow.SubFlows {
				logger.Debugw(ctx, "Flow Del added to queue", log.Fields{"Cookie": cookie, "Device": device, "Port": port})
			}
		}
	}
	return nil
}

// GroupUpdate for group update
func (v *VoltController) GroupUpdate(port string, device string, group *of.Group) error {
	d, err := v.GetDevice(device)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": device})
		return err
	}

	devPort := d.GetPortByName(port)
	if devPort == nil {
		logger.Errorw(ctx, "Port Not Found", log.Fields{"Device": device})
		return errorCodes.ErrPortNotFound
	}

	if d.ctx == nil {
		// FIXME: Application should know the context before it could submit task. Handle at application level
		logger.Errorw(ctx, "Context is missing. GroupMod Operation Not added to task", log.Fields{"Device": device})
		return errorCodes.ErrInvalidParamInRequest
	}

	d.UpdateGroup(group, devPort)
	return nil
}

// ModMeter to get mod meter info
func (v *VoltController) ModMeter(port string, device string, command of.MeterCommand, meter *of.Meter) error {
	d, err := v.GetDevice(device)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": device})
		return err
	}

	devPort := d.GetPortByName(port)
	if devPort == nil {
		logger.Errorw(ctx, "Port Not Found", log.Fields{"Device": device})
		return errorCodes.ErrPortNotFound
	}

	d.ModMeter(command, meter, devPort)
	return nil
}

// PortAddInd for port add indication
func (v *VoltController) PortAddInd(cntx context.Context, device string, id uint32, name string) {
	v.app.PortAddInd(cntx, device, id, name)
}

// PortDelInd for port delete indication
func (v *VoltController) PortDelInd(cntx context.Context, device string, port string) {
	v.app.PortDelInd(cntx, device, port)
}

// PortUpdateInd for port update indication
func (v *VoltController) PortUpdateInd(device string, name string, id uint32) {
	v.app.PortUpdateInd(device, name, id)
}

// PortUpInd for port up indication
func (v *VoltController) PortUpInd(cntx context.Context, device string, port string) {
	v.app.PortUpInd(cntx, device, port)
}

// PortDownInd for port down indication
func (v *VoltController) PortDownInd(cntx context.Context, device string, port string) {
	v.app.PortDownInd(cntx, device, port)
}

// DeviceUpInd for device up indication
func (v *VoltController) DeviceUpInd(device string) {
	v.app.DeviceUpInd(device)
}

// DeviceDownInd for device down indication
func (v *VoltController) DeviceDownInd(device string) {
	v.app.DeviceDownInd(device)
}

// PacketInInd for packet in indication
func (v *VoltController) PacketInInd(cntx context.Context, device string, port string, data []byte) {
	v.app.PacketInInd(cntx, device, port, data)
}

// GetPortState to get port status
func (v *VoltController) GetPortState(device string, name string) (PortState, error) {
	d, err := v.GetDevice(device)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": device})
		return PortStateDown, err
	}
	return d.GetPortState(name)
}

// UpdateMvlanProfiles for update mvlan profiles
func (v *VoltController) UpdateMvlanProfiles(cntx context.Context, device string) {
	v.app.UpdateMvlanProfilesForDevice(cntx, device)
}

// GetController to get controller
func GetController() *VoltController {
	return vcontroller
}

/*
// PostIndication to post indication
func (v *VoltController) PostIndication(device string, task interface{}) error {
	var srvTask AddServiceIndTask
	var portTask AddPortIndTask
	var taskCommon tasks.Task
	var isSvcTask bool

	switch data := task.(type) {
	case *AddServiceIndTask:
		srvTask = *data
		taskCommon = data
		isSvcTask = true
	case *AddPortIndTask:
		portTask = *data
		taskCommon = data
	}

	d, err := v.GetDevice(device)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": device})
		//It means device itself it not present so just post the indication directly
		if isSvcTask {
			msgbus.PostAccessConfigInd(srvTask.result, d.SerialNum, srvTask.indicationType, srvTask.serviceName, 0, srvTask.reason, srvTask.trigger, srvTask.portState)
		} else {
			msgbus.ProcessPortInd(portTask.indicationType, d.SerialNum, portTask.portName, portTask.accessConfig, portTask.serviceList)
		}
		return err
	}
	if taskCommon != nil {
		d.AddTask(taskCommon)
	}
	return nil
}
*/

// GetTaskList to get the task list
func (v *VoltController) GetTaskList(device string) []tasks.Task {
	d, err := v.GetDevice(device)
	if err != nil || d.ctx == nil {
		logger.Errorw(ctx, "Device Not Connected/Found", log.Fields{"Device": device, "Dev Obj": d})
		return []tasks.Task{}
	}
	return d.GetTaskList()
}

// AddBlockedDevices to add Devices to blocked Devices list
func (v *VoltController) AddBlockedDevices(deviceSerialNumber string) {
	v.BlockedDeviceList.Set(deviceSerialNumber, deviceSerialNumber)
}

// DelBlockedDevices to remove device from blocked device list
func (v *VoltController) DelBlockedDevices(deviceSerialNumber string) {
	v.BlockedDeviceList.Remove(deviceSerialNumber)
}

// IsBlockedDevice to check if device is blocked
func (v *VoltController) IsBlockedDevice(deviceSerialNumber string) bool {
	_, ifPresent := v.BlockedDeviceList.Get(deviceSerialNumber)
	return ifPresent
}

// GetFlows returns flow specific to device and flowID
func (v *VoltController) GetFlow(deviceID string, cookie uint64) (*of.VoltSubFlow, error) {
	d, err := v.GetDevice(deviceID)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": deviceID, "Error": err})
		return nil, err
	}
	if flow, ok := d.GetFlow(cookie); ok {
		return flow, nil
	}
	return nil, nil
}

// GetFlows returns list of flows for a particular device
func (v *VoltController) GetFlows(deviceID string) ([]*of.VoltSubFlow, error) {
	d, err := v.GetDevice(deviceID)
	if err != nil {
		logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": deviceID, "Error": err})
		return nil, nil
	}
	return d.GetAllFlows(), nil
}

// GetAllFlows returns list of all flows
func (v *VoltController) GetAllFlows() ([]*of.VoltSubFlow, error) {
	var flows []*of.VoltSubFlow
	v.Devices.Range(func(_, value interface{}) bool {
		d, ok := value.(*Device)
		if ok {
			flows = append(flows, d.GetAllFlows()...)
		}
		return true
	})
	return flows, nil
}

// GetAllPendingFlows returns list of all flows
func (v *VoltController) GetAllPendingFlows() ([]*of.VoltSubFlow, error) {
	var flows []*of.VoltSubFlow
	v.Devices.Range(func(_, value interface{}) bool {
		d, ok := value.(*Device)
		if ok {
			flows = append(flows, d.GetAllPendingFlows()...)
		}
		return true
	})
	return flows, nil
}
func (v *VoltController) GetAllMeterInfo() (map[string][]*of.Meter, error) {
	logger.Info(ctx, "Entering into GetAllMeterInfo method")
	meters := map[string][]*of.Meter{}
	v.Devices.Range(func(_, value interface{}) bool {
		device, ok := value.(*Device)
		if ok {
			logger.Debugw(ctx, "Inside GetAllMeterInfo method", log.Fields{"deviceId": device.ID, "southbound": device.SouthBoundID, "serial no": device.SerialNum})
			for _, meter := range device.meters {
				meters[device.ID] = append(meters[device.ID], meter)
			}
			logger.Debugw(ctx, "Inside GetAllMeterInfo method", log.Fields{"meters": meters})
		}
		return true
	})
	return meters, nil
}

func (v *VoltController) GetMeterInfo(cntx context.Context, id uint32) (map[string]*of.Meter, error) {
	logger.Info(ctx, "Entering into GetMeterInfo method")
	meters := map[string]*of.Meter{}
	var errResult error
	v.Devices.Range(func(_, value interface{}) bool {
		device, ok := value.(*Device)
		if ok {
			logger.Debugw(ctx, "Inside GetMeterInfo method", log.Fields{"deviceId": device.ID})
			meter, err := device.GetMeter(id)
			if err != nil {
				logger.Errorw(ctx, "Failed to fetch the meter", log.Fields{"Reason": err.Error()})
				errResult = err
				return false
			}
			meters[device.ID] = meter
			logger.Debugw(ctx, "meters", log.Fields{"Meter": meters})
		}
		return true
	})
	if errResult != nil {
		return nil, errResult
	}
	return meters, nil
}

func (v *VoltController) GetGroupList() ([]*of.Group, error) {
	logger.Info(ctx, "Entering into GetGroupList method")
	groups := []*of.Group{}
	v.Devices.Range(func(_, value interface{}) bool {
		device, ok := value.(*Device)
		if ok {
			device.groups.Range(func(key, value interface{}) bool {
				groupID := key.(uint32)
				logger.Debugw(ctx, "Inside GetGroupList method", log.Fields{"groupID": groupID})
				//Obtain all groups associated with the device
				grps, ok := device.groups.Load(groupID)
				if !ok {
					return true
				}
				grp := grps.(*of.Group)
				groups = append(groups, grp)
				return true
			})
		}
		return true
	})
	logger.Debugw(ctx, "Groups", log.Fields{"groups": groups})
	return groups, nil
}

func (v *VoltController) GetGroups(cntx context.Context, id uint32) (*of.Group, error) {
	logger.Info(ctx, "Entering into GetGroupList method")
	var groups *of.Group
	var err error
	v.Devices.Range(func(_, value interface{}) bool {
		device, ok := value.(*Device)
		if ok {
			logger.Debugw(ctx, "Inside GetGroupList method", log.Fields{"groupID": id})
			grps, ok := device.groups.Load(id)
			if !ok {
				err = errors.New("group not found")
				return false
			}
			groups = grps.(*of.Group)
			logger.Debugw(ctx, "Groups", log.Fields{"groups": groups})
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}
