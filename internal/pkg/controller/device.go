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
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	infraerror "voltha-go-controller/internal/pkg/errorcodes"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/holder"
	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"

	//"voltha-go-controller/internal/pkg/vpagent"
	"voltha-go-controller/internal/pkg/tasks"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"

	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/opencord/voltha-protos/v5/go/voltha"
)

// PortState type
type PortState string

const (
	// PortStateDown constant
	PortStateDown PortState = "DOWN"
	// PortStateUp constant
	PortStateUp PortState = "UP"
	// DefaultMaxFlowQueues constant
	DefaultMaxFlowQueues = 67
	//ErrDuplicateFlow - indicates flow already exists in DB
	ErrDuplicateFlow string = "duplicate flow"
	//Unknown_Port_ID - indicates that the port id is unknown
	Unknown_Port_ID = "unknown port id"
	//Duplicate_Port - indicates the port is already exist in controller
	Duplicate_Port = "duplicate port"
)

// DevicePort structure
type DevicePort struct {
	Name    string
	State   PortState
	Version string
	HwAddr  string
	tasks.Tasks
	CurrSpeed uint32
	MaxSpeed  uint32
	ID        uint32
}

// NewDevicePort is the constructor for DevicePort
func NewDevicePort(mp *ofp.OfpPort) *DevicePort {
	var port DevicePort

	port.ID = mp.PortNo
	port.Name = mp.Name

	//port.HwAddr = strings.Trim(strings.Join(strings.Fields(fmt.Sprint("%02x", mp.HwAddr)), ":"), "[]")
	port.HwAddr = strings.Trim(strings.ReplaceAll(fmt.Sprintf("%02x", mp.HwAddr), " ", ":"), "[]")
	port.CurrSpeed = mp.CurrSpeed
	port.MaxSpeed = mp.MaxSpeed
	port.State = PortStateDown
	return &port
}

// UniIDFlowQueue structure which maintains flows in queue.
type UniIDFlowQueue struct {
	tasks.Tasks
	ID uint32
}

// NewUniIDFlowQueue is the constructor for UniIDFlowQueue.
func NewUniIDFlowQueue(id uint32) *UniIDFlowQueue {
	var flowQueue UniIDFlowQueue
	flowQueue.ID = id
	return &flowQueue
}

// DeviceState type
type DeviceState string

const (

	// DeviceStateUNKNOWN constant
	DeviceStateUNKNOWN DeviceState = "UNKNOWN"
	// DeviceStateINIT constant
	DeviceStateINIT DeviceState = "INIT"
	// DeviceStateUP constant
	DeviceStateUP DeviceState = "UP"
	// DeviceStateDOWN constant
	DeviceStateDOWN DeviceState = "DOWN"
	// DeviceStateREBOOTED constant
	DeviceStateREBOOTED DeviceState = "REBOOTED"
	// DeviceStateDISABLED constant
	DeviceStateDISABLED DeviceState = "DISABLED"
	// DeviceStateDELETED constant
	DeviceStateDELETED DeviceState = "DELETED"
)

type DeviceInterface interface {
	SetFlowHash(cntx context.Context, hash uint32)
}

// Device structure
type Device struct {
	ctx              context.Context
	cancel           context.CancelFunc
	vclientHolder    *holder.VolthaServiceClientHolder
	packetOutChannel chan *ofp.PacketOut
	PortsByName      map[string]*DevicePort
	flows            map[uint64]*of.VoltSubFlow
	PortsByID        map[uint32]*DevicePort
	meters           map[uint32]*of.Meter
	flowQueue        map[uint32]*UniIDFlowQueue // key is hash ID generated and value is UniIDFlowQueue.
	SouthBoundID     string
	MfrDesc          string
	HwDesc           string
	SwDesc           string
	ID               string
	SerialNum        string
	State            DeviceState
	TimeStamp        time.Time
	groups           sync.Map //map[uint32]*of.Group -> [GroupId : Group]
	tasks.Tasks
	portLock              sync.RWMutex
	flowLock              sync.RWMutex
	meterLock             sync.RWMutex
	flowQueueLock         sync.RWMutex
	flowHash              uint32
	auditInProgress       bool
	deviceAuditInProgress bool
}

// NewDevice is the constructor for Device
func NewDevice(cntx context.Context, id string, slno string, vclientHldr *holder.VolthaServiceClientHolder, southBoundID, mfr, hwDesc, swDesc string) *Device {
	var device Device
	device.ID = id
	device.SerialNum = slno
	device.State = DeviceStateDOWN
	device.PortsByID = make(map[uint32]*DevicePort)
	device.PortsByName = make(map[string]*DevicePort)
	device.vclientHolder = vclientHldr
	device.flows = make(map[uint64]*of.VoltSubFlow)
	device.meters = make(map[uint32]*of.Meter)
	device.flowQueue = make(map[uint32]*UniIDFlowQueue)
	// Get the flowhash from db and update the flowhash variable in the device.
	device.SouthBoundID = southBoundID
	device.MfrDesc = mfr
	device.HwDesc = hwDesc
	device.SwDesc = swDesc
	device.TimeStamp = time.Now()
	flowHash, err := db.GetFlowHash(cntx, id)
	if err != nil {
		device.flowHash = DefaultMaxFlowQueues
	} else {
		var hash uint32
		err = json.Unmarshal([]byte(flowHash), &hash)
		if err != nil {
			logger.Errorw(ctx, "Failed to unmarshall flowhash", log.Fields{"data": flowHash})
		} else {
			device.flowHash = hash
		}
	}
	logger.Infow(ctx, "Flow hash for device", log.Fields{"Deviceid": id, "hash": device.flowHash})
	return &device
}

// ResetCache to reset cache
func (d *Device) ResetCache() {
	logger.Warnw(ctx, "Resetting flows, meters and groups cache", log.Fields{"Device": d.ID})
	d.flows = make(map[uint64]*of.VoltSubFlow)
	d.meters = make(map[uint32]*of.Meter)
	d.groups = sync.Map{}
}

// GetFlow - Get the flow from device obj
func (d *Device) GetFlow(cookie uint64) (*of.VoltSubFlow, bool) {
	d.flowLock.RLock()
	defer d.flowLock.RUnlock()
	logger.Debugw(ctx, "Get Flow", log.Fields{"Cookie": cookie})
	flow, ok := d.flows[cookie]
	return flow, ok
}

// GetAllFlows - Get the flow from device obj
func (d *Device) GetAllFlows() []*of.VoltSubFlow {
	d.flowLock.RLock()
	defer d.flowLock.RUnlock()
	var flows []*of.VoltSubFlow
	logger.Debugw(ctx, "Get All Flows", log.Fields{"deviceID": d.ID})
	for _, f := range d.flows {
		flows = append(flows, f)
	}
	return flows
}

// GetAllPendingFlows - Get the flow from device obj
func (d *Device) GetAllPendingFlows() []*of.VoltSubFlow {
	d.flowLock.RLock()
	defer d.flowLock.RUnlock()
	var flows []*of.VoltSubFlow
	logger.Debugw(ctx, "Get All Pending Flows", log.Fields{"deviceID": d.ID})
	for _, f := range d.flows {
		if f.State == of.FlowAddPending {
			flows = append(flows, f)
		}
	}
	return flows
}

// AddFlow - Adds the flow to the device and also to the database
func (d *Device) AddFlow(cntx context.Context, flow *of.VoltSubFlow) error {
	d.flowLock.Lock()
	defer d.flowLock.Unlock()
	logger.Debugw(ctx, "AddFlow to device", log.Fields{"Cookie": flow.Cookie})
	if _, ok := d.flows[flow.Cookie]; ok {
		return errors.New(ErrDuplicateFlow)
	}
	d.flows[flow.Cookie] = flow
	d.AddFlowToDb(cntx, flow)
	return nil
}

// AddFlowToDb is the utility to add the flow to the device
func (d *Device) AddFlowToDb(cntx context.Context, flow *of.VoltSubFlow) {
	if b, err := json.Marshal(flow); err == nil {
		if err = db.PutFlow(cntx, d.ID, flow.Cookie, string(b)); err != nil {
			logger.Errorw(ctx, "Write Flow to DB failed", log.Fields{"device": d.ID, "cookie": flow.Cookie, "Reason": err})
		}
	}
}

// DelFlow - Deletes the flow from the device and the database
func (d *Device) DelFlow(cntx context.Context, flow *of.VoltSubFlow) error {
	d.flowLock.Lock()
	defer d.flowLock.Unlock()
	if _, ok := d.flows[flow.Cookie]; ok {
		delete(d.flows, flow.Cookie)
		d.DelFlowFromDb(cntx, flow.Cookie)
		return nil
	}
	return errors.New("flow does not exist")
}

// DelFlowFromDb is utility to delete the flow from the device
func (d *Device) DelFlowFromDb(cntx context.Context, flowID uint64) {
	_ = db.DelFlow(cntx, d.ID, flowID)
}

// IsFlowPresentWithOldCookie is to check whether there is any flow with old cookie.
func (d *Device) IsFlowPresentWithOldCookie(flow *of.VoltSubFlow) bool {
	d.flowLock.RLock()
	defer d.flowLock.RUnlock()
	if _, ok := d.flows[flow.Cookie]; ok {
		return false
	} else if flow.OldCookie != 0 && flow.Cookie != flow.OldCookie {
		if _, ok := d.flows[flow.OldCookie]; ok {
			logger.Debugw(ctx, "Flow present with old cookie", log.Fields{"OldCookie": flow.OldCookie})
			return true
		}
	}
	return false
}

// DelFlowWithOldCookie is to delete flow with old cookie.
func (d *Device) DelFlowWithOldCookie(cntx context.Context, flow *of.VoltSubFlow) error {
	d.flowLock.Lock()
	defer d.flowLock.Unlock()
	if _, ok := d.flows[flow.OldCookie]; ok {
		logger.Debugw(ctx, "Flow was added before vgc upgrade. Trying to delete with old cookie",
			log.Fields{"OldCookie": flow.OldCookie})
		delete(d.flows, flow.OldCookie)
		d.DelFlowFromDb(cntx, flow.OldCookie)
		return nil
	}
	return errors.New("flow does not exist")
}

// RestoreFlowsFromDb to restore flows from database
func (d *Device) RestoreFlowsFromDb(cntx context.Context) {
	flows, _ := db.GetFlows(cntx, d.ID)
	for _, flow := range flows {
		b, ok := flow.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		d.CreateFlowFromString(b)
	}
}

// CreateFlowFromString to create flow from string
func (d *Device) CreateFlowFromString(b []byte) {
	var flow of.VoltSubFlow
	if err := json.Unmarshal(b, &flow); err == nil {
		if _, ok := d.flows[flow.Cookie]; !ok {
			logger.Debugw(ctx, "Adding Flow From Db", log.Fields{"Cookie": flow.Cookie})
			d.flows[flow.Cookie] = &flow
		} else {
			logger.Warnw(ctx, "Duplicate Flow", log.Fields{"Cookie": flow.Cookie})
		}
	} else {
		logger.Warn(ctx, "Unmarshal failed")
	}
}

// ----------------------------------------------------------
// Database related functionality
// Group operations at the device which include update and delete

// UpdateGroupEntry - Adds/Updates the group to the device and also to the database
func (d *Device) UpdateGroupEntry(cntx context.Context, group *of.Group) {
	logger.Debugw(ctx, "Update Group to device", log.Fields{"ID": group.GroupID})
	d.groups.Store(group.GroupID, group)
	d.AddGroupToDb(cntx, group)
}

// AddGroupToDb - Utility to add the group to the device DB
func (d *Device) AddGroupToDb(cntx context.Context, group *of.Group) {
	if b, err := json.Marshal(group); err == nil {
		logger.Debugw(ctx, "Adding Group to DB", log.Fields{"grp": group, "Json": string(b)})
		if err = db.PutGroup(cntx, d.ID, group.GroupID, string(b)); err != nil {
			logger.Errorw(ctx, "Write Group to DB failed", log.Fields{"device": d.ID, "groupID": group.GroupID, "Reason": err})
		}
	}
}

// DelGroupEntry - Deletes the group from the device and the database
func (d *Device) DelGroupEntry(cntx context.Context, group *of.Group) {
	if _, ok := d.groups.Load(group.GroupID); ok {
		d.groups.Delete(group.GroupID)
		d.DelGroupFromDb(cntx, group.GroupID)
	}
}

// DelGroupFromDb - Utility to delete the Group from the device
func (d *Device) DelGroupFromDb(cntx context.Context, groupID uint32) {
	_ = db.DelGroup(cntx, d.ID, groupID)
}

// RestoreGroupsFromDb - restores all groups from DB
func (d *Device) RestoreGroupsFromDb(cntx context.Context) {
	logger.Info(ctx, "Restoring Groups")
	groups, _ := db.GetGroups(cntx, d.ID)
	for _, group := range groups {
		b, ok := group.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		d.CreateGroupFromString(b)
	}
}

// CreateGroupFromString - Forms group struct from json string
func (d *Device) CreateGroupFromString(b []byte) {
	var group of.Group
	if err := json.Unmarshal(b, &group); err == nil {
		if _, ok := d.groups.Load(group.GroupID); !ok {
			logger.Debugw(ctx, "Adding Group From Db", log.Fields{"GroupId": group.GroupID})
			d.groups.Store(group.GroupID, &group)
		} else {
			logger.Warnw(ctx, "Duplicate Group", log.Fields{"GroupId": group.GroupID})
		}
	} else {
		logger.Warn(ctx, "Unmarshal failed")
	}
}

// AddMeter to add meter
func (d *Device) AddMeter(cntx context.Context, meter *of.Meter) error {
	d.meterLock.Lock()
	defer d.meterLock.Unlock()
	if _, ok := d.meters[meter.ID]; ok {
		return errors.New("duplicate meter")
	}
	d.meters[meter.ID] = meter
	go d.AddMeterToDb(cntx, meter)
	return nil
}

// UpdateMeter to update meter
func (d *Device) UpdateMeter(cntx context.Context, meter *of.Meter) error {
	d.meterLock.Lock()
	defer d.meterLock.Unlock()
	if _, ok := d.meters[meter.ID]; ok {
		d.meters[meter.ID] = meter
		d.AddMeterToDb(cntx, meter)
	} else {
		return errors.New("meter not found for updation")
	}
	return nil
}

// GetMeter to get meter
func (d *Device) GetMeter(id uint32) (*of.Meter, error) {
	d.meterLock.RLock()
	defer d.meterLock.RUnlock()
	if m, ok := d.meters[id]; ok {
		return m, nil
	}
	return nil, errors.New("meter not found")
}

// DelMeter to delete meter
func (d *Device) DelMeter(cntx context.Context, meter *of.Meter) bool {
	d.meterLock.Lock()
	defer d.meterLock.Unlock()
	if _, ok := d.meters[meter.ID]; ok {
		delete(d.meters, meter.ID)
		go d.DelMeterFromDb(cntx, meter.ID)
		return true
	}
	return false
}

// AddMeterToDb is utility to add the Group to the device
func (d *Device) AddMeterToDb(cntx context.Context, meter *of.Meter) {
	if b, err := json.Marshal(meter); err == nil {
		if err = db.PutDeviceMeter(cntx, d.ID, meter.ID, string(b)); err != nil {
			logger.Errorw(ctx, "Write Meter to DB failed", log.Fields{"device": d.ID, "meterID": meter.ID, "Reason": err})
		}
	}
}

// DelMeterFromDb to delete meter from db
func (d *Device) DelMeterFromDb(cntx context.Context, id uint32) {
	_ = db.DelDeviceMeter(cntx, d.ID, id)
}

// RestoreMetersFromDb to restore meters from db
func (d *Device) RestoreMetersFromDb(cntx context.Context) {
	meters, _ := db.GetDeviceMeters(cntx, d.ID)
	for _, meter := range meters {
		b, ok := meter.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		d.CreateMeterFromString(b)
	}
}

// CreateMeterFromString to create meter from string
func (d *Device) CreateMeterFromString(b []byte) {
	var meter of.Meter
	if err := json.Unmarshal(b, &meter); err == nil {
		if _, ok := d.meters[meter.ID]; !ok {
			logger.Debugw(ctx, "Adding Meter From Db", log.Fields{"ID": meter.ID})
			d.meters[meter.ID] = &meter
		} else {
			logger.Warnw(ctx, "Duplicate Meter", log.Fields{"ID": meter.ID})
		}
	} else {
		logger.Warnw(ctx, "Unmarshal failed", log.Fields{"error": err, "meter": string(b)})
	}
}

// VolthaClient to get voltha client
func (d *Device) VolthaClient() voltha.VolthaServiceClient {
	return d.vclientHolder.Get()
}

// AddPort to add the port as requested by the device/VOLTHA
// Inform the application if the port is successfully added
func (d *Device) AddPort(cntx context.Context, mp *ofp.OfpPort) error {
	d.portLock.Lock()
	defer d.portLock.Unlock()
	id := mp.PortNo
	name := mp.Name
	if _, ok := d.PortsByID[id]; ok {
		return errors.New(Duplicate_Port)
	}
	if _, ok := d.PortsByName[name]; ok {
		return errors.New(Duplicate_Port)
	}

	p := NewDevicePort(mp)
	d.PortsByID[id] = p
	d.PortsByName[name] = p
	d.WritePortToDb(cntx, p)
	GetController().PortAddInd(cntx, d.ID, p.ID, p.Name)
	logger.Infow(ctx, "Added Port", log.Fields{"Device": d.ID, "Port": id})
	return nil
}

// DelPort to delete the port as requested by the device/VOLTHA
// Inform the application if the port is successfully deleted
func (d *Device) DelPort(cntx context.Context, id uint32, portName string) error {
	p := d.GetPortByID(id)
	if p == nil {
		p = d.GetPortByName(portName)
		if p == nil {
			return errors.New("unknown port")
		} else {
			logger.Infow(ctx, "Found port by name", log.Fields{"PortName": p.Name, "PortID": p.ID})
		}
	}
	if p.State == PortStateUp {
		GetController().PortDownInd(cntx, d.ID, p.Name)
	}
	GetController().PortDelInd(cntx, d.ID, p.Name)

	d.portLock.Lock()
	defer d.portLock.Unlock()

	delete(d.PortsByID, p.ID)
	delete(d.PortsByName, p.Name)
	d.DelPortFromDb(cntx, p.ID)
	logger.Infow(ctx, "Deleted Port", log.Fields{"Device": d.ID, "Port": id})
	return nil
}

// UpdatePortByName is utility to update the port by Name
func (d *Device) UpdatePortByName(cntx context.Context, name string, port uint32) {
	d.portLock.Lock()
	defer d.portLock.Unlock()

	p, ok := d.PortsByName[name]
	if !ok {
		return
	}
	delete(d.PortsByID, p.ID)
	p.ID = port
	d.PortsByID[port] = p
	d.WritePortToDb(cntx, p)
	GetController().PortUpdateInd(d.ID, p.Name, p.ID)
	logger.Infow(ctx, "Updated Port", log.Fields{"Device": d.ID, "Port": p.ID, "PortName": name})
}

// GetPortName to get the name of the port by its id
func (d *Device) GetPortName(id uint32) (string, error) {
	d.portLock.RLock()
	defer d.portLock.RUnlock()

	if p, ok := d.PortsByID[id]; ok {
		return p.Name, nil
	}
	logger.Errorw(ctx, "Port not found", log.Fields{"port": id})
	return "", errors.New(Unknown_Port_ID)
}

// GetPortByID is utility to retrieve the port by ID
func (d *Device) GetPortByID(id uint32) *DevicePort {
	d.portLock.RLock()
	defer d.portLock.RUnlock()

	p, ok := d.PortsByID[id]
	if ok {
		return p
	}
	return nil
}

// GetPortByName is utility to retrieve the port by Name
func (d *Device) GetPortByName(name string) *DevicePort {
	d.portLock.RLock()
	defer d.portLock.RUnlock()

	p, ok := d.PortsByName[name]
	if ok {
		return p
	}
	return nil
}

// GetPortState to get the state of the port by name
func (d *Device) GetPortState(name string) (PortState, error) {
	d.portLock.RLock()
	defer d.portLock.RUnlock()

	if p, ok := d.PortsByName[name]; ok {
		return p.State, nil
	}
	return PortStateDown, errors.New(Unknown_Port_ID)
}

// GetPortID to get the port-id by the port name
func (d *Device) GetPortID(name string) (uint32, error) {
	d.portLock.RLock()
	defer d.portLock.RUnlock()

	if p, ok := d.PortsByName[name]; ok {
		return p.ID, nil
	}
	return 0, errors.New(Unknown_Port_ID)
}

// WritePortToDb to add the port to the database
func (d *Device) WritePortToDb(ctx context.Context, port *DevicePort) {
	port.Version = database.PresentVersionMap[database.DevicePortPath]
	if b, err := json.Marshal(port); err == nil {
		if err = db.PutPort(ctx, d.ID, port.ID, string(b)); err != nil {
			logger.Errorw(ctx, "Write port to DB failed", log.Fields{"device": d.ID, "port": port.ID, "Reason": err})
		}
	}
}

// DelPortFromDb to delete port from database
func (d *Device) DelPortFromDb(cntx context.Context, id uint32) {
	_ = db.DelPort(cntx, d.ID, id)
}

// RestorePortsFromDb to restore ports from database
func (d *Device) RestorePortsFromDb(cntx context.Context) {
	ports, _ := db.GetPorts(cntx, d.ID)
	for _, port := range ports {
		b, ok := port.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		d.CreatePortFromString(cntx, b)
	}
}

// CreatePortFromString to create port from string
func (d *Device) CreatePortFromString(cntx context.Context, b []byte) {
	var port DevicePort
	if err := json.Unmarshal(b, &port); err == nil {
		if _, ok := d.PortsByID[port.ID]; !ok {
			logger.Debugw(ctx, "Adding Port From Db", log.Fields{"ID": port.ID})
			d.PortsByID[port.ID] = &port
			d.PortsByName[port.Name] = &port
			GetController().PortAddInd(cntx, d.ID, port.ID, port.Name)
		} else {
			logger.Warnw(ctx, Duplicate_Port, log.Fields{"ID": port.ID})
		}
	} else {
		logger.Warnw(ctx, "Unmarshal failed", log.Fields{"port": string(b)})
	}
}

// Delete : OLT Delete functionality yet to be implemented. IDeally all of the
// resources should have been removed by this time. It is an error
// scenario if the OLT has resources associated with it.
func (d *Device) Delete() {
	d.StopAll()
}

// Stop to stop the task
func (d *Device) Stop() {
}

// ConnectInd is called when the connection between VGC and the VOLTHA is
// restored. This will perform audit of the device post reconnection
func (d *Device) ConnectInd(ctx context.Context, discType intf.DiscoveryType) {
	logger.Warnw(ctx, "Audit Upon Connection Establishment", log.Fields{"Device": d.ID, "State": d.State})
	ctx1, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.ctx = ctx1
	d.Tasks.Initialize(ctx1)

	logger.Debugw(ctx, "Device State change Ind: UP", log.Fields{"Device": d.ID})
	d.State = DeviceStateUP
	d.TimeStamp = time.Now()
	GetController().DeviceUpInd(d.ID)

	logger.Debugw(ctx, "Device State change Ind: UP, trigger Audit Tasks", log.Fields{"Device": d.ID})
	t := NewAuditDevice(d, AuditEventDeviceDisc)
	d.Tasks.AddTask(t)

	t1 := NewAuditTablesTask(d)
	d.Tasks.AddTask(t1)

	t2 := NewPendingProfilesTask(d)
	d.Tasks.AddTask(t2)

	go d.synchronizeDeviceTables()
}

func (d *Device) synchronizeDeviceTables() {
	tick := time.NewTicker(GetController().GetDeviceTableSyncDuration())
loop:
	for {
		select {
		case <-d.ctx.Done():
			logger.Warnw(d.ctx, "Context Done. Canceling Periodic Audit", log.Fields{"Context": ctx, "Device": d.ID, "DeviceSerialNum": d.SerialNum})
			break loop
		case <-tick.C:
			t1 := NewAuditTablesTask(d)
			d.Tasks.AddTask(t1)
		}
	}
	tick.Stop()
}

// DeviceUpInd is called when the logical device state changes to UP. This will perform audit of the device post reconnection
func (d *Device) DeviceUpInd() {
	logger.Warnw(ctx, "Device State change Ind: UP", log.Fields{"Device": d.ID})
	d.State = DeviceStateUP
	d.TimeStamp = time.Now()
	GetController().DeviceUpInd(d.ID)

	logger.Warnw(ctx, "Device State change Ind: UP, trigger Audit Tasks", log.Fields{"Device": d.ID})
	t := NewAuditDevice(d, AuditEventDeviceDisc)
	d.Tasks.AddTask(t)

	t1 := NewAuditTablesTask(d)
	d.Tasks.AddTask(t1)

	t2 := NewPendingProfilesTask(d)
	d.Tasks.AddTask(t2)
}

// DeviceDownInd is called when the logical device state changes to Down.
func (d *Device) DeviceDownInd() {
	logger.Warnw(ctx, "Device State change Ind: Down", log.Fields{"Device": d.ID})
	d.State = DeviceStateDOWN
	d.TimeStamp = time.Now()
	GetController().DeviceDownInd(d.ID)
}

// DeviceRebootInd is called when the logical device is rebooted.
func (d *Device) DeviceRebootInd(cntx context.Context) {
	logger.Warnw(ctx, "Device State change Ind: Rebooted", log.Fields{"Device": d.ID})

	if d.State == DeviceStateREBOOTED {
		d.State = DeviceStateREBOOTED
		logger.Warnw(ctx, "Ignoring Device State change Ind: REBOOT, Device Already in REBOOT state", log.Fields{"Device": d.ID, "SeralNo": d.SerialNum})
		return
	}

	d.State = DeviceStateREBOOTED
	d.TimeStamp = time.Now()
	GetController().SetRebootInProgressForDevice(d.ID)
	GetController().DeviceRebootInd(cntx, d.ID, d.SerialNum, d.SouthBoundID)
	d.ReSetAllPortStates(cntx)
}

// DeviceDisabledInd is called when the logical device is disabled
func (d *Device) DeviceDisabledInd(cntx context.Context) {
	logger.Warnw(ctx, "Device State change Ind: Disabled", log.Fields{"Device": d.ID})
	d.State = DeviceStateDISABLED
	d.TimeStamp = time.Now()
	GetController().DeviceDisableInd(cntx, d.ID)
}

// ReSetAllPortStates - Set all logical device port status to DOWN
func (d *Device) ReSetAllPortStates(cntx context.Context) {
	logger.Warnw(ctx, "Resetting all Ports State to DOWN", log.Fields{"Device": d.ID, "State": d.State})

	d.portLock.Lock()
	defer d.portLock.Unlock()

	for _, port := range d.PortsByID {
		if port.State != PortStateDown {
			logger.Infow(ctx, "Resetting Port State to DOWN", log.Fields{"Device": d.ID, "Port": port})
			GetController().PortDownInd(cntx, d.ID, port.Name)
			port.State = PortStateDown
			d.WritePortToDb(cntx, port)
		}
	}
}

// ReSetAllPortStatesInDb - Set all logical device port status to DOWN in DB and skip indication to application
func (d *Device) ReSetAllPortStatesInDb(cntx context.Context) {
	logger.Warnw(ctx, "Resetting all Ports State to DOWN In DB", log.Fields{"Device": d.ID, "State": d.State})

	d.portLock.Lock()
	defer d.portLock.Unlock()

	for _, port := range d.PortsByID {
		if port.State != PortStateDown {
			logger.Debugw(ctx, "Resetting Port State to DOWN and Write to DB", log.Fields{"Device": d.ID, "Port": port})
			port.State = PortStateDown
			d.WritePortToDb(cntx, port)
		}
	}
}

// ProcessPortUpdate deals with the change in port id (ONU movement) and taking action
// to update only when the port state is DOWN
func (d *Device) ProcessPortUpdate(cntx context.Context, portName string, port uint32, state uint32) {
	if p := d.GetPortByName(portName); p != nil {
		if p.ID != port {
			logger.Infow(ctx, "Port ID update indication", log.Fields{"Port": p.Name, "Old PortID": p.ID, "New Port ID": port})
			if p.State != PortStateDown {
				logger.Errorw(ctx, "Port ID update failed. Port State UP", log.Fields{"Port": p})
				return
			}
			d.UpdatePortByName(cntx, portName, port)
			logger.Errorw(ctx, "Port ID Updated", log.Fields{"Port": p})
		}
		d.ProcessPortState(cntx, port, state)
	}
}

// ***Operations Performed on Port state Transitions***
//
// |-----------------------------------------------------------------------------|
// |  State             |   Action                                               |
// |--------------------|--------------------------------------------------------|
// | UP                 | UNI - Trigger Flow addition for service configured     |
// |                    | NNI - Trigger Flow addition for vnets & mvlan profiles |
// |                    |                                                        |
// | DOWN               | UNI - Trigger Flow deletion for service configured     |
// |                    | NNI - Trigger Flow deletion for vnets & mvlan profiles |
// |                    |                                                        |
// |-----------------------------------------------------------------------------|
//

// ProcessPortState deals with the change in port status and taking action
// based on the new state and the old state
func (d *Device) ProcessPortState(cntx context.Context, port uint32, state uint32) {
	if d.State != DeviceStateUP && !util.IsNniPort(port) {
		logger.Warnw(ctx, "Ignore Port State Processing - Device not UP", log.Fields{"Device": d.ID, "Port": port, "DeviceState": d.State})
		return
	}
	if p := d.GetPortByID(port); p != nil {
		logger.Infow(ctx, "Port State Processing", log.Fields{"Received": state, "Current": p.State})

		// Avoid blind initialization as the current tasks in the queue will be lost
		// Eg: Service Del followed by Port Down - The flows will be dangling
		// Eg: NNI Down followed by NNI UP - Mcast data flows will be dangling
		p.Tasks.CheckAndInitialize(d.ctx)
		if state == uint32(ofp.OfpPortState_OFPPS_LIVE) && p.State == PortStateDown {
			// Transition from DOWN to UP
			logger.Infow(ctx, "Port State Change to UP", log.Fields{"Device": d.ID, "Port": port})
			GetController().PortUpInd(cntx, d.ID, p.Name)
			p.State = PortStateUp
			d.WritePortToDb(cntx, p)
		} else if (state != uint32(ofp.OfpPortState_OFPPS_LIVE)) && (p.State != PortStateDown) {
			// Transition from UP to Down
			logger.Infow(ctx, "Port State Change to Down", log.Fields{"Device": d.ID, "Port": port})
			GetController().PortDownInd(cntx, d.ID, p.Name)
			p.State = PortStateDown
			d.WritePortToDb(cntx, p)
		} else {
			logger.Warnw(ctx, "Dropping Port Ind: No Change in Port State", log.Fields{"PortName": p.Name, "ID": port, "Device": d.ID, "PortState": p.State, "IncomingState": state})
		}
	}
}

// ProcessPortStateAfterReboot - triggers the port state indication to sort out configu mismatch due to reboot
func (d *Device) ProcessPortStateAfterReboot(cntx context.Context, port uint32, state uint32) {
	if d.State != DeviceStateUP && !util.IsNniPort(port) {
		logger.Warnw(ctx, "Ignore Port State Processing - Device not UP", log.Fields{"Device": d.ID, "Port": port, "DeviceState": d.State})
		return
	}
	if p := d.GetPortByID(port); p != nil {
		logger.Infow(ctx, "Port State Processing after Reboot", log.Fields{"Received": state, "Current": p.State})
		p.Tasks.Initialize(d.ctx)
		if p.State == PortStateUp {
			logger.Infow(ctx, "Port State: UP", log.Fields{"Device": d.ID, "Port": port})
			GetController().PortUpInd(cntx, d.ID, p.Name)
		} else if p.State == PortStateDown {
			logger.Infow(ctx, "Port State: Down", log.Fields{"Device": d.ID, "Port": port})
			GetController().PortDownInd(cntx, d.ID, p.Name)
		}
	}
}

// ChangeEvent : Change event brings in ports related changes such as addition/deletion
// or modification where the port status change up/down is indicated to the
// controller
func (d *Device) ChangeEvent(event *ofp.ChangeEvent) error {
	cet := NewChangeEventTask(d.ctx, event, d)
	d.AddTask(cet)
	return nil
}

// PacketIn handle the incoming packet-in and deliver to the application for the
// actual processing
func (d *Device) PacketIn(cntx context.Context, pkt *ofp.PacketIn) {
	logger.Debugw(ctx, "Received a Packet-In", log.Fields{"Device": d.ID})
	if pkt.PacketIn.Reason != ofp.OfpPacketInReason_OFPR_ACTION {
		logger.Warnw(ctx, "Unsupported PacketIn Reason", log.Fields{"Reason": pkt.PacketIn.Reason})
		return
	}
	data := pkt.PacketIn.Data
	port := PacketInGetPort(pkt.PacketIn)
	if pName, err := d.GetPortName(port); err == nil {
		GetController().PacketInInd(cntx, d.ID, pName, data)
	} else {
		logger.Warnw(ctx, "Unknown Port", log.Fields{"Reason": err.Error()})
	}
}

// PacketInGetPort to get the port on which the packet-in is reported
func PacketInGetPort(pkt *ofp.OfpPacketIn) uint32 {
	for _, field := range pkt.Match.OxmFields {
		if field.OxmClass == ofp.OfpOxmClass_OFPXMC_OPENFLOW_BASIC {
			if ofbField, ok := field.Field.(*ofp.OfpOxmField_OfbField); ok {
				if ofbField.OfbField.Type == ofp.OxmOfbFieldTypes_OFPXMT_OFB_IN_PORT {
					if port, ok := ofbField.OfbField.Value.(*ofp.OfpOxmOfbField_Port); ok {
						return port.Port
					}
				}
			}
		}
	}
	return 0
}

// PacketOutReq receives the packet out request from the application via the
// controller. The interface from the application uses name as the identity.
func (d *Device) PacketOutReq(outport string, inport string, data []byte, isCustomPkt bool) error {
	inp, err := d.GetPortID(inport)
	if err != nil {
		return errors.New("unknown inport")
	}
	outp, err1 := d.GetPortID(outport)
	if err1 != nil {
		return errors.New("unknown outport")
	}
	logger.Debugw(ctx, "Sending packet out", log.Fields{"Device": d.ID, "Inport": inport, "Outport": outport})
	return d.SendPacketOut(outp, inp, data, isCustomPkt)
}

// SendPacketOut is responsible for building the OF structure and send the
// packet-out to the VOLTHA
func (d *Device) SendPacketOut(outport uint32, inport uint32, data []byte, isCustomPkt bool) error {
	pout := &ofp.PacketOut{}
	pout.Id = d.ID
	opout := &ofp.OfpPacketOut{}
	pout.PacketOut = opout
	opout.InPort = inport
	opout.Data = data
	opout.Actions = []*ofp.OfpAction{
		{
			Type: ofp.OfpActionType_OFPAT_OUTPUT,
			Action: &ofp.OfpAction_Output{
				Output: &ofp.OfpActionOutput{
					Port:   outport,
					MaxLen: 65535,
				},
			},
		},
	}
	d.packetOutChannel <- pout
	return nil
}

// UpdateFlows receives the flows in the form that is implemented
// in the VGC and transforms them to the OF format. This is handled
// as a port of the task that is enqueued to do the same.
func (d *Device) UpdateFlows(flow *of.VoltFlow, devPort *DevicePort) {
	t := NewAddFlowsTask(d.ctx, flow, d)
	logger.Debugw(ctx, "Port Context", log.Fields{"Ctx": devPort.GetContext()})
	// check if port isNni , if yes flows will be added to device port queues.
	if util.IsNniPort(devPort.ID) {
		// Adding the flows to device port queues.
		devPort.AddTask(t)
		return
	}
	// If the flowHash is enabled then add the flows to the flowhash generated queues.
	flowQueue := d.getAndAddFlowQueueForUniID(uint32(devPort.ID))
	if flowQueue != nil {
		logger.Debugw(ctx, "flowHashQId", log.Fields{"uniid": devPort.ID, "flowhash": flowQueue.ID})
		flowQueue.AddTask(t)
		logger.Debugw(ctx, "Tasks Info", log.Fields{"uniid": devPort.ID, "flowhash": flowQueue.ID, "Total": flowQueue.TotalTasks(), "Pending": flowQueue.NumPendingTasks()})
	} else {
		//FlowThrotling disabled, add to the device port queue
		devPort.AddTask(t)
		return
	}
}

// UpdateGroup to update group info
func (d *Device) UpdateGroup(group *of.Group, devPort *DevicePort) {
	task := NewModGroupTask(d.ctx, group, d)
	logger.Debugw(ctx, "NNI Port Context", log.Fields{"Ctx": devPort.GetContext()})
	devPort.AddTask(task)
}

// ModMeter for mod meter task
func (d *Device) ModMeter(command of.MeterCommand, meter *of.Meter, devPort *DevicePort) {
	if command == of.MeterCommandAdd {
		if _, err := d.GetMeter(meter.ID); err == nil {
			logger.Debugw(ctx, "Meter already added", log.Fields{"ID": meter.ID})
			return
		}
	}
	t := NewModMeterTask(d.ctx, command, meter, d)
	devPort.AddTask(t)
}

func (d *Device) getAndAddFlowQueueForUniID(id uint32) *UniIDFlowQueue {
	d.flowQueueLock.RLock()
	// If flowhash is 0 that means flowhash throttling is disabled, return nil
	if d.flowHash == 0 {
		d.flowQueueLock.RUnlock()
		return nil
	}
	flowHashID := id % uint32(d.flowHash)
	if value, found := d.flowQueue[uint32(flowHashID)]; found {
		d.flowQueueLock.RUnlock()
		return value
	}
	d.flowQueueLock.RUnlock()
	logger.Debugw(ctx, "Flow queue not found creating one", log.Fields{"uniid": id, "hash": flowHashID})

	return d.addFlowQueueForUniID(id)
}

func (d *Device) addFlowQueueForUniID(id uint32) *UniIDFlowQueue {
	d.flowQueueLock.Lock()
	defer d.flowQueueLock.Unlock()
	flowHashID := id % uint32(d.flowHash)
	flowQueue := NewUniIDFlowQueue(uint32(flowHashID))
	flowQueue.Tasks.Initialize(d.ctx)
	d.flowQueue[flowHashID] = flowQueue
	return flowQueue
}

// SetFlowHash sets the device flow hash and writes to the DB.
func (d *Device) SetFlowHash(cntx context.Context, hash uint32) {
	d.flowQueueLock.Lock()
	defer d.flowQueueLock.Unlock()

	d.flowHash = hash
	d.writeFlowHashToDB(cntx)
}

func (d *Device) writeFlowHashToDB(cntx context.Context) {
	hash, err := json.Marshal(d.flowHash)
	if err != nil {
		logger.Errorw(ctx, "failed to marshal flow hash", log.Fields{"hash": d.flowHash, "error": err})
		return
	}
	if err := db.PutFlowHash(cntx, d.ID, string(hash)); err != nil {
		logger.Errorw(ctx, "Failed to add flow hash to DB", log.Fields{"device": d.ID, "hash": d.flowHash, "error": err})
	}
}

// isSBOperAllowed - determines if the SB operation is allowed based on device state & force flag
func (d *Device) isSBOperAllowed(forceAction bool) bool {
	if d.State == DeviceStateUP {
		return true
	}

	if d.State == DeviceStateDISABLED && forceAction {
		return true
	}

	return false
}

func (d *Device) triggerFlowNotification(cntx context.Context, cookie uint64, oper of.Command, bwDetails of.BwAvailDetails, err error) {
	flow, _ := d.GetFlow(cookie)
	d.triggerFlowResultNotification(cntx, cookie, flow, oper, bwDetails, err)
}

func (d *Device) triggerFlowResultNotification(cntx context.Context, cookie uint64, flow *of.VoltSubFlow, oper of.Command, bwDetails of.BwAvailDetails, err error) {
	statusCode, statusMsg := infraerror.GetErrorInfo(err)
	success := isFlowOperSuccess(statusCode, oper)

	updateFlow := func(cookie uint64, state int, reason string) {
		if dbFlow, ok := d.GetFlow(cookie); ok {
			dbFlow.State = uint8(state)
			dbFlow.ErrorReason = reason
			d.AddFlowToDb(cntx, dbFlow)
		}
	}

	// Update flow results
	// Add - Update Success or Failure status with reason
	// Del - Delete entry from DB on success else update error reason
	if oper == of.CommandAdd {
		state := of.FlowAddSuccess
		reason := ""
		if !success {
			state = of.FlowAddFailure
			reason = statusMsg
		}
		updateFlow(cookie, state, reason)
		logger.Debugw(ctx, "Updated Flow to DB", log.Fields{"Cookie": cookie, "State": state})
	} else {
		if success && flow != nil {
			if err := d.DelFlow(cntx, flow); err != nil {
				logger.Warnw(ctx, "Delete Flow Error", log.Fields{"Cookie": flow.Cookie, "Reason": err.Error()})
			}
		} else if !success {
			updateFlow(cookie, of.FlowDelFailure, statusMsg)
		}
	}

	flowResult := intf.FlowStatus{
		Cookie:         strconv.FormatUint(cookie, 10),
		Device:         d.ID,
		FlowModType:    oper,
		Flow:           flow,
		Status:         statusCode,
		Reason:         statusMsg,
		AdditionalData: bwDetails,
	}

	logger.Debugw(ctx, "Sending Flow Notification", log.Fields{"Cookie": cookie, "Error Code": statusCode, "FlowOp": oper})
	GetController().ProcessFlowModResultIndication(cntx, flowResult)
}
