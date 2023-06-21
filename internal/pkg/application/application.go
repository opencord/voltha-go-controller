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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/controller"
	cntlr "voltha-go-controller/internal/pkg/controller"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/tasks"
	"voltha-go-controller/internal/pkg/util"
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

const (
	// TODO - Need to identify a right place for this

	// PriorityNone constant.
	PriorityNone uint8 = 8
	// AnyVlan constant.
	AnyVlan uint16 = 0xFFFF
)

// List of Mac Learning Type
const (
	MacLearningNone MacLearningType = iota
	Learn
	ReLearn
)

// MacLearningType represents Mac Learning Type
type MacLearningType int

var (
	tickCount         uint16
	vgcRebooted       bool
	isUpgradeComplete bool
)

var db database.DBIntf

// PacketHandlers : packet handler for different protocols
var PacketHandlers map[string]CallBack

// CallBack : registered call back function for different protocol packets
type CallBack func(cntx context.Context, device string, port string, pkt gopacket.Packet)

const (
	// ARP packet
	ARP string = "ARP"
	// DHCPv4 packet
	DHCPv4 string = "DHCPv4"
	// DHCPv6 packet
	DHCPv6 string = "DHCPv6"
	// IGMP packet
	IGMP string = "IGMP"
	// PPPOE packet
	PPPOE string = "PPPOE"
	// US packet side
	US string = "US"
	// DS packet side
	DS string = "DS"
	// NNI port name
	NNI string = "nni"
)

// RegisterPacketHandler : API to register callback function for every protocol
func RegisterPacketHandler(protocol string, callback CallBack) {
	if PacketHandlers == nil {
		PacketHandlers = make(map[string]CallBack)
	}
	PacketHandlers[protocol] = callback
}

// ---------------------------------------------------------------------
// VOLT Ports
// ---------------------------------------------------------------------
// VOLT Ports are ports associated with VOLT devices. Each port is classified into
// Access/NNI. Each port is identified by Name (Identity known to the NB) and
// Id (Identity used on the SB). Both identities are presented when a port is
// discovered in the SB.

// VoltPortType type for Port Type
type VoltPortType uint8

const (
	// VoltPortTypeAccess constant.
	VoltPortTypeAccess VoltPortType = 0
	// VoltPortTypeNni constant.
	VoltPortTypeNni VoltPortType = 1
)

// PortState type for Port State.
type PortState uint8

const (
	// PortStateDown constant.
	PortStateDown PortState = 0
	// PortStateUp constant.
	PortStateUp PortState = 1
)

// VoltPort structure that is used to store the ports. The name is the
// the main identity used by the application. The SB and NB both present name
// as the identity. The SB is abstracted by VPAgent and the VPAgent transacts
// using name as identity
type VoltPort struct {
	Name                     string
	Device                   string
	PonPort                  uint32
	ActiveChannels           uint32
	ID                       uint32
	Type                     VoltPortType
	State                    PortState
	ChannelPerSubAlarmRaised bool
}

// NewVoltPort : Constructor for the port.
func NewVoltPort(device string, name string, id uint32) *VoltPort {
	var vp VoltPort
	vp.Device = device
	vp.Name = name
	vp.ID = id
	if util.IsNniPort(id) {
		vp.Type = VoltPortTypeNni
	} else {
		vp.PonPort = GetPonPortIDFromUNIPort(id)
	}
	vp.State = PortStateDown
	vp.ChannelPerSubAlarmRaised = false
	return &vp
}

// SetPortID : The ID is used when constructing flows as the flows require ID.
func (vp *VoltPort) SetPortID(id uint32) {
	vp.ID = id
	if util.IsNniPort(id) {
		vp.Type = VoltPortTypeNni
	}
}

// ---------------------------------------------------------------------
// VOLT Device
// ---------------------------------------------------------------------
//
// VoltDevice is an OLT which contains ports of type access and NNI. Each OLT
// can only have one NNI port in the current release. The NNI port always uses
// identity 65536 and all the access ports use identities less than 65535. The
// identification of NNI is done by comparing the port identity with 65535

// VoltDevice fields :
// Name:         This is the name presented by the device/VOLTHA. This doesn't
// have any relation to the physical device
// SerialNum:    This is the serial number of the device and can be used to
// correlate the devices
// NniPort:      The identity of the NNI port
// Ports:        List of all ports added to the device
type VoltDevice struct {
	FlowAddEventMap              *util.ConcurrentMap //map[string]*FlowEvent
	FlowDelEventMap              *util.ConcurrentMap //map[string]*FlowEvent
	MigratingServices            *util.ConcurrentMap //<vnetID,<RequestID, MigrateServicesRequest>>
	VpvsBySvlan                  *util.ConcurrentMap // map[svlan]map[vnet_port]*VoltPortVnet
	ConfiguredVlanForDeviceFlows *util.ConcurrentMap //map[string]map[string]bool
	IgmpDsFlowAppliedForMvlan    map[uint16]bool
	State                        controller.DeviceState
	SouthBoundID                 string
	NniPort                      string
	Name                         string
	SerialNum                    string
	Ports                        sync.Map
	VlanPortStatus               sync.Map
	ActiveChannelsPerPon         sync.Map   // [PonPortID]*PonPortCfg
	PonPortList                  sync.Map   // [PonPortID]map[string]string
	ActiveChannelCountLock       sync.Mutex // This lock is used to update ActiveIGMPChannels
	NniDhcpTrapVid               of.VlanType
	GlobalDhcpFlowAdded          bool
	icmpv6GroupAdded             bool
}

// NewVoltDevice : Constructor for the device
func NewVoltDevice(name string, slno, southBoundID string) *VoltDevice {
	var d VoltDevice
	d.Name = name
	d.SouthBoundID = southBoundID
	d.State = controller.DeviceStateDOWN
	d.NniPort = ""
	d.SouthBoundID = southBoundID
	d.SerialNum = slno
	d.icmpv6GroupAdded = false
	d.IgmpDsFlowAppliedForMvlan = make(map[uint16]bool)
	d.ConfiguredVlanForDeviceFlows = util.NewConcurrentMap()
	d.MigratingServices = util.NewConcurrentMap()
	d.VpvsBySvlan = util.NewConcurrentMap()
	d.FlowAddEventMap = util.NewConcurrentMap()
	d.FlowDelEventMap = util.NewConcurrentMap()
	d.GlobalDhcpFlowAdded = false
	if config, ok := GetApplication().DevicesConfig.Load(slno); ok {
		//Update nni dhcp vid
		deviceConfig := config.(*DeviceConfig)
		d.NniDhcpTrapVid = of.VlanType(deviceConfig.NniDhcpTrapVid)
	}
	return &d
}

// GetAssociatedVpvsForDevice - return the associated VPVs for given device & svlan
func (va *VoltApplication) GetAssociatedVpvsForDevice(device string, svlan of.VlanType) *util.ConcurrentMap {
	if d := va.GetDevice(device); d != nil {
		return d.GetAssociatedVpvs(svlan)
	}
	return nil
}

// AssociateVpvsToDevice - updates the associated VPVs for given device & svlan
func (va *VoltApplication) AssociateVpvsToDevice(device string, vpv *VoltPortVnet) {
	if d := va.GetDevice(device); d != nil {
		vpvMap := d.GetAssociatedVpvs(vpv.SVlan)
		vpvMap.Set(vpv, true)
		d.VpvsBySvlan.Set(vpv.SVlan, vpvMap)
		logger.Infow(ctx, "VPVMap: SET", log.Fields{"Map": vpvMap.Length()})
		return
	}
	logger.Errorw(ctx, "Set VPVMap failed: Device Not Found", log.Fields{"Svlan": vpv.SVlan, "Device": device})
}

// DisassociateVpvsFromDevice - disassociated VPVs from given device & svlan
func (va *VoltApplication) DisassociateVpvsFromDevice(device string, vpv *VoltPortVnet) {
	if d := va.GetDevice(device); d != nil {
		vpvMap := d.GetAssociatedVpvs(vpv.SVlan)
		vpvMap.Remove(vpv)
		d.VpvsBySvlan.Set(vpv.SVlan, vpvMap)
		logger.Infow(ctx, "VPVMap: Remove", log.Fields{"Map": vpvMap.Length()})
		return
	}
	logger.Errorw(ctx, "Remove VPVMap failed: Device Not Found", log.Fields{"Svlan": vpv.SVlan, "Device": device})
}

// GetAssociatedVpvs - returns the associated VPVs for the given Svlan
func (d *VoltDevice) GetAssociatedVpvs(svlan of.VlanType) *util.ConcurrentMap {
	var vpvMap *util.ConcurrentMap
	var mapIntf interface{}
	var ok bool

	if mapIntf, ok = d.VpvsBySvlan.Get(svlan); ok {
		vpvMap = mapIntf.(*util.ConcurrentMap)
	} else {
		vpvMap = util.NewConcurrentMap()
	}
	logger.Infow(ctx, "VPVMap: GET", log.Fields{"Map": vpvMap.Length()})
	return vpvMap
}

// AddPort add port to the device.
func (d *VoltDevice) AddPort(port string, id uint32) *VoltPort {
	addPonPortFromUniPort := func(vPort *VoltPort) {
		if vPort.Type == VoltPortTypeAccess {
			ponPortID := GetPonPortIDFromUNIPort(vPort.ID)

			if ponPortUniList, ok := d.PonPortList.Load(ponPortID); !ok {
				uniList := make(map[string]uint32)
				uniList[port] = vPort.ID
				d.PonPortList.Store(ponPortID, uniList)
			} else {
				ponPortUniList.(map[string]uint32)[port] = vPort.ID
				d.PonPortList.Store(ponPortID, ponPortUniList)
			}
		}
	}
	va := GetApplication()
	if pIntf, ok := d.Ports.Load(port); ok {
		voltPort := pIntf.(*VoltPort)
		addPonPortFromUniPort(voltPort)
		va.AggActiveChannelsCountPerSub(d.Name, port, voltPort)
		d.Ports.Store(port, voltPort)
		return voltPort
	}
	p := NewVoltPort(d.Name, port, id)
	va.AggActiveChannelsCountPerSub(d.Name, port, p)
	d.Ports.Store(port, p)
	if util.IsNniPort(id) {
		d.NniPort = port
	}
	addPonPortFromUniPort(p)
	return p
}

// GetPort to get port information from the device.
func (d *VoltDevice) GetPort(port string) *VoltPort {
	if pIntf, ok := d.Ports.Load(port); ok {
		return pIntf.(*VoltPort)
	}
	return nil
}

// GetPortByPortID to get port information from the device.
func (d *VoltDevice) GetPortNameFromPortID(portID uint32) string {
	portName := ""
	d.Ports.Range(func(key, value interface{}) bool {
		vp := value.(*VoltPort)
		if vp.ID == portID {
			portName = vp.Name
		}
		return true
	})
	return portName
}

// DelPort to delete port from the device
func (d *VoltDevice) DelPort(port string) {
	if _, ok := d.Ports.Load(port); ok {
		d.Ports.Delete(port)
	} else {
		logger.Warnw(ctx, "Port doesn't exist", log.Fields{"Device": d.Name, "Port": port})
	}
}

// pushFlowsForUnis to send port-up-indication for uni ports.
func (d *VoltDevice) pushFlowsForUnis(cntx context.Context) {
	logger.Info(ctx, "NNI Discovered, Sending Port UP Ind for UNIs")
	d.Ports.Range(func(key, value interface{}) bool {
		port := key.(string)
		vp := value.(*VoltPort)

		logger.Infow(ctx, "NNI Discovered. Sending Port UP Ind for UNI", log.Fields{"Port": port})
		//Ignore if UNI port is not UP
		if vp.State != PortStateUp {
			return true
		}

		//Obtain all VPVs associated with the port
		vnets, ok := GetApplication().VnetsByPort.Load(port)
		if !ok {
			return true
		}

		for _, vpv := range vnets.([]*VoltPortVnet) {
			vpv.VpvLock.Lock()
			vpv.PortUpInd(cntx, d, port)
			vpv.VpvLock.Unlock()
		}
		return true
	})
}

// ----------------------------------------------------------
// VOLT Application - hosts all other objects
// ----------------------------------------------------------
//
// The VOLT application is a singleton implementation where
// there is just one instance in the system and is the gateway
// to all other components within the controller
// The declaration of the singleton object
var vapplication *VoltApplication

// VoltApplication fields :
// ServiceByName - Stores the services by the name as key
// A record of NB configuration.
// VnetsByPort   - Stores the VNETs by the ports configured
// from NB. A record of NB configuration.
// VnetsByTag    - Stores the VNETs by the VLANS configured
// from NB. A record of NB configuration.
// VnetsByName   - Stores the VNETs by the name configured
// from NB. A record of NB configuration.
// DevicesDisc   - Stores the devices discovered from SB.
// Should be updated only by events from SB
// PortsDisc     - Stores the ports discovered from SB.
// Should be updated only by events from SB
type VoltApplication struct {
	MeterMgr
	DataMigrationInfo     DataMigration
	VnetsBySvlan          *util.ConcurrentMap
	IgmpGroupIds          []*IgmpGroup
	VoltPortVnetsToDelete map[*VoltPortVnet]bool
	IgmpPendingPool       map[string]map[*IgmpGroup]bool //[grpkey, map[groupObj]bool]  //mvlan_grpName/IP
	macPortMap            map[string]string
	VnetsToDelete         map[string]bool
	ServicesToDelete      map[string]bool
       ServicesToDeactivate  map[string]bool
	PortAlarmProfileCache map[string]map[string]int // [portAlarmID][ThresholdLevelString]ThresholdLevel
	vendorID              string
	ServiceByName         sync.Map // [serName]*VoltService
	VnetsByPort           sync.Map // [portName][]*VoltPortVnet
	VnetsByTag            sync.Map // [svlan-cvlan-uvlan]*VoltVnet
	VnetsByName           sync.Map // [vnetName]*VoltVnet
	DevicesDisc           sync.Map
	PortsDisc             sync.Map
	IgmpGroups            sync.Map // [grpKey]*IgmpGroup
	MvlanProfilesByTag    sync.Map
	MvlanProfilesByName   sync.Map
	Icmpv6Receivers       sync.Map
	DeviceCounters        sync.Map //[logicalDeviceId]*DeviceCounters
	ServiceCounters       sync.Map //[serviceName]*ServiceCounters
	NbDevice              sync.Map // [OLTSouthBoundID]*NbDevice
	OltIgmpInfoBySerial   sync.Map
	McastConfigMap        sync.Map //[OltSerialNo_MvlanProfileID]*McastConfig
	DevicesConfig         sync.Map //[serialNumber]*DeviceConfig
	IgmpProfilesByName    sync.Map
	IgmpTasks             tasks.Tasks
	IndicationsTasks      tasks.Tasks
	MulticastAlarmTasks   tasks.Tasks
	IgmpKPIsTasks         tasks.Tasks
	pppoeTasks            tasks.Tasks
	OltFlowServiceConfig  OltFlowService
	PendingPoolLock       sync.RWMutex
	// MacAddress-Port MAP to avoid swap of mac across ports.
	macPortLock sync.RWMutex
	portLock    sync.Mutex
}

type DeviceConfig struct {
	SerialNumber       string `json:"id"`
	HardwareIdentifier string `json:"hardwareIdentifier"`
	IPAddress          string `json:"ipAddress"`
	UplinkPort         string `json:"uplinkPort"`
	NasID              string `json:"nasId"`
	NniDhcpTrapVid     int    `json:"nniDhcpTrapVid"`
}

// PonPortCfg contains NB port config and activeIGMPChannels count
type PonPortCfg struct {
	PortAlarmProfileID string
	PortID             uint32
	MaxActiveChannels  uint32
	ActiveIGMPChannels uint32
	EnableMulticastKPI bool
}

// NbDevice OLT Device info
type NbDevice struct {
	SouthBoundID string
	PonPorts     sync.Map // [PortID]*PonPortCfg
}

// RestoreNbDeviceFromDb restores the NB Device in case of VGC pod restart.
func (va *VoltApplication) RestoreNbDeviceFromDb(cntx context.Context, deviceID string) *NbDevice {
	nbDevice := NewNbDevice()
	nbDevice.SouthBoundID = deviceID

	nbPorts, _ := db.GetAllNbPorts(cntx, deviceID)

	for key, p := range nbPorts {
		b, ok := p.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var port PonPortCfg
		err := json.Unmarshal(b, &port)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of PonPortCfg failed")
			continue
		}
		logger.Debugw(ctx, "Port recovered", log.Fields{"port": port})
		ponPortID, _ := strconv.Atoi(key)
		nbDevice.PonPorts.Store(uint32(ponPortID), &port)
	}
	va.NbDevice.Store(deviceID, nbDevice)
	return nbDevice
}

// NewNbDevice Constructor for NbDevice
func NewNbDevice() *NbDevice {
	var nbDevice NbDevice
	return &nbDevice
}

// WriteToDb writes nb device port config to kv store
func (nbd *NbDevice) WriteToDb(cntx context.Context, portID uint32, ponPort *PonPortCfg) {
	b, err := json.Marshal(ponPort)
	if err != nil {
		logger.Errorw(ctx, "PonPortConfig-marshal-failed", log.Fields{"err": err})
		return
	}
	db.PutNbDevicePort(cntx, nbd.SouthBoundID, portID, string(b))
}

// AddPortToNbDevice Adds pon port to NB Device and DB
func (nbd *NbDevice) AddPortToNbDevice(cntx context.Context, portID, allowedChannels uint32,
	enableMulticastKPI bool, portAlarmProfileID string) *PonPortCfg {
	ponPort := &PonPortCfg{
		PortID:             portID,
		MaxActiveChannels:  allowedChannels,
		EnableMulticastKPI: enableMulticastKPI,
		PortAlarmProfileID: portAlarmProfileID,
	}
	nbd.PonPorts.Store(portID, ponPort)
	nbd.WriteToDb(cntx, portID, ponPort)
	return ponPort
}

// RestoreDeviceConfigFromDb to restore vnet from port
func (va *VoltApplication) RestoreDeviceConfigFromDb(cntx context.Context) {
	// VNETS must be learnt first
	dConfig, _ := db.GetDeviceConfig(cntx)
	for _, device := range dConfig {
		b, ok := device.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		devConfig := DeviceConfig{}
		err := json.Unmarshal(b, &devConfig)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of device configuration failed")
			continue
		}
		logger.Debugw(ctx, "Retrieved device config", log.Fields{"Device Config": devConfig})
		if err := va.AddDeviceConfig(cntx, devConfig.SerialNumber, devConfig.HardwareIdentifier, devConfig.NasID, devConfig.IPAddress, devConfig.UplinkPort, devConfig.NniDhcpTrapVid); err != nil {
			logger.Warnw(ctx, "Add device config failed", log.Fields{"DeviceConfig": devConfig, "Error": err})
		}
	}
}

// WriteDeviceConfigToDb writes sb device config to kv store
func (dc *DeviceConfig) WriteDeviceConfigToDb(cntx context.Context, serialNum string, deviceConfig *DeviceConfig) error {
	b, err := json.Marshal(deviceConfig)
	if err != nil {
		logger.Errorw(ctx, "deviceConfig-marshal-failed", log.Fields{"err": err})
		return err
	}
	dberr := db.PutDeviceConfig(cntx, serialNum, string(b))
	if dberr != nil {
		logger.Errorw(ctx, "update device config failed", log.Fields{"err": err})
		return dberr
	}
	return nil
}

func (va *VoltApplication) AddDeviceConfig(cntx context.Context, serialNum, hardwareIdentifier, nasID, ipAddress, uplinkPort string, nniDhcpTrapID int) error {
	var dc *DeviceConfig

	deviceConfig := &DeviceConfig{
		SerialNumber:       serialNum,
		HardwareIdentifier: hardwareIdentifier,
		NasID:              nasID,
		UplinkPort:         uplinkPort,
		IPAddress:          ipAddress,
		NniDhcpTrapVid:     nniDhcpTrapID,
	}
	va.DevicesConfig.Store(serialNum, deviceConfig)
	err := dc.WriteDeviceConfigToDb(cntx, serialNum, deviceConfig)
	if err != nil {
		logger.Errorw(ctx, "DB update for device config failed", log.Fields{"err": err})
		return err
	}

	// If device is already discovered update the VoltDevice structure
	device, id := va.GetDeviceBySerialNo(serialNum)
	if device != nil {
		device.NniDhcpTrapVid = of.VlanType(nniDhcpTrapID)
		va.DevicesDisc.Store(id, device)
	}

	return nil
}

// GetDeviceConfig to get a device config.
func (va *VoltApplication) GetDeviceConfig(serNum string) *DeviceConfig {
	if d, ok := va.DevicesConfig.Load(serNum); ok {
		return d.(*DeviceConfig)
	}
	return nil
}

// UpdatePortToNbDevice Adds pon port to NB Device and DB
func (nbd *NbDevice) UpdatePortToNbDevice(cntx context.Context, portID, allowedChannels uint32, enableMulticastKPI bool, portAlarmProfileID string) *PonPortCfg {
	p, exists := nbd.PonPorts.Load(portID)
	if !exists {
		logger.Errorw(ctx, "PON port not exists in nb-device", log.Fields{"portID": portID})
		return nil
	}
	port := p.(*PonPortCfg)
	if allowedChannels != 0 {
		port.MaxActiveChannels = allowedChannels
		port.EnableMulticastKPI = enableMulticastKPI
		port.PortAlarmProfileID = portAlarmProfileID
	}

	nbd.PonPorts.Store(portID, port)
	nbd.WriteToDb(cntx, portID, port)
	return port
}

// DeletePortFromNbDevice Deletes pon port from NB Device and DB
func (nbd *NbDevice) DeletePortFromNbDevice(cntx context.Context, portID uint32) {
	if _, ok := nbd.PonPorts.Load(portID); ok {
		nbd.PonPorts.Delete(portID)
	}
	db.DelNbDevicePort(cntx, nbd.SouthBoundID, portID)
}

// GetApplication : Interface to access the singleton object
func GetApplication() *VoltApplication {
	if vapplication == nil {
		vapplication = newVoltApplication()
	}
	return vapplication
}

// newVoltApplication : Constructor for the singleton object. Hence this is not
// an exported function
func newVoltApplication() *VoltApplication {
	var va VoltApplication
	va.IgmpTasks.Initialize(context.TODO())
	va.MulticastAlarmTasks.Initialize(context.TODO())
	va.IgmpKPIsTasks.Initialize(context.TODO())
	va.pppoeTasks.Initialize(context.TODO())
	va.storeIgmpProfileMap(DefaultIgmpProfID, newDefaultIgmpProfile())
	va.MeterMgr.Init()
	va.AddIgmpGroups(5000)
	va.macPortMap = make(map[string]string)
	va.IgmpPendingPool = make(map[string]map[*IgmpGroup]bool)
	va.VnetsBySvlan = util.NewConcurrentMap()
	va.VnetsToDelete = make(map[string]bool)
	va.ServicesToDelete = make(map[string]bool)
       va.ServicesToDeactivate = make(map[string]bool)
	va.VoltPortVnetsToDelete = make(map[*VoltPortVnet]bool)
	go va.Start(context.Background(), TimerCfg{tick: 100 * time.Millisecond}, tickTimer)
	go va.Start(context.Background(), TimerCfg{tick: time.Duration(GroupExpiryTime) * time.Minute}, pendingPoolTimer)
	InitEventFuncMapper()
	db = database.GetDatabase()
	return &va
}

// GetFlowEventRegister - returs the register based on flow mod type
func (d *VoltDevice) GetFlowEventRegister(flowModType of.Command) (*util.ConcurrentMap, error) {
	switch flowModType {
	case of.CommandDel:
		return d.FlowDelEventMap, nil
	case of.CommandAdd:
		return d.FlowAddEventMap, nil
	default:
		logger.Error(ctx, "Unknown Flow Mod received")
	}
	return util.NewConcurrentMap(), errors.New("Unknown Flow Mod")
}

// RegisterFlowAddEvent to register a flow event.
func (d *VoltDevice) RegisterFlowAddEvent(cookie string, event *FlowEvent) {
	logger.Debugw(ctx, "Registered Flow Add Event", log.Fields{"Cookie": cookie, "Event": event})
	d.FlowAddEventMap.MapLock.Lock()
	defer d.FlowAddEventMap.MapLock.Unlock()
	d.FlowAddEventMap.Set(cookie, event)
}

// RegisterFlowDelEvent to register a flow event.
func (d *VoltDevice) RegisterFlowDelEvent(cookie string, event *FlowEvent) {
	logger.Debugw(ctx, "Registered Flow Del Event", log.Fields{"Cookie": cookie, "Event": event})
	d.FlowDelEventMap.MapLock.Lock()
	defer d.FlowDelEventMap.MapLock.Unlock()
	d.FlowDelEventMap.Set(cookie, event)
}

// UnRegisterFlowEvent to unregister a flow event.
func (d *VoltDevice) UnRegisterFlowEvent(cookie string, flowModType of.Command) {
	logger.Debugw(ctx, "UnRegistered Flow Add Event", log.Fields{"Cookie": cookie, "Type": flowModType})
	flowEventMap, err := d.GetFlowEventRegister(flowModType)
	if err != nil {
		logger.Debugw(ctx, "Flow event map does not exists", log.Fields{"flowMod": flowModType, "Error": err})
		return
	}
	flowEventMap.MapLock.Lock()
	defer flowEventMap.MapLock.Unlock()
	flowEventMap.Remove(cookie)
}

// AddIgmpGroups to add Igmp groups.
func (va *VoltApplication) AddIgmpGroups(numOfGroups uint32) {
	//TODO: Temp change to resolve group id issue in pOLT
	//for i := 1; uint32(i) <= numOfGroups; i++ {
	for i := 2; uint32(i) <= (numOfGroups + 1); i++ {
		ig := IgmpGroup{}
		ig.GroupID = uint32(i)
		va.IgmpGroupIds = append(va.IgmpGroupIds, &ig)
	}
}

// GetAvailIgmpGroupID to get id of available igmp group.
func (va *VoltApplication) GetAvailIgmpGroupID() *IgmpGroup {
	var ig *IgmpGroup
	if len(va.IgmpGroupIds) > 0 {
		ig, va.IgmpGroupIds = va.IgmpGroupIds[0], va.IgmpGroupIds[1:]
		return ig
	}
	return nil
}

// GetIgmpGroupID to get id of igmp group.
func (va *VoltApplication) GetIgmpGroupID(gid uint32) (*IgmpGroup, error) {
	for id, ig := range va.IgmpGroupIds {
		if ig.GroupID == gid {
			va.IgmpGroupIds = append(va.IgmpGroupIds[0:id], va.IgmpGroupIds[id+1:]...)
			return ig, nil
		}
	}
	return nil, errors.New("Group Id Missing")
}

// PutIgmpGroupID to add id of igmp group.
func (va *VoltApplication) PutIgmpGroupID(ig *IgmpGroup) {
	va.IgmpGroupIds = append([]*IgmpGroup{ig}, va.IgmpGroupIds[0:]...)
}

// RestoreUpgradeStatus - gets upgrade/migration status from DB and updates local flags
func (va *VoltApplication) RestoreUpgradeStatus(cntx context.Context) {
	Migrate := new(DataMigration)
	if err := GetMigrationInfo(cntx, Migrate); err == nil {
		if Migrate.Status == MigrationInProgress {
			isUpgradeComplete = false
			return
		}
	}
	isUpgradeComplete = true

	logger.Infow(ctx, "Upgrade Status Restored", log.Fields{"Upgrade Completed": isUpgradeComplete})
}

// ReadAllFromDb : If we are restarted, learn from the database the current execution
// stage
func (va *VoltApplication) ReadAllFromDb(cntx context.Context) {
	logger.Info(ctx, "Reading the meters from DB")
	va.RestoreMetersFromDb(cntx)
	logger.Info(ctx, "Reading the VNETs from DB")
	va.RestoreVnetsFromDb(cntx)
	logger.Info(ctx, "Reading the VPVs from DB")
	va.RestoreVpvsFromDb(cntx)
	logger.Info(ctx, "Reading the Services from DB")
	va.RestoreSvcsFromDb(cntx)
	logger.Info(ctx, "Reading the MVLANs from DB")
	va.RestoreMvlansFromDb(cntx)
	logger.Info(ctx, "Reading the IGMP profiles from DB")
	va.RestoreIGMPProfilesFromDb(cntx)
	logger.Info(ctx, "Reading the Mcast configs from DB")
	va.RestoreMcastConfigsFromDb(cntx)
	logger.Info(ctx, "Reading the IGMP groups for DB")
	va.RestoreIgmpGroupsFromDb(cntx)
	logger.Info(ctx, "Reading Upgrade status from DB")
	va.RestoreUpgradeStatus(cntx)
	logger.Info(ctx, "Reading OltFlowService from DB")
	va.RestoreOltFlowService(cntx)
	logger.Info(ctx, "Reading device config from DB")
	va.RestoreDeviceConfigFromDb(cntx)
	logger.Info(ctx, "Reconciled from DB")
}

// InitStaticConfig to initialize static config.
func (va *VoltApplication) InitStaticConfig() {
	va.InitIgmpSrcMac()
}

// SetVendorID to set vendor id
func (va *VoltApplication) SetVendorID(vendorID string) {
	va.vendorID = vendorID
}

// GetVendorID to get vendor id
func (va *VoltApplication) GetVendorID() string {
	return va.vendorID
}

// SetRebootFlag to set reboot flag
func (va *VoltApplication) SetRebootFlag(flag bool) {
	vgcRebooted = flag
}

// GetUpgradeFlag to get reboot status
func (va *VoltApplication) GetUpgradeFlag() bool {
	return isUpgradeComplete
}

// SetUpgradeFlag to set reboot status
func (va *VoltApplication) SetUpgradeFlag(flag bool) {
	isUpgradeComplete = flag
}

// ------------------------------------------------------------
// Device related functions

// AddDevice : Add a device and typically the device stores the NNI port on the device
// The NNI port is used when the packets are emitted towards the network.
// The outport is selected as the NNI port of the device. Today, we support
// a single NNI port per OLT. This is true whether the network uses any
// protection mechanism (LAG, ERPS, etc.). The aggregate of the such protection
// is represented by a single NNI port
func (va *VoltApplication) AddDevice(cntx context.Context, device string, slno, southBoundID string) {
	logger.Warnw(ctx, "Received Device Ind: Add", log.Fields{"Device": device, "SrNo": slno, "southBoundID": southBoundID})
	if _, ok := va.DevicesDisc.Load(device); ok {
		logger.Warnw(ctx, "Device Exists", log.Fields{"Device": device})
	}
	d := NewVoltDevice(device, slno, southBoundID)

	addPort := func(key, value interface{}) bool {
		portID := key.(uint32)
		port := value.(*PonPortCfg)
		va.AggActiveChannelsCountForPonPort(device, portID, port)
		d.ActiveChannelsPerPon.Store(portID, port)
		return true
	}
	if nbDevice, exists := va.NbDevice.Load(southBoundID); exists {
		// Pon Ports added before OLT activate.
		nbDevice.(*NbDevice).PonPorts.Range(addPort)
	} else {
		// Check if NbPort exists in DB. VGC restart case.
		nbd := va.RestoreNbDeviceFromDb(cntx, southBoundID)
		nbd.PonPorts.Range(addPort)
	}
	va.DevicesDisc.Store(device, d)
}

// GetDevice to get a device.
func (va *VoltApplication) GetDevice(device string) *VoltDevice {
	if d, ok := va.DevicesDisc.Load(device); ok {
		return d.(*VoltDevice)
	}
	return nil
}

// DelDevice to delete a device.
func (va *VoltApplication) DelDevice(cntx context.Context, device string) {
	logger.Warnw(ctx, "Received Device Ind: Delete", log.Fields{"Device": device})
	if vdIntf, ok := va.DevicesDisc.Load(device); ok {
		vd := vdIntf.(*VoltDevice)
		va.DevicesDisc.Delete(device)
		_ = db.DelAllRoutesForDevice(cntx, device)
		va.HandleFlowClearFlag(cntx, device, vd.SerialNum, vd.SouthBoundID)
		_ = db.DelAllGroup(cntx, device)
		_ = db.DelAllMeter(cntx, device)
		_ = db.DelAllPorts(cntx, device)
		logger.Debugw(ctx, "Device deleted", log.Fields{"Device": device})
	} else {
		logger.Warnw(ctx, "Device Doesn't Exist", log.Fields{"Device": device})
	}
}

// GetDeviceBySerialNo to get a device by serial number.
// TODO - Transform this into a MAP instead
func (va *VoltApplication) GetDeviceBySerialNo(slno string) (*VoltDevice, string) {
	var device *VoltDevice
	var deviceID string
	getserial := func(key interface{}, value interface{}) bool {
		device = value.(*VoltDevice)
		deviceID = key.(string)
		return device.SerialNum != slno
	}
	va.DevicesDisc.Range(getserial)
	return device, deviceID
}

// PortAddInd : This is a PORT add indication coming from the VPAgent, which is essentially
// a request coming from VOLTHA. The device and identity of the port is provided
// in this request. Add them to the application for further use
func (va *VoltApplication) PortAddInd(cntx context.Context, device string, id uint32, portName string) {
	logger.Infow(ctx, "Received Port Ind: Add", log.Fields{"Device": device, "Port": portName})
	va.portLock.Lock()
	if d := va.GetDevice(device); d != nil {
		p := d.AddPort(portName, id)
		va.PortsDisc.Store(portName, p)
		va.portLock.Unlock()
		nni, _ := va.GetNniPort(device)
		if nni == portName {
			d.pushFlowsForUnis(cntx)
		}
	} else {
		va.portLock.Unlock()
		logger.Warnw(ctx, "Device Not Found - Dropping Port Ind: Add", log.Fields{"Device": device, "Port": portName})
	}
}

// PortDelInd : Only the NNI ports are recorded in the device for now. When port delete
// arrives, only the NNI ports need adjustments.
func (va *VoltApplication) PortDelInd(cntx context.Context, device string, port string) {
	logger.Infow(ctx, "Received Port Ind: Delete", log.Fields{"Device": device, "Port": port})
	if d := va.GetDevice(device); d != nil {
		p := d.GetPort(port)
		if p != nil && p.State == PortStateUp {
			logger.Infow(ctx, "Port state is UP. Trigerring Port Down Ind before deleting", log.Fields{"Port": p})
			va.PortDownInd(cntx, device, port)
		}
		// if RemoveFlowsOnDisable is flase, then flows will be existing till port delete. Remove the flows now
		if !va.OltFlowServiceConfig.RemoveFlowsOnDisable {
			vpvs, ok := va.VnetsByPort.Load(port)
			if !ok || nil == vpvs || len(vpvs.([]*VoltPortVnet)) == 0 {
				logger.Infow(ctx, "No VNETs on port", log.Fields{"Device": device, "Port": port})
			} else {
				for _, vpv := range vpvs.([]*VoltPortVnet) {
					vpv.VpvLock.Lock()
					vpv.PortDownInd(cntx, device, port, true)
					vpv.VpvLock.Unlock()
				}
			}
		}
		va.portLock.Lock()
		defer va.portLock.Unlock()
		d.DelPort(port)
		if _, ok := va.PortsDisc.Load(port); ok {
			va.PortsDisc.Delete(port)
		}
	} else {
		logger.Warnw(ctx, "Device Not Found - Dropping Port Ind: Delete", log.Fields{"Device": device, "Port": port})
	}
}

// PortUpdateInd Updates port Id incase of ONU movement
func (va *VoltApplication) PortUpdateInd(device string, portName string, id uint32) {
	logger.Infow(ctx, "Received Port Ind: Update", log.Fields{"Device": device, "Port": portName})
	va.portLock.Lock()
	defer va.portLock.Unlock()
	if d := va.GetDevice(device); d != nil {
		vp := d.GetPort(portName)
		vp.ID = id
	} else {
		logger.Warnw(ctx, "Device Not Found", log.Fields{"Device": device, "Port": portName})
	}
}

// AddNbPonPort Add pon port to nbDevice
func (va *VoltApplication) AddNbPonPort(cntx context.Context, oltSbID string, portID, maxAllowedChannels uint32,
	enableMulticastKPI bool, portAlarmProfileID string) error {
	var nbd *NbDevice
	nbDevice, ok := va.NbDevice.Load(oltSbID)

	if !ok {
		nbd = NewNbDevice()
		nbd.SouthBoundID = oltSbID
	} else {
		nbd = nbDevice.(*NbDevice)
	}
	port := nbd.AddPortToNbDevice(cntx, portID, maxAllowedChannels, enableMulticastKPI, portAlarmProfileID)

	// Add this port to voltDevice
	addPort := func(key, value interface{}) bool {
		voltDevice := value.(*VoltDevice)
		if oltSbID == voltDevice.SouthBoundID {
			if _, exists := voltDevice.ActiveChannelsPerPon.Load(portID); !exists {
				voltDevice.ActiveChannelsPerPon.Store(portID, port)
			}
			return false
		}
		return true
	}
	va.DevicesDisc.Range(addPort)
	va.NbDevice.Store(oltSbID, nbd)

	return nil
}

// UpdateNbPonPort update pon port to nbDevice
func (va *VoltApplication) UpdateNbPonPort(cntx context.Context, oltSbID string, portID, maxAllowedChannels uint32, enableMulticastKPI bool, portAlarmProfileID string) error {
	var nbd *NbDevice
	nbDevice, ok := va.NbDevice.Load(oltSbID)

	if !ok {
		logger.Errorw(ctx, "Device-doesn't-exists", log.Fields{"deviceID": oltSbID})
		return fmt.Errorf("Device-doesn't-exists-%v", oltSbID)
	}
	nbd = nbDevice.(*NbDevice)

	port := nbd.UpdatePortToNbDevice(cntx, portID, maxAllowedChannels, enableMulticastKPI, portAlarmProfileID)
	if port == nil {
		return fmt.Errorf("Port-doesn't-exists-%v", portID)
	}
	va.NbDevice.Store(oltSbID, nbd)

	// Add this port to voltDevice
	updPort := func(key, value interface{}) bool {
		voltDevice := value.(*VoltDevice)
		if oltSbID == voltDevice.SouthBoundID {
			voltDevice.ActiveChannelCountLock.Lock()
			if p, exists := voltDevice.ActiveChannelsPerPon.Load(portID); exists {
				oldPort := p.(*PonPortCfg)
				if port.MaxActiveChannels != 0 {
					oldPort.MaxActiveChannels = port.MaxActiveChannels
					oldPort.EnableMulticastKPI = port.EnableMulticastKPI
					voltDevice.ActiveChannelsPerPon.Store(portID, oldPort)
				}
			}
			voltDevice.ActiveChannelCountLock.Unlock()
			return false
		}
		return true
	}
	va.DevicesDisc.Range(updPort)

	return nil
}

// DeleteNbPonPort Delete pon port to nbDevice
func (va *VoltApplication) DeleteNbPonPort(cntx context.Context, oltSbID string, portID uint32) error {
	nbDevice, ok := va.NbDevice.Load(oltSbID)
	if ok {
		nbDevice.(*NbDevice).DeletePortFromNbDevice(cntx, portID)
		va.NbDevice.Store(oltSbID, nbDevice.(*NbDevice))
	} else {
		logger.Warnw(ctx, "Delete pon received for unknown device", log.Fields{"oltSbID": oltSbID})
		return nil
	}
	// Delete this port from voltDevice
	delPort := func(key, value interface{}) bool {
		voltDevice := value.(*VoltDevice)
		if oltSbID == voltDevice.SouthBoundID {
			if _, exists := voltDevice.ActiveChannelsPerPon.Load(portID); exists {
				voltDevice.ActiveChannelsPerPon.Delete(portID)
			}
			return false
		}
		return true
	}
	va.DevicesDisc.Range(delPort)
	return nil
}

// GetNniPort : Get the NNI port for a device. Called from different other applications
// as a port to match or destination for a packet out. The VOLT application
// is written with the assumption that there is a single NNI port. The OLT
// device is responsible for translating the combination of VLAN and the
// NNI port ID to identify possibly a single physical port or a logical
// port which is a result of protection methods applied.
func (va *VoltApplication) GetNniPort(device string) (string, error) {
	va.portLock.Lock()
	defer va.portLock.Unlock()
	d, ok := va.DevicesDisc.Load(device)
	if !ok {
		return "", errors.New("Device Doesn't Exist")
	}
	return d.(*VoltDevice).NniPort, nil
}

// NniDownInd process for Nni down indication.
func (va *VoltApplication) NniDownInd(cntx context.Context, deviceID string, devSrNo string) {
	logger.Debugw(ctx, "NNI Down Ind", log.Fields{"device": devSrNo})

	handleIgmpDsFlows := func(key interface{}, value interface{}) bool {
		mvProfile := value.(*MvlanProfile)
		mvProfile.removeIgmpMcastFlows(cntx, devSrNo)
		return true
	}
	va.MvlanProfilesByName.Range(handleIgmpDsFlows)

	//Clear Static Group
	va.ReceiverDownInd(cntx, deviceID, StaticPort)
}

// DeviceUpInd changes device state to up.
func (va *VoltApplication) DeviceUpInd(device string) {
	logger.Warnw(ctx, "Received Device Ind: UP", log.Fields{"Device": device})
	if d := va.GetDevice(device); d != nil {
		d.State = controller.DeviceStateUP
	} else {
		logger.Errorw(ctx, "Ignoring Device indication: UP. Device Missing", log.Fields{"Device": device})
	}
}

// DeviceDownInd changes device state to down.
func (va *VoltApplication) DeviceDownInd(device string) {
	logger.Warnw(ctx, "Received Device Ind: DOWN", log.Fields{"Device": device})
	if d := va.GetDevice(device); d != nil {
		d.State = controller.DeviceStateDOWN
	} else {
		logger.Errorw(ctx, "Ignoring Device indication: DOWN. Device Missing", log.Fields{"Device": device})
	}
}

// DeviceRebootInd process for handling flow clear flag for device reboot
func (va *VoltApplication) DeviceRebootInd(cntx context.Context, device string, serialNum string, southBoundID string) {
	logger.Warnw(ctx, "Received Device Ind: Reboot", log.Fields{"Device": device, "SerialNumber": serialNum})

	if d := va.GetDevice(device); d != nil {
		if d.State == controller.DeviceStateREBOOTED {
			logger.Warnw(ctx, "Ignoring Device Ind: Reboot, Device already in Reboot state", log.Fields{"Device": device, "SerialNumber": serialNum, "State": d.State})
			return
		}
		d.State = controller.DeviceStateREBOOTED
	}
	va.HandleFlowClearFlag(cntx, device, serialNum, southBoundID)
}

// DeviceDisableInd handles device deactivation process
func (va *VoltApplication) DeviceDisableInd(cntx context.Context, device string) {
	logger.Warnw(ctx, "Received Device Ind: Disable", log.Fields{"Device": device})

	d := va.GetDevice(device)
	if d == nil {
		logger.Errorw(ctx, "Ignoring Device indication: DISABLED. Device Missing", log.Fields{"Device": device})
		return
	}

	d.State = controller.DeviceStateDISABLED
	va.HandleFlowClearFlag(cntx, device, d.SerialNum, d.SouthBoundID)
}

// ProcessIgmpDSFlowForMvlan for processing Igmp DS flow for device
func (va *VoltApplication) ProcessIgmpDSFlowForMvlan(cntx context.Context, d *VoltDevice, mvp *MvlanProfile, addFlow bool) {
	logger.Debugw(ctx, "Process IGMP DS Flows for MVlan", log.Fields{"device": d.Name, "Mvlan": mvp.Mvlan, "addFlow": addFlow})
	portState := false
	p := d.GetPort(d.NniPort)
	if p != nil && p.State == PortStateUp {
		portState = true
	}

	if addFlow {
		if portState {
			mvp.pushIgmpMcastFlows(cntx, d.SerialNum)
		}
	} else {
		mvp.removeIgmpMcastFlows(cntx, d.SerialNum)
	}
}

// ProcessIgmpDSFlowForDevice for processing Igmp DS flow for device
func (va *VoltApplication) ProcessIgmpDSFlowForDevice(cntx context.Context, d *VoltDevice, addFlow bool) {
	logger.Debugw(ctx, "Process IGMP DS Flows for device", log.Fields{"device": d.Name, "addFlow": addFlow})

	handleIgmpDsFlows := func(key interface{}, value interface{}) bool {
		mvProfile := value.(*MvlanProfile)
		va.ProcessIgmpDSFlowForMvlan(cntx, d, mvProfile, addFlow)
		return true
	}
	va.MvlanProfilesByName.Range(handleIgmpDsFlows)
}

// GetDeviceFromPort : This is suitable only for access ports as their naming convention
// makes them unique across all the OLTs. This must be called with
// port name that is an access port. Currently called from VNETs, attached
// only to access ports, and the services which are also attached only
// to access ports
func (va *VoltApplication) GetDeviceFromPort(port string) (*VoltDevice, error) {
	va.portLock.Lock()
	defer va.portLock.Unlock()
	var err error
	err = nil
	p, ok := va.PortsDisc.Load(port)
	if !ok {
		return nil, errorCodes.ErrPortNotFound
	}
	d := va.GetDevice(p.(*VoltPort).Device)
	if d == nil {
		err = errorCodes.ErrDeviceNotFound
	}
	return d, err
}

// GetPortID : This too applies only to access ports. The ports can be indexed
// purely by their names without the device forming part of the key
func (va *VoltApplication) GetPortID(port string) (uint32, error) {
	va.portLock.Lock()
	defer va.portLock.Unlock()
	p, ok := va.PortsDisc.Load(port)
	if !ok {
		return 0, errorCodes.ErrPortNotFound
	}
	return p.(*VoltPort).ID, nil
}

// GetPortName : This too applies only to access ports. The ports can be indexed
// purely by their names without the device forming part of the key
func (va *VoltApplication) GetPortName(port uint32) (string, error) {
	va.portLock.Lock()
	defer va.portLock.Unlock()
	var portName string
	va.PortsDisc.Range(func(key interface{}, value interface{}) bool {
		portInfo := value.(*VoltPort)
		if portInfo.ID == port {
			portName = portInfo.Name
			return false
		}
		return true
	})
	return portName, nil
}

// GetPonFromUniPort to get Pon info from UniPort
func (va *VoltApplication) GetPonFromUniPort(port string) (string, error) {
	uniPortID, err := va.GetPortID(port)
	if err == nil {
		ponPortID := (uniPortID & 0x0FF00000) >> 20 //pon(8) + onu(8) + uni(12)
		return strconv.FormatUint(uint64(ponPortID), 10), nil
	}
	return "", err
}

// GetPortState : This too applies only to access ports. The ports can be indexed
// purely by their names without the device forming part of the key
func (va *VoltApplication) GetPortState(port string) (PortState, error) {
	va.portLock.Lock()
	defer va.portLock.Unlock()
	p, ok := va.PortsDisc.Load(port)
	if !ok {
		return 0, errors.New("Port not configured")
	}
	return p.(*VoltPort).State, nil
}

// GetIcmpv6Receivers to get Icmp v6 receivers
func (va *VoltApplication) GetIcmpv6Receivers(device string) []uint32 {
	var receiverList []uint32
	receivers, _ := va.Icmpv6Receivers.Load(device)
	if receivers != nil {
		receiverList = receivers.([]uint32)
	}
	return receiverList
}

// AddIcmpv6Receivers to add Icmp v6 receivers
func (va *VoltApplication) AddIcmpv6Receivers(device string, portID uint32) []uint32 {
	var receiverList []uint32
	receivers, _ := va.Icmpv6Receivers.Load(device)
	if receivers != nil {
		receiverList = receivers.([]uint32)
	}
	receiverList = append(receiverList, portID)
	va.Icmpv6Receivers.Store(device, receiverList)
	logger.Debugw(ctx, "Receivers after addition", log.Fields{"Receivers": receiverList})
	return receiverList
}

// DelIcmpv6Receivers to delete Icmp v6 receievers
func (va *VoltApplication) DelIcmpv6Receivers(device string, portID uint32) []uint32 {
	var receiverList []uint32
	receivers, _ := va.Icmpv6Receivers.Load(device)
	if receivers != nil {
		receiverList = receivers.([]uint32)
	}
	for i, port := range receiverList {
		if port == portID {
			receiverList = append(receiverList[0:i], receiverList[i+1:]...)
			va.Icmpv6Receivers.Store(device, receiverList)
			break
		}
	}
	logger.Debugw(ctx, "Receivers After deletion", log.Fields{"Receivers": receiverList})
	return receiverList
}

// ProcessDevFlowForDevice - Process DS ICMPv6 & ARP flow for provided device and vnet profile
// device - Device Obj
// vnet - vnet profile name
// enabled - vlan enabled/disabled - based on the status, the flow shall be added/removed
func (va *VoltApplication) ProcessDevFlowForDevice(cntx context.Context, device *VoltDevice, vnet *VoltVnet, enabled bool) {
	_, applied := device.ConfiguredVlanForDeviceFlows.Get(VnetKey(vnet.SVlan, vnet.CVlan, 0))
	if enabled {
		va.PushDevFlowForVlan(cntx, vnet)
	} else if !enabled && applied {
		//va.DeleteDevFlowForVlan(vnet)
		va.DeleteDevFlowForVlanFromDevice(cntx, vnet, device.SerialNum)
	}
}

// NniVlanIndToIgmp - Trigger receiver up indication to all ports with igmp enabled
// and has the provided mvlan
func (va *VoltApplication) NniVlanIndToIgmp(device *VoltDevice, mvp *MvlanProfile) {
	logger.Infow(ctx, "Sending Igmp Receiver UP indication for all Services", log.Fields{"Vlan": mvp.Mvlan})

	// Trigger nni indication for receiver only for first time
	if device.IgmpDsFlowAppliedForMvlan[uint16(mvp.Mvlan)] {
		return
	}
	device.Ports.Range(func(key, value interface{}) bool {
		port := key.(string)

		if state, _ := va.GetPortState(port); state == PortStateUp {
			vpvs, _ := va.VnetsByPort.Load(port)
			if vpvs == nil {
				return true
			}
			for _, vpv := range vpvs.([]*VoltPortVnet) {
				// Send indication only for subscribers with the received mvlan profile
				if vpv.IgmpEnabled && vpv.MvlanProfileName == mvp.Name {
					vpv.services.Range(ReceiverUpInd)
				}
			}
		}
		return true
	})
}

// PortUpInd :
// -----------------------------------------------------------------------
// Port status change handling
// ----------------------------------------------------------------------
// Port UP indication is passed to all services associated with the port
// so that the services can configure flows applicable when the port goes
// up from down state
func (va *VoltApplication) PortUpInd(cntx context.Context, device string, port string) {
	d := va.GetDevice(device)

	if d == nil {
		logger.Warnw(ctx, "Device Not Found - Dropping Port Ind: UP", log.Fields{"Device": device, "Port": port})
		return
	}

	// Fixme: If Port Update Comes in large numbers, this will result in slow update per device
	va.portLock.Lock()
	// Do not defer the port mutex unlock here
	// Some of the following func calls needs the port lock, so defering the lock here
	// may lead to dead-lock
	p := d.GetPort(port)

	if p == nil {
		logger.Infow(ctx, "Ignoring Port Ind: UP, Port doesnt exist", log.Fields{"Device": device, "PortName": port, "PortId": p})
		va.portLock.Unlock()
		return
	}
	p.State = PortStateUp
	va.portLock.Unlock()

	logger.Infow(ctx, "Received SouthBound Port Ind: UP", log.Fields{"Device": device, "PortName": port, "PortId": p.ID})
	if p.Type == VoltPortTypeNni {
		logger.Warnw(ctx, "Received NNI Port Ind: UP", log.Fields{"Device": device, "PortName": port, "PortId": p.ID})
		//va.PushDevFlowForDevice(d)
		//Build Igmp TrapFlowRule
		//va.ProcessIgmpDSFlowForDevice(d, true)
	}
	vpvs, ok := va.VnetsByPort.Load(port)
	if !ok || nil == vpvs || len(vpvs.([]*VoltPortVnet)) == 0 {
		logger.Infow(ctx, "No VNETs on port", log.Fields{"Device": device, "Port": port})
		//msgbus.ProcessPortInd(msgbus.PortUp, d.SerialNum, p.Name, false, getServiceList(port))
		return
	}

	// If NNI port is not UP, do not push Flows
	if d.NniPort == "" {
		logger.Warnw(ctx, "NNI port not UP. Not sending Port UP Ind for VPVs", log.Fields{"NNI": d.NniPort})
		return
	}

	for _, vpv := range vpvs.([]*VoltPortVnet) {
		vpv.VpvLock.Lock()
		// If no service is activated drop the portUpInd
		if vpv.IsServiceActivated(cntx) {
			// Do not trigger indication for the vpv which is already removed from vpv list as
			// part of service delete (during the lock wait duration)
			// In that case, the services associated wil be zero
			if vpv.servicesCount.Load() != 0 {
				vpv.PortUpInd(cntx, d, port)
			}
		} else {
			// Service not activated, still attach device to service
			vpv.setDevice(d.Name)
		}
		vpv.VpvLock.Unlock()
	}
	// At the end of processing inform the other entities that
	// are interested in the events
}

/*
func getServiceList(port string) map[string]bool {
	serviceList := make(map[string]bool)

	getServiceNames := func(key interface{}, value interface{}) bool {
		serviceList[key.(string)] = value.(*VoltService).DsHSIAFlowsApplied
		return true
	}

	if vpvs, _ := GetApplication().VnetsByPort.Load(port); vpvs != nil {
		vpvList := vpvs.([]*VoltPortVnet)
		for _, vpv := range vpvList {
			vpv.services.Range(getServiceNames)
		}
	}
	return serviceList

}*/

// ReceiverUpInd - Send receiver up indication for service with Igmp enabled
func ReceiverUpInd(key, value interface{}) bool {
	svc := value.(*VoltService)
	var vlan of.VlanType

	if !svc.IPAssigned() {
		logger.Infow(ctx, "IP Not assigned, skipping general query", log.Fields{"Service": svc})
		return false
	}

	// Send port up indication to igmp only for service with igmp enabled
	if svc.IgmpEnabled {
		if svc.VlanControl == ONUCVlan || svc.VlanControl == ONUCVlanOLTSVlan {
			vlan = svc.CVlan
		} else {
			vlan = svc.UniVlan
		}
		if device, _ := GetApplication().GetDeviceFromPort(svc.Port); device != nil {
			GetApplication().ReceiverUpInd(device.Name, svc.Port, svc.MvlanProfileName, vlan, svc.Pbits)
		}
		return false
	}
	return true
}

// PortDownInd : Port down indication is passed on to the services so that the services
// can make changes at this transition.
func (va *VoltApplication) PortDownInd(cntx context.Context, device string, port string) {
	logger.Infow(ctx, "Received SouthBound Port Ind: DOWN", log.Fields{"Device": device, "Port": port})
	d := va.GetDevice(device)

	if d == nil {
		logger.Warnw(ctx, "Device Not Found - Dropping Port Ind: DOWN", log.Fields{"Device": device, "Port": port})
		return
	}
	// Fixme: If Port Update Comes in large numbers, this will result in slow update per device
	va.portLock.Lock()
	// Do not defer the port mutex unlock here
	// Some of the following func calls needs the port lock, so defering the lock here
	// may lead to dead-lock
	p := d.GetPort(port)
	if p == nil {
		logger.Infow(ctx, "Ignoring Port Ind: Down, Port doesnt exist", log.Fields{"Device": device, "PortName": port, "PortId": p})
		va.portLock.Unlock()
		return
	}
	p.State = PortStateDown
	va.portLock.Unlock()

	if d.State == controller.DeviceStateREBOOTED {
		logger.Infow(ctx, "Ignoring Port Ind: Down, Device has been Rebooted", log.Fields{"Device": device, "PortName": port, "PortId": p})
		return
	}

	if p.Type == VoltPortTypeNni {
		logger.Warnw(ctx, "Received NNI Port Ind: DOWN", log.Fields{"Device": device, "Port": port})
		va.DeleteDevFlowForDevice(cntx, d)
		va.NniDownInd(cntx, device, d.SerialNum)
		va.RemovePendingGroups(cntx, device, true)
	}
	vpvs, ok := va.VnetsByPort.Load(port)
	if !ok || nil == vpvs || len(vpvs.([]*VoltPortVnet)) == 0 {
		logger.Infow(ctx, "No VNETs on port", log.Fields{"Device": device, "Port": port})
		//msgbus.ProcessPortInd(msgbus.PortDown, d.SerialNum, p.Name, false, getServiceList(port))
		return
	}

	for _, vpv := range vpvs.([]*VoltPortVnet) {
		vpv.VpvLock.Lock()
		vpv.PortDownInd(cntx, device, port, false)
		if vpv.IgmpEnabled {
			va.ReceiverDownInd(cntx, device, port)
		}
		vpv.VpvLock.Unlock()
	}
}

// PacketInInd :
// -----------------------------------------------------------------------
// PacketIn Processing
// Packet In Indication processing. It arrives with the identities of
// the device and port on which the packet is received. At first, the
// packet is decoded and the right processor is called. Currently, we
// plan to support only DHCP and IGMP. In future, we can add more
// capabilities as needed
func (va *VoltApplication) PacketInInd(cntx context.Context, device string, port string, pkt []byte) {
	// Decode the incoming packet
	packetSide := US
	if strings.Contains(port, NNI) {
		packetSide = DS
	}

	logger.Debugw(ctx, "Received a Packet-In Indication", log.Fields{"Device": device, "Port": port})

	gopkt := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)

	var dot1qFound = false
	for _, l := range gopkt.Layers() {
		if l.LayerType() == layers.LayerTypeDot1Q {
			dot1qFound = true
			break
		}
	}

	if !dot1qFound {
		logger.Debugw(ctx, "Ignoring Received Packet-In Indication without Dot1Q Header",
			log.Fields{"Device": device, "Port": port})
		return
	}

	logger.Debugw(ctx, "Received Southbound Packet In", log.Fields{"Pkt": hex.EncodeToString(gopkt.Data())})

	// Classify the packet into packet types that we support
	// The supported types are DHCP and IGMP. The DHCP packet is
	// identified by matching the L4 protocol to UDP. The IGMP packet
	// is identified by matching L3 protocol to IGMP
	arpl := gopkt.Layer(layers.LayerTypeARP)
	if arpl != nil {
		if callBack, ok := PacketHandlers[ARP]; ok {
			callBack(cntx, device, port, gopkt)
		} else {
			logger.Debugw(ctx, "ARP handler is not registered, dropping the packet", log.Fields{"Pkt": hex.EncodeToString(gopkt.Data())})
		}
		return
	}
	ipv4l := gopkt.Layer(layers.LayerTypeIPv4)
	if ipv4l != nil {
		ip := ipv4l.(*layers.IPv4)

		if ip.Protocol == layers.IPProtocolUDP {
			logger.Debugw(ctx, "Received Southbound UDP ipv4 packet in", log.Fields{"StreamSide": packetSide})
			dhcpl := gopkt.Layer(layers.LayerTypeDHCPv4)
			if dhcpl != nil {
				if callBack, ok := PacketHandlers[DHCPv4]; ok {
					callBack(cntx, device, port, gopkt)
				} else {
					logger.Debugw(ctx, "DHCPv4 handler is not registered, dropping the packet", log.Fields{"Pkt": hex.EncodeToString(gopkt.Data())})
				}
			}
		} else if ip.Protocol == layers.IPProtocolIGMP {
			logger.Debugw(ctx, "Received Southbound IGMP packet in", log.Fields{"StreamSide": packetSide})
			if callBack, ok := PacketHandlers[IGMP]; ok {
				callBack(cntx, device, port, gopkt)
			} else {
				logger.Debugw(ctx, "IGMP handler is not registered, dropping the packet", log.Fields{"Pkt": hex.EncodeToString(gopkt.Data())})
			}
		}
		return
	}
	ipv6l := gopkt.Layer(layers.LayerTypeIPv6)
	if ipv6l != nil {
		ip := ipv6l.(*layers.IPv6)
		if ip.NextHeader == layers.IPProtocolUDP {
			logger.Debug(ctx, "Received Southbound UDP ipv6 packet in")
			dhcpl := gopkt.Layer(layers.LayerTypeDHCPv6)
			if dhcpl != nil {
				if callBack, ok := PacketHandlers[DHCPv6]; ok {
					callBack(cntx, device, port, gopkt)
				} else {
					logger.Debugw(ctx, "DHCPv6 handler is not registered, dropping the packet", log.Fields{"Pkt": hex.EncodeToString(gopkt.Data())})
				}
			}
		}
		return
	}

	pppoel := gopkt.Layer(layers.LayerTypePPPoE)
	if pppoel != nil {
		logger.Debugw(ctx, "Received Southbound PPPoE packet in", log.Fields{"StreamSide": packetSide})
		if callBack, ok := PacketHandlers[PPPOE]; ok {
			callBack(cntx, device, port, gopkt)
		} else {
			logger.Debugw(ctx, "PPPoE handler is not registered, dropping the packet", log.Fields{"Pkt": hex.EncodeToString(gopkt.Data())})
		}
	}
}

// GetVlans : This utility gets the VLANs from the packet. The VLANs are
// used to identify the right service that must process the incoming
// packet
func GetVlans(pkt gopacket.Packet) []of.VlanType {
	var vlans []of.VlanType
	for _, l := range pkt.Layers() {
		if l.LayerType() == layers.LayerTypeDot1Q {
			q, ok := l.(*layers.Dot1Q)
			if ok {
				vlans = append(vlans, of.VlanType(q.VLANIdentifier))
			}
		}
	}
	return vlans
}

// GetPriority to get priority
func GetPriority(pkt gopacket.Packet) uint8 {
	for _, l := range pkt.Layers() {
		if l.LayerType() == layers.LayerTypeDot1Q {
			q, ok := l.(*layers.Dot1Q)
			if ok {
				return q.Priority
			}
		}
	}
	return PriorityNone
}

// HandleFlowClearFlag to handle flow clear flag during reboot
func (va *VoltApplication) HandleFlowClearFlag(cntx context.Context, deviceID string, serialNum, southBoundID string) {
	logger.Warnw(ctx, "Clear All flags for Device", log.Fields{"Device": deviceID, "SerialNum": serialNum, "SBID": southBoundID})
	dev, ok := va.DevicesDisc.Load(deviceID)
	if ok && dev != nil {
		logger.Infow(ctx, "Clear Flags for device", log.Fields{"voltDevice": dev.(*VoltDevice).Name})
		dev.(*VoltDevice).icmpv6GroupAdded = false
		logger.Infow(ctx, "Clearing DS Icmpv6 Map",
			log.Fields{"voltDevice": dev.(*VoltDevice).Name})
		dev.(*VoltDevice).ConfiguredVlanForDeviceFlows = util.NewConcurrentMap()
		logger.Infow(ctx, "Clearing DS IGMP Map",
			log.Fields{"voltDevice": dev.(*VoltDevice).Name})
		for k := range dev.(*VoltDevice).IgmpDsFlowAppliedForMvlan {
			delete(dev.(*VoltDevice).IgmpDsFlowAppliedForMvlan, k)
		}
		// Delete group 1 - ICMPv6/ARP group
		if err := ProcessIcmpv6McGroup(deviceID, true); err != nil {
			logger.Errorw(ctx, "ProcessIcmpv6McGroup failed", log.Fields{"Device": deviceID, "Error": err})
		}
	} else {
		logger.Warnw(ctx, "VoltDevice not found for device ", log.Fields{"deviceID": deviceID})
	}

	getVpvs := func(key interface{}, value interface{}) bool {
		vpvs := value.([]*VoltPortVnet)
		for _, vpv := range vpvs {
			if vpv.Device == deviceID {
				logger.Infow(ctx, "Clear Flags for vpv",
					log.Fields{"device": vpv.Device, "port": vpv.Port,
						"svlan": vpv.SVlan, "cvlan": vpv.CVlan, "univlan": vpv.UniVlan})
				vpv.ClearAllServiceFlags(cntx)
				vpv.ClearAllVpvFlags(cntx)

				if vpv.IgmpEnabled {
					va.ReceiverDownInd(cntx, vpv.Device, vpv.Port)
					// Also clear service igmp stats
					vpv.ClearServiceCounters(cntx)
				}
			}
		}
		return true
	}
	va.VnetsByPort.Range(getVpvs)

	// Clear Static Group
	va.ReceiverDownInd(cntx, deviceID, StaticPort)

	logger.Warnw(ctx, "All flags cleared for device", log.Fields{"Device": deviceID})

	// Reset pending group pool
	va.RemovePendingGroups(cntx, deviceID, true)

	// Process all Migrate Service Request - force udpate all profiles since resources are already cleaned up
	if dev != nil {
		triggerForceUpdate := func(key, value interface{}) bool {
			msrList := value.(*util.ConcurrentMap)
			forceUpdateServices := func(key, value interface{}) bool {
				msr := value.(*MigrateServicesRequest)
				forceUpdateAllServices(cntx, msr)
				return true
			}
			msrList.Range(forceUpdateServices)
			return true
		}
		dev.(*VoltDevice).MigratingServices.Range(triggerForceUpdate)
	} else {
		va.FetchAndProcessAllMigrateServicesReq(cntx, deviceID, forceUpdateAllServices)
	}
}

// GetPonPortIDFromUNIPort to get pon port id from uni port
func GetPonPortIDFromUNIPort(uniPortID uint32) uint32 {
	ponPortID := (uniPortID & 0x0FF00000) >> 20
	return ponPortID
}

// ProcessFlowModResultIndication - Processes Flow mod operation indications from controller
func (va *VoltApplication) ProcessFlowModResultIndication(cntx context.Context, flowStatus intf.FlowStatus) {
	d := va.GetDevice(flowStatus.Device)
	if d == nil {
		logger.Errorw(ctx, "Dropping Flow Mod Indication. Device not found", log.Fields{"Cookie": flowStatus.Cookie, "Device": flowStatus.Device})
		return
	}

	cookieExists := ExecuteFlowEvent(cntx, d, flowStatus.Cookie, flowStatus)

	if flowStatus.Flow != nil {
		flowAdd := (flowStatus.FlowModType == of.CommandAdd)
		if !cookieExists && !isFlowStatusSuccess(flowStatus.Status, flowAdd) {
			pushFlowFailureNotif(flowStatus)
		}
	}
}

func pushFlowFailureNotif(flowStatus intf.FlowStatus) {
	subFlow := flowStatus.Flow
	cookie := subFlow.Cookie
	uniPort := cookie >> 16 & 0xFFFFFFFF
	logger.Errorw(ctx, "Flow Failure Notification", log.Fields{"uniPort": uniPort, "Cookie": cookie})
}

// UpdateMvlanProfilesForDevice to update mvlan profile for device
func (va *VoltApplication) UpdateMvlanProfilesForDevice(cntx context.Context, device string) {
	checkAndAddMvlanUpdateTask := func(key, value interface{}) bool {
		mvp := value.(*MvlanProfile)
		if mvp.IsUpdateInProgressForDevice(device) {
			mvp.UpdateProfile(cntx, device)
		}
		return true
	}
	va.MvlanProfilesByName.Range(checkAndAddMvlanUpdateTask)
}

// TaskInfo structure that is used to store the task Info.
type TaskInfo struct {
	ID        string
	Name      string
	Timestamp string
}

// GetTaskList to get task list information.
func (va *VoltApplication) GetTaskList(device string) map[int]*TaskInfo {
	taskList := cntlr.GetController().GetTaskList(device)
	taskMap := make(map[int]*TaskInfo)
	for i, task := range taskList {
		taskID := strconv.Itoa(int(task.TaskID()))
		name := task.Name()
		timestamp := task.Timestamp()
		taskInfo := &TaskInfo{ID: taskID, Name: name, Timestamp: timestamp}
		taskMap[i] = taskInfo
	}
	return taskMap
}

// UpdateDeviceSerialNumberList to update the device serial number list after device serial number is updated for vnet and mvlan
func (va *VoltApplication) UpdateDeviceSerialNumberList(oldOltSlNo string, newOltSlNo string) {
	voltDevice, _ := va.GetDeviceBySerialNo(oldOltSlNo)

	if voltDevice != nil {
		// Device is present with old serial number ID
		logger.Errorw(ctx, "OLT Migration cannot be completed as there are dangling devices", log.Fields{"Serial Number": oldOltSlNo})
	} else {
		logger.Infow(ctx, "No device present with old serial number", log.Fields{"Serial Number": oldOltSlNo})
		// Add Serial Number to Blocked Devices List.
		cntlr.GetController().AddBlockedDevices(oldOltSlNo)
		cntlr.GetController().AddBlockedDevices(newOltSlNo)

		updateSlNoForVnet := func(key, value interface{}) bool {
			vnet := value.(*VoltVnet)
			for i, deviceSlNo := range vnet.VnetConfig.DevicesList {
				if deviceSlNo == oldOltSlNo {
					vnet.VnetConfig.DevicesList[i] = newOltSlNo
					logger.Infow(ctx, "device serial number updated for vnet profile", log.Fields{"Updated Serial Number": deviceSlNo, "Previous Serial Number": oldOltSlNo})
					break
				}
			}
			return true
		}

		updateSlNoforMvlan := func(key interface{}, value interface{}) bool {
			mvProfile := value.(*MvlanProfile)
			for deviceSlNo := range mvProfile.DevicesList {
				if deviceSlNo == oldOltSlNo {
					mvProfile.DevicesList[newOltSlNo] = mvProfile.DevicesList[oldOltSlNo]
					delete(mvProfile.DevicesList, oldOltSlNo)
					logger.Infow(ctx, "device serial number updated for mvlan profile", log.Fields{"Updated Serial Number": deviceSlNo, "Previous Serial Number": oldOltSlNo})
					break
				}
			}
			return true
		}

		va.VnetsByName.Range(updateSlNoForVnet)
		va.MvlanProfilesByName.Range(updateSlNoforMvlan)

		// Clear the serial number from Blocked Devices List
		cntlr.GetController().DelBlockedDevices(oldOltSlNo)
		cntlr.GetController().DelBlockedDevices(newOltSlNo)
	}
}

// GetVpvsForDsPkt to get vpv for downstream packets
func (va *VoltApplication) GetVpvsForDsPkt(cvlan of.VlanType, svlan of.VlanType, clientMAC net.HardwareAddr,
	pbit uint8) ([]*VoltPortVnet, error) {
	var matchVPVs []*VoltPortVnet
	findVpv := func(key, value interface{}) bool {
		vpvs := value.([]*VoltPortVnet)
		for _, vpv := range vpvs {
			if vpv.isVlanMatching(cvlan, svlan) && vpv.MatchesPriority(pbit) != nil {
				var subMac net.HardwareAddr
				if NonZeroMacAddress(vpv.MacAddr) {
					subMac = vpv.MacAddr
				} else if vpv.LearntMacAddr != nil && NonZeroMacAddress(vpv.LearntMacAddr) {
					subMac = vpv.LearntMacAddr
				} else {
					matchVPVs = append(matchVPVs, vpv)
					continue
				}
				if util.MacAddrsMatch(subMac, clientMAC) {
					matchVPVs = append([]*VoltPortVnet{}, vpv)
					logger.Infow(ctx, "Matching VPV found", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "MAC": clientMAC})
					return false
				}
			}
		}
		return true
	}
	va.VnetsByPort.Range(findVpv)

	if len(matchVPVs) != 1 {
		logger.Infow(ctx, "No matching VPV found or multiple vpvs found", log.Fields{"Match VPVs": matchVPVs, "MAC": clientMAC})
		return nil, errors.New("No matching VPV found or multiple vpvs found")
	}
	return matchVPVs, nil
}

// GetMacInPortMap to get PORT value  based on MAC key
func (va *VoltApplication) GetMacInPortMap(macAddr net.HardwareAddr) string {
	if NonZeroMacAddress(macAddr) {
		va.macPortLock.Lock()
		defer va.macPortLock.Unlock()
		if port, ok := va.macPortMap[macAddr.String()]; ok {
			logger.Debugw(ctx, "found-entry-macportmap", log.Fields{"MacAddr": macAddr.String(), "Port": port})
			return port
		}
	}
	logger.Infow(ctx, "entry-not-found-macportmap", log.Fields{"MacAddr": macAddr.String()})
	return ""
}

// UpdateMacInPortMap to update MAC PORT (key value) information in MacPortMap
func (va *VoltApplication) UpdateMacInPortMap(macAddr net.HardwareAddr, port string) {
	if NonZeroMacAddress(macAddr) {
		va.macPortLock.Lock()
		va.macPortMap[macAddr.String()] = port
		va.macPortLock.Unlock()
		logger.Debugw(ctx, "updated-macportmap", log.Fields{"MacAddr": macAddr.String(), "Port": port})
	}
}

// DeleteMacInPortMap to remove MAC key from MacPortMap
func (va *VoltApplication) DeleteMacInPortMap(macAddr net.HardwareAddr) {
	if NonZeroMacAddress(macAddr) {
		port := va.GetMacInPortMap(macAddr)
		va.macPortLock.Lock()
		delete(va.macPortMap, macAddr.String())
		va.macPortLock.Unlock()
		logger.Debugw(ctx, "deleted-from-macportmap", log.Fields{"MacAddr": macAddr.String(), "Port": port})
	}
}

// AddGroupToPendingPool - adds the IgmpGroup with active group table entry to global pending pool
func (va *VoltApplication) AddGroupToPendingPool(ig *IgmpGroup) {
	var grpMap map[*IgmpGroup]bool
	var ok bool

	va.PendingPoolLock.Lock()
	defer va.PendingPoolLock.Unlock()

	logger.Infow(ctx, "Adding IgmpGroup to Global Pending Pool", log.Fields{"GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr, "PendingDevices": len(ig.Devices)})
	// Do Not Reset any current profile info since group table entry tied to mvlan profile
	// The PonVlan is part of set field in group installed
	// Hence, Group created is always tied to the same mvlan profile until deleted

	for device := range ig.Devices {
		key := getPendingPoolKey(ig.Mvlan, device)

		if grpMap, ok = va.IgmpPendingPool[key]; !ok {
			grpMap = make(map[*IgmpGroup]bool)
		}
		grpMap[ig] = true

		//Add grpObj reference to all associated devices
		va.IgmpPendingPool[key] = grpMap
	}
}

// RemoveGroupFromPendingPool - removes the group from global pending group pool
func (va *VoltApplication) RemoveGroupFromPendingPool(device string, ig *IgmpGroup) bool {
	GetApplication().PendingPoolLock.Lock()
	defer GetApplication().PendingPoolLock.Unlock()

	logger.Infow(ctx, "Removing IgmpGroup from Global Pending Pool", log.Fields{"Device": device, "GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr, "PendingDevices": len(ig.Devices)})

	key := getPendingPoolKey(ig.Mvlan, device)
	if _, ok := va.IgmpPendingPool[key]; ok {
		delete(va.IgmpPendingPool[key], ig)
		return true
	}
	return false
}

// RemoveGroupsFromPendingPool - removes the group from global pending group pool
func (va *VoltApplication) RemoveGroupsFromPendingPool(cntx context.Context, device string, mvlan of.VlanType) {
	GetApplication().PendingPoolLock.Lock()
	defer GetApplication().PendingPoolLock.Unlock()

	logger.Infow(ctx, "Removing IgmpGroups from Global Pending Pool for given Deivce & Mvlan", log.Fields{"Device": device, "Mvlan": mvlan.String()})

	key := getPendingPoolKey(mvlan, device)
	va.RemoveGroupListFromPendingPool(cntx, key)
}

// RemoveGroupListFromPendingPool - removes the groups for provided key
// 1. Deletes the group from device
// 2. Delete the IgmpGroup obj and release the group ID to pool
// Note: Make sure to obtain PendingPoolLock lock before calling this func
func (va *VoltApplication) RemoveGroupListFromPendingPool(cntx context.Context, key string) {
	if grpMap, ok := va.IgmpPendingPool[key]; ok {
		delete(va.IgmpPendingPool, key)
		for ig := range grpMap {
			for device := range ig.Devices {
				ig.DeleteIgmpGroupDevice(cntx, device)
			}
		}
	}
}

// RemoveGroupDevicesFromPendingPool - removes the group from global pending group pool
func (va *VoltApplication) RemoveGroupDevicesFromPendingPool(ig *IgmpGroup) {
	logger.Infow(ctx, "Removing IgmpGroup for all devices from Global Pending Pool", log.Fields{"GroupID": ig.GroupID, "GroupName": ig.GroupName, "GroupAddr": ig.GroupAddr, "PendingDevices": len(ig.Devices)})
	for device := range ig.PendingGroupForDevice {
		va.RemoveGroupFromPendingPool(device, ig)
	}
}

// GetGroupFromPendingPool - Returns IgmpGroup obj from global pending pool
func (va *VoltApplication) GetGroupFromPendingPool(mvlan of.VlanType, device string) *IgmpGroup {
	var ig *IgmpGroup

	va.PendingPoolLock.Lock()
	defer va.PendingPoolLock.Unlock()

	key := getPendingPoolKey(mvlan, device)
	logger.Infow(ctx, "Getting IgmpGroup from Global Pending Pool", log.Fields{"Device": device, "Mvlan": mvlan.String(), "Key": key})

	// Gets all IgmpGrp Obj for the device
	grpMap, ok := va.IgmpPendingPool[key]
	if !ok || len(grpMap) == 0 {
		logger.Infow(ctx, "Matching IgmpGroup not found in Global Pending Pool", log.Fields{"Device": device, "Mvlan": mvlan.String()})
		return nil
	}

	// Gets a random obj from available grps
	for ig = range grpMap {
		// Remove grp obj reference from all devices associated in pending pool
		for dev := range ig.Devices {
			key := getPendingPoolKey(mvlan, dev)
			delete(va.IgmpPendingPool[key], ig)
		}

		// Safety check to avoid re-allocating group already in use
		if ig.NumDevicesActive() == 0 {
			return ig
		}

		// Iteration will continue only if IG is not allocated
	}
	return nil
}

// RemovePendingGroups - removes all pending groups for provided reference from global pending pool
// reference - mvlan/device ID
// isRefDevice - true  - Device as reference
// false - Mvlan as reference
func (va *VoltApplication) RemovePendingGroups(cntx context.Context, reference string, isRefDevice bool) {
	va.PendingPoolLock.Lock()
	defer va.PendingPoolLock.Unlock()

	logger.Infow(ctx, "Removing IgmpGroups from Global Pending Pool", log.Fields{"Reference": reference, "isRefDevice": isRefDevice})

	// Pending Pool key: "<mvlan>_<DeviceID>""
	paramPosition := 0
	if isRefDevice {
		paramPosition = 1
	}

	// 1.Remove the Entry from pending pool
	// 2.Deletes the group from device
	// 3.Delete the IgmpGroup obj and release the group ID to pool
	for key := range va.IgmpPendingPool {
		keyParams := strings.Split(key, "_")
		if keyParams[paramPosition] == reference {
			va.RemoveGroupListFromPendingPool(cntx, key)
		}
	}
}

func getPendingPoolKey(mvlan of.VlanType, device string) string {
	return mvlan.String() + "_" + device
}

func (va *VoltApplication) removeExpiredGroups(cntx context.Context) {
	logger.Debug(ctx, "Check for expired Igmp Groups")
	removeExpiredGroups := func(key interface{}, value interface{}) bool {
		ig := value.(*IgmpGroup)
		ig.removeExpiredGroupFromDevice(cntx)
		return true
	}
	va.IgmpGroups.Range(removeExpiredGroups)
}

// TriggerPendingProfileDeleteReq - trigger pending profile delete request
func (va *VoltApplication) TriggerPendingProfileDeleteReq(cntx context.Context, device string) {
       va.TriggerPendingServiceDeactivateReq(cntx, device)
	va.TriggerPendingServiceDeleteReq(cntx, device)
	va.TriggerPendingVpvDeleteReq(cntx, device)
	va.TriggerPendingVnetDeleteReq(cntx, device)
	logger.Warnw(ctx, "All Pending Profile Delete triggered for device", log.Fields{"Device": device})
}

// TriggerPendingServiceDeactivateReq - trigger pending service deactivate request
func (va *VoltApplication) TriggerPendingServiceDeactivateReq(cntx context.Context, device string) {
       logger.Infow(ctx, "Pending Services to be deactivated", log.Fields{"Count": len(va.ServicesToDeactivate)})
       for serviceName := range va.ServicesToDeactivate {
               logger.Infow(ctx, "Trigger Service Deactivate", log.Fields{"Service": serviceName})
               if vs := va.GetService(serviceName); vs != nil {
                       if vs.Device == device {
                               logger.Warnw(ctx, "Triggering Pending Service Deactivate", log.Fields{"Service": vs.Name})
                               vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan)
                               if vpv == nil {
                                       logger.Errorw(ctx, "Vpv Not found for Service", log.Fields{"vs": vs.Name, "port": vs.Port, "Vnet": vs.VnetID})
                                       continue
                               }

                               vpv.DelTrapFlows(cntx)
                               vs.DelHsiaFlows(cntx)
                               vs.WriteToDb(cntx)
                               vpv.ClearServiceCounters(cntx)
                       }
               } else {
                       logger.Errorw(ctx, "Pending Service Not found", log.Fields{"Service": serviceName})
               }
       }
}

// TriggerPendingServiceDeleteReq - trigger pending service delete request
func (va *VoltApplication) TriggerPendingServiceDeleteReq(cntx context.Context, device string) {
	logger.Warnw(ctx, "Pending Services to be deleted", log.Fields{"Count": len(va.ServicesToDelete)})
	for serviceName := range va.ServicesToDelete {
		logger.Debugw(ctx, "Trigger Service Delete", log.Fields{"Service": serviceName})
		if vs := va.GetService(serviceName); vs != nil {
			if vs.Device == device {
				logger.Warnw(ctx, "Triggering Pending Service delete", log.Fields{"Service": vs.Name})
				vs.DelHsiaFlows(cntx)
				if vs.ForceDelete {
					vs.DelFromDb(cntx)
				}
			}
		} else {
			logger.Errorw(ctx, "Pending Service Not found", log.Fields{"Service": serviceName})
		}
	}
}

// TriggerPendingVpvDeleteReq - trigger pending VPV delete request
func (va *VoltApplication) TriggerPendingVpvDeleteReq(cntx context.Context, device string) {
	logger.Warnw(ctx, "Pending VPVs to be deleted", log.Fields{"Count": len(va.VoltPortVnetsToDelete)})
	for vpv := range va.VoltPortVnetsToDelete {
		if vpv.Device == device {
			logger.Warnw(ctx, "Triggering Pending VPv flow delete", log.Fields{"Port": vpv.Port, "Device": vpv.Device, "Vnet": vpv.VnetName})
			va.DelVnetFromPort(cntx, vpv.Port, vpv)
		}
	}
}

// TriggerPendingVnetDeleteReq - trigger pending vnet delete request
func (va *VoltApplication) TriggerPendingVnetDeleteReq(cntx context.Context, device string) {
	logger.Warnw(ctx, "Pending Vnets to be deleted", log.Fields{"Count": len(va.VnetsToDelete)})
	for vnetName := range va.VnetsToDelete {
		if vnetIntf, _ := va.VnetsByName.Load(vnetName); vnetIntf != nil {
			vnet := vnetIntf.(*VoltVnet)
			logger.Warnw(ctx, "Triggering Pending Vnet flows delete", log.Fields{"Vnet": vnet.Name})
			if d, _ := va.GetDeviceBySerialNo(vnet.PendingDeviceToDelete); d != nil && d.SerialNum == vnet.PendingDeviceToDelete {
				va.DeleteDevFlowForVlanFromDevice(cntx, vnet, vnet.PendingDeviceToDelete)
				va.deleteVnetConfig(vnet)
			} else {
				logger.Warnw(ctx, "Vnet Delete Failed : Device Not Found", log.Fields{"Vnet": vnet.Name, "Device": vnet.PendingDeviceToDelete})
			}
		}
	}
}

type OltFlowService struct {
	DefaultTechProfileID int  `json:"defaultTechProfileId"`
	EnableDhcpOnNni      bool `json:"enableDhcpOnNni"`
	EnableIgmpOnNni      bool `json:"enableIgmpOnNni"`
	EnableEapol          bool `json:"enableEapol"`
	EnableDhcpV6         bool `json:"enableDhcpV6"`
	EnableDhcpV4         bool `json:"enableDhcpV4"`
	RemoveFlowsOnDisable bool `json:"removeFlowsOnDisable"`
}

func (va *VoltApplication) UpdateOltFlowService(cntx context.Context, oltFlowService OltFlowService) {
	logger.Infow(ctx, "UpdateOltFlowService", log.Fields{"oldValue": va.OltFlowServiceConfig, "newValue": oltFlowService})
	va.OltFlowServiceConfig = oltFlowService
	b, err := json.Marshal(va.OltFlowServiceConfig)
	if err != nil {
		logger.Warnw(ctx, "Failed to Marshal OltFlowServiceConfig", log.Fields{"OltFlowServiceConfig": va.OltFlowServiceConfig})
		return
	}
	_ = db.PutOltFlowService(cntx, string(b))
}

// RestoreOltFlowService to read from the DB and restore olt flow service config
func (va *VoltApplication) RestoreOltFlowService(cntx context.Context) {
	oltflowService, err := db.GetOltFlowService(cntx)
	if err != nil {
		logger.Warnw(ctx, "Failed to Get OltFlowServiceConfig from DB", log.Fields{"Error": err})
		return
	}
	err = json.Unmarshal([]byte(oltflowService), &va.OltFlowServiceConfig)
	if err != nil {
		logger.Warn(ctx, "Unmarshal of oltflowService failed")
		return
	}
	logger.Infow(ctx, "updated OltFlowServiceConfig from DB", log.Fields{"OltFlowServiceConfig": va.OltFlowServiceConfig})
}

func (va *VoltApplication) UpdateDeviceConfig(cntx context.Context, deviceConfig *DeviceConfig) {
	var dc *DeviceConfig
	va.DevicesConfig.Store(deviceConfig.SerialNumber, deviceConfig)
	err := dc.WriteDeviceConfigToDb(cntx, deviceConfig.SerialNumber, deviceConfig)
	if err != nil {
		logger.Errorw(ctx, "DB update for device config failed", log.Fields{"err": err})
	}
	logger.Infow(ctx, "Added OLT configurations", log.Fields{"DeviceInfo": deviceConfig})
	// If device is already discovered update the VoltDevice structure
	device, id := va.GetDeviceBySerialNo(deviceConfig.SerialNumber)
	if device != nil {
		device.NniDhcpTrapVid = of.VlanType(deviceConfig.NniDhcpTrapVid)
		va.DevicesDisc.Store(id, device)
	}
}
