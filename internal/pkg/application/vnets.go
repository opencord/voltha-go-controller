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
	"net"
	"strconv"
	"sync"
	"time"

	//errorCodes "voltha-go-controller/internal/pkg/errorcodes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/atomic"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/controller"
	cntlr "voltha-go-controller/internal/pkg/controller"

	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

const (
	// ICMPv6ArpGroupID constant
	ICMPv6ArpGroupID uint32 = 1

	// Radisys vendor id constant
	Radisys string = "Radisys"

	// DPU_MGMT_TRAFFIC serviceType, vnetType constant
	DpuMgmtTraffic string = "DPU_MGMT_TRAFFIC"

	// DPU_ANCP_TRAFFIC serviceType, vnetType constant
	DpuAncpTraffic string = "DPU_ANCP_TRAFFIC"

	// FTTB_SUBSCRIBER_TRAFFIC serviceType, vnetType constant
	FttbSubscriberTraffic string = "FTTB_SUBSCRIBER_TRAFFIC"
)

var (
	//BroadcastMAC - Broadcast MAC Address
	BroadcastMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
)

// NonZeroMacAddress utility to identify if the MAC address is non-zero.
// We use zero MAC address as an unset MAC address
func NonZeroMacAddress(h net.HardwareAddr) bool {
	for i := 0; i < 6; i++ {
		if h[i] != 0 {
			return true
		}
	}
	return false
}

// VNET package manages the different virtual networks that are part of the
// the network. In the case of VOLT, the networks can be single tagged or
// double tagged networks. In addition, the networks may be used for unicast
// and multicast traffic. The unicast traffic further has two models, the
// 1:1 and N:1 model. In case of a 1:1 model, the outer tag is same for many
// subscribers and the inner tag is unique to each subscriber for the same
// outer tag. The N:1 uses the same inner and outer tags, or for that matter
// a single tag that can also be shared by subscribers. The VNET implementation
// manages all these possibilities and the associated configuration.

const (
	// PbitMatchNone constant
	PbitMatchNone of.PbitType = 8
	// PbitMatchAll constant
	PbitMatchAll of.PbitType = 0xFF
)

// SVlan        - Value of the outer tag if double tagged or the only tag if single
//                tagged
// SVlanTpid    - SVlan Tag Protocol Identifier
// CVlan        - Value of the inner tag. Set to VlanNone if single tagged
// DhcpRelay    - Set to true if the DHCP relay is enabled on the virtual network
// MacLearning  - Set to true if the flows should include MAC address
// UsDhcpPbit   - The pbit used for US DHCP packets
// DsDhcpPbit   - The pbit used for DS DHCP packets

// VnetConfig structure
type VnetConfig struct {
	CtrlPktPbitRemark          map[of.PbitType]of.PbitType
	Name                       string
	VnetType                   string
	Encapsulation              string
	DevicesList                []string //List of serial number of devices on which this vnet is applied
	UsDhcpPbit                 []of.PbitType
	DsDhcpPbit                 []of.PbitType
	UsIGMPPbit                 []of.PbitType
	DsIGMPPbit                 []of.PbitType
	ONTEtherTypeClassification int
	MacLearning                MacLearningType
	UsPonCTagPriority          of.PbitType
	UsPonSTagPriority          of.PbitType
	DsPonCTagPriority          of.PbitType
	DsPonSTagPriority          of.PbitType
	SVlan                      of.VlanType
	CVlan                      of.VlanType
	UniVlan                    of.VlanType
	SVlanTpid                  layers.EthernetType
	VlanControl                VlanControl
	DhcpRelay                  bool
	ArpLearning                bool
	AllowTransparent           bool
	PppoeIa                    bool
}

// VnetOper structure
type VnetOper struct {
	PendingDeleteFlow     map[string]map[string]bool
	AssociatedPorts       map[string]bool `json:"-"`
	PendingDeviceToDelete string
	VnetLock              sync.RWMutex `json:"-"`
	VnetPortLock          sync.RWMutex `json:"-"`
	DeleteInProgress      bool
}

// VoltVnet sructure
type VoltVnet struct {
	Version string
	VnetConfig
	VnetOper
}

const (
	// EncapsulationPPPoEIA constant
	EncapsulationPPPoEIA string = "PPPoE-IA"
	// EncapsulationPPPoE constant
	EncapsulationPPPoE string = "PPPoE"
	// EncapsulationIPoE constant
	EncapsulationIPoE string = "IPoE"
)

// NewVoltVnet is constructor for the VNET structure
func NewVoltVnet(cfg VnetConfig) *VoltVnet {
	var vv VoltVnet
	vv.VnetConfig = cfg
	if vv.PendingDeleteFlow == nil {
		vv.PendingDeleteFlow = make(map[string]map[string]bool)
	}
	vv.DeleteInProgress = false
	if cfg.Encapsulation == EncapsulationPPPoEIA {
		vv.PppoeIa = true
	}
	vv.AssociatedPorts = make(map[string]bool)
	return &vv
}

// associatePortToVnet - associate a port to Vnet
func (vv *VoltVnet) associatePortToVnet(port string) {
	vv.VnetPortLock.Lock()
	if vv.AssociatedPorts == nil {
		vv.AssociatedPorts = make(map[string]bool)
	}
	vv.AssociatedPorts[port] = true
	vv.VnetPortLock.Unlock()
}

// disassociatePortFromVnet - disassociate a port from Vnet and return true if the association map is empty
func (vv *VoltVnet) disassociatePortFromVnet(cntx context.Context, device string, port string) {
	vv.VnetPortLock.Lock()
	delete(vv.AssociatedPorts, port)
	logger.Infow(ctx, "Disassociated Port from Vnet", log.Fields{"Device": device, "Port": port, "Vnet": vv.Name, "PendingDeleteFlow": vv.PendingDeleteFlow, "AssociatedPorts": vv.AssociatedPorts, "DeleteFlag": vv.DeleteInProgress})
	vv.VnetPortLock.Unlock()

	if vv.DeleteInProgress {
		if !vv.isAssociatedPortsPresent() {
			if len(vv.PendingDeleteFlow[device]) == 0 {
				logger.Warnw(ctx, "Deleting Vnet", log.Fields{"Name": vv.Name})
				GetApplication().deleteVnetConfig(vv)
				_ = db.DelVnet(cntx, vv.Name)
			} else {
				logger.Warnw(ctx, "Skipping Del Vnet", log.Fields{"Name": vv.Name, "PendingDeleteFlow": vv.PendingDeleteFlow})
			}
		} else {
			vv.VnetPortLock.RLock()
			logger.Warnw(ctx, "Skipping Del Vnet", log.Fields{"Name": vv.Name, "AssociatedPorts": vv.AssociatedPorts})
			vv.VnetPortLock.RUnlock()
		}
	}
}

func (vv *VoltVnet) isAssociatedPortsPresent() bool {
	vv.VnetPortLock.RLock()
	defer vv.VnetPortLock.RUnlock()
	return len(vv.AssociatedPorts) != 0
}

// WriteToDb commit the VNET to the database
func (vv *VoltVnet) WriteToDb(cntx context.Context) {
	if vv.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Redis Update for Vnet, Vnet delete in progress", log.Fields{"Vnet": vv.Name})
		return
	}
	vv.ForceWriteToDb(cntx)
}

// ForceWriteToDb force commit a vnet to the DB
func (vv *VoltVnet) ForceWriteToDb(cntx context.Context) {
	vv.VnetPortLock.RLock()
	defer vv.VnetPortLock.RUnlock()
	vv.Version = database.PresentVersionMap[database.VnetPath]
	logger.Debugw(ctx, "Updating VNET....", log.Fields{"vnet": vv})
	if b, err := json.Marshal(vv); err == nil {
		if err := db.PutVnet(cntx, vv.Name, string(b)); err != nil {
			logger.Warnw(ctx, "Add Vnet to DB failed", log.Fields{"vnet name": vv.Name, "Error": err})
		}
	}
}

// VnetKey creates the key using the two VLAN tags
// We append the two VLAN tags to create a single key
func VnetKey(otag of.VlanType, itag of.VlanType, utag of.VlanType) string {
	return strconv.Itoa(int(otag)) + "-" + strconv.Itoa(int(itag)) + "-" + strconv.Itoa(int(utag))
}

// GetVnet get VNET configuration related functionality associated with VOLT application
func (va *VoltApplication) GetVnet(otag of.VlanType, itag of.VlanType, utag of.VlanType) *VoltVnet {
	// When matching VNET, it is expected to match first just the outer
	// tag, and then the combination to make sure there is no conflict
	// for the new configuration.
	if vnet, ok := va.VnetsByTag.Load(VnetKey(otag, of.VlanNone, utag)); ok {
		return vnet.(*VoltVnet)
	}
	if vnet, ok := va.VnetsByTag.Load(VnetKey(otag, itag, utag)); ok {
		return vnet.(*VoltVnet)
	}
	return nil
}

// The VNET may also be assigned name for easier references. For now,
// the VNET is mainly identified by the two VLANs.

// GetVnetByName to get vnet by name
func (va *VoltApplication) GetVnetByName(name string) *VoltVnet {
	if vnet, ok := va.VnetsByName.Load(name); ok {
		return vnet.(*VoltVnet)
	}
	return nil
}

// storeVnetConfig to store vnet config
func (va *VoltApplication) storeVnetConfig(cfg VnetConfig, vv *VoltVnet) {
	var vnetMap *util.ConcurrentMap

	va.VnetsByTag.Store(VnetKey(cfg.SVlan, cfg.CVlan, cfg.UniVlan), vv)
	va.VnetsByName.Store(cfg.Name, vv)

	if vnetMapIntf, ok := va.VnetsBySvlan.Get(vv.SVlan); !ok {
		vnetMap = util.NewConcurrentMap()
	} else {
		vnetMap = vnetMapIntf.(*util.ConcurrentMap)
	}
	vnetMap.Set(vv, true)
	va.VnetsBySvlan.Set(vv.SVlan, vnetMap)
}

// deleteVnetConfig to delete vnet config
func (va *VoltApplication) deleteVnetConfig(vnet *VoltVnet) {
	va.VnetsByTag.Delete(VnetKey(vnet.SVlan, vnet.CVlan, vnet.UniVlan))
	va.VnetsByName.Delete(vnet.Name)

	if vnetMapIntf, ok := va.VnetsBySvlan.Get(vnet.SVlan); ok {
		vnetMap := vnetMapIntf.(*util.ConcurrentMap)
		vnetMap.Remove(vnet)
		va.VnetsBySvlan.Set(vnet.SVlan, vnetMap)
	}
}

// AddVnet to add a VNET to the list of VNETs configured.
func (va *VoltApplication) AddVnet(cntx context.Context, cfg VnetConfig, oper *VnetOper) error {
	AppMutex.VnetMutex.Lock()
	var vv *VoltVnet
	devicesToHandle := []string{}
	vv = va.GetVnetByName(cfg.Name)
	if vv != nil {
		//Could be for another OLT or could be case of backup-restore
		for _, serialNum := range cfg.DevicesList {
			if isDeviceInList(serialNum, vv.DevicesList) {
				//This is backup restore scenario, just update the profile
				logger.Info(ctx, "Add Vnet : Profile Name already exists with OLT, update-the-profile")
				continue
			}
			devicesToHandle = append(devicesToHandle, serialNum)
		}
		if len(devicesToHandle) == 0 {
			logger.Debugw(ctx, "Ignoring Duplicate VNET by name ", log.Fields{"Vnet": cfg.Name})
			AppMutex.VnetMutex.Unlock()
			return nil
		}
	}

	if vv == nil {
		vv = NewVoltVnet(cfg)
		if oper != nil {
			vv.PendingDeleteFlow = oper.PendingDeleteFlow
			vv.DeleteInProgress = oper.DeleteInProgress
			vv.AssociatedPorts = oper.AssociatedPorts
			vv.PendingDeviceToDelete = oper.PendingDeviceToDelete
		}
		devicesToHandle = append(devicesToHandle, cfg.DevicesList...)
	} else {
		vv.DevicesList = append(vv.DevicesList, devicesToHandle...)
	}

	va.storeVnetConfig(cfg, vv)
	vv.WriteToDb(cntx)

	logger.Infow(ctx, "Added VNET TO DB", log.Fields{"cfg": cfg, "devicesToHandle": devicesToHandle})

	//va.PushDevFlowForVlan(vv)
	AppMutex.VnetMutex.Unlock()
	return nil
}

// DelVnet to delete a VNET from the list of VNETs configured
func (va *VoltApplication) DelVnet(cntx context.Context, name, deviceSerialNum string) error {
	logger.Infow(ctx, "Deleting Vnet", log.Fields{"Vnet": name})
	AppMutex.VnetMutex.Lock()
	if vnetIntf, ok := va.VnetsByName.Load(name); ok {
		vnet := vnetIntf.(*VoltVnet)
		// Delete from mvp list
		vnet.DevicesList = util.RemoveFromSlice(vnet.DevicesList, deviceSerialNum)

		va.DeleteDevFlowForVlanFromDevice(cntx, vnet, deviceSerialNum)
		if len(vnet.DevicesList) == 0 {
			vnet.DeleteInProgress = true
			vnet.PendingDeviceToDelete = deviceSerialNum
			vnet.ForceWriteToDb(cntx)
			vnet.VnetPortLock.RLock()
			if len(vnet.PendingDeleteFlow) == 0 && !vnet.isAssociatedPortsPresent() {
				logger.Warnw(ctx, "Deleting Vnet", log.Fields{"Name": vnet.Name, "AssociatedPorts": vnet.AssociatedPorts, "PendingDelFlows": vnet.PendingDeleteFlow})
				va.deleteVnetConfig(vnet)
				_ = db.DelVnet(cntx, vnet.Name)
			} else {
				logger.Warnw(ctx, "Skipping Del Vnet", log.Fields{"Name": vnet.Name, "AssociatedPorts": vnet.AssociatedPorts, "PendingDelFlows": vnet.PendingDeleteFlow})
			}
			vnet.VnetPortLock.RUnlock()
		} else {
			// Update the devicelist in db
			vnet.WriteToDb(cntx)
		}
	}
	// TODO: if no vnets are present on device remove icmpv6 group from device
	AppMutex.VnetMutex.Unlock()
	return nil
}

// UpdateVnet to update the VNET with associated service count
func (va *VoltApplication) UpdateVnet(cntx context.Context, vv *VoltVnet) error {
	va.storeVnetConfig(vv.VnetConfig, vv)
	vv.WriteToDb(cntx)
	logger.Infow(ctx, "Updated VNET TO DB", log.Fields{"vv": vv.VnetConfig})
	return nil
}

// ------------------------------------------------------------
// Manifestation of a VNET on a port is handled below
// ------------------------------------------------------------
//
// The VNET on a port handles everything that is done for a VNET
// such as DHCP relay state machine, MAC addresses, IP addresses
// learnt, so on.

// DhcpStatus type
type DhcpStatus uint8

const (
	// DhcpStatusNone constant
	DhcpStatusNone DhcpStatus = 0
	// DhcpStatusAcked constant
	DhcpStatusAcked DhcpStatus = 1
	// DhcpStatusNacked constant
	DhcpStatusNacked DhcpStatus = 2
	// EthTypeNone constant
	EthTypeNone int = 0
	// EthTypeIPoE constant
	EthTypeIPoE int = 1
	// EthTypePPPoE constant
	EthTypePPPoE int = 2
)

// VoltPortVnet structure
type VoltPortVnet struct {
	PendingDeleteFlow          map[string]bool
	servicesCount              *atomic.Uint64
	services                   sync.Map
	Device                     string
	Port                       string
	VnetName                   string
	VnetType                   string
	MvlanProfileName           string
	Version                    string
	DhcpExpiryTime             time.Time
	Dhcp6ExpiryTime            time.Time
	Ipv4Addr                   net.IP
	Ipv6Addr                   net.IP
	MacAddr                    net.HardwareAddr
	LearntMacAddr              net.HardwareAddr
	CircuitID                  []byte       //Will not be used
	RemoteID                   []byte       //Will not be used
	VpvLock                    sync.Mutex   `json:"-"`
	PendingFlowLock            sync.RWMutex `json:"-"`
	SchedID                    int
	ONTEtherTypeClassification int
	MacLearning                MacLearningType
	PonPort                    uint32
	McastUsMeterID             uint32
	McastTechProfileID         uint16
	McastPbit                  of.PbitType
	SVlanTpid                  layers.EthernetType
	DhcpPbit                   of.PbitType
	UsPonCTagPriority          of.PbitType
	UsPonSTagPriority          of.PbitType
	DsPonCTagPriority          of.PbitType
	DsPonSTagPriority          of.PbitType
	SVlan                      of.VlanType
	CVlan                      of.VlanType
	UniVlan                    of.VlanType
	VlanControl                VlanControl
	RelayState                 DhcpRelayState
	DhcpStatus                 DhcpStatus
	PPPoeState                 PppoeIaState
	RelayStatev6               Dhcpv6RelayState
	DHCPv6DUID                 [MaxLenDhcpv6DUID]byte
	DhcpRelay                  bool
	ArpRelay                   bool
	PppoeIa                    bool
	DeleteInProgress           bool
	Blocked                    bool
	AllowTransparent           bool
	IgmpEnabled                bool
	IgmpFlowsApplied           bool
	McastService               bool
	FlowsApplied               bool
	IsOption82Disabled         bool //Will not be used
}

// VlanControl vlan control type
type VlanControl uint8

const (
	// None constant
	// ONU and OLT will passthrough UNIVLAN as is to BNG
	None VlanControl = iota

	// ONUCVlanOLTSVlan constant
	// Tagged traffic, ONU will replace UNIVLAN with CVLAN and OLT will add SVLAN
	// Untagged traffic, ONU will add CVLAN and OLT will add SVLAN
	ONUCVlanOLTSVlan

	// OLTCVlanOLTSVlan constant
	// Tagged traffic, ONU will passthrough UNIVLAN as is to OLT and
	// OLT will replace UNIVLAN with CVLAN and add SVLAN
	OLTCVlanOLTSVlan

	// ONUCVlan constant
	// Tagged traffic, ONU will replace UNIVLAN with CVLAN
	// Untagged traffic, ONU will add CVLAN
	ONUCVlan

	// OLTSVlan constant
	// UnTagged traffic, OLT will add the SVLAN
	OLTSVlan
)

// NewVoltPortVnet is constructor for VoltPortVnet
func NewVoltPortVnet(vnet *VoltVnet) *VoltPortVnet {
	var vpv VoltPortVnet

	vpv.VnetName = vnet.Name
	vpv.SVlan = vnet.SVlan
	vpv.CVlan = vnet.CVlan
	vpv.UniVlan = vnet.UniVlan
	vpv.SVlanTpid = vnet.SVlanTpid
	vpv.DhcpRelay = vnet.DhcpRelay
	vpv.DhcpStatus = DhcpStatusNone
	vpv.PPPoeState = PppoeIaStateNone
	vpv.ArpRelay = vnet.ArpLearning
	vpv.PppoeIa = vnet.PppoeIa
	vpv.VlanControl = vnet.VlanControl
	vpv.ONTEtherTypeClassification = vnet.ONTEtherTypeClassification
	vpv.AllowTransparent = vnet.AllowTransparent
	vpv.FlowsApplied = false
	vpv.IgmpEnabled = false
	vpv.MacAddr, _ = net.ParseMAC("00:00:00:00:00:00")
	vpv.LearntMacAddr, _ = net.ParseMAC("00:00:00:00:00:00")
	vpv.servicesCount = atomic.NewUint64(0)
	vpv.SchedID = 0
	vpv.PendingDeleteFlow = make(map[string]bool)
	vpv.DhcpPbit = vnet.UsDhcpPbit[0]
	vpv.UsPonCTagPriority = vnet.UsPonCTagPriority
	vpv.UsPonSTagPriority = vnet.UsPonSTagPriority
	vpv.DsPonCTagPriority = vnet.UsPonCTagPriority
	vpv.DsPonSTagPriority = vnet.UsPonSTagPriority

	vpv.VnetType = vnet.VnetType
	return &vpv
}

func (vpv *VoltPortVnet) setDevice(device string) {
	if vpv.Device != device && vpv.Device != "" {
		GetApplication().DisassociateVpvsFromDevice(device, vpv)
		// TEMP:
		vpv.printAssociatedVPVs(false)
	}

	logger.Infow(ctx, "Associating VPV and Device", log.Fields{"Device": device, "Port": vpv.Port, "SVlan": vpv.SVlan})

	vpv.Device = device
	GetApplication().AssociateVpvsToDevice(device, vpv)
	// TEMP:
	vpv.printAssociatedVPVs(true)
}

// TODO - Nav - Temp
func (vpv *VoltPortVnet) printAssociatedVPVs(add bool) {
	logger.Infow(ctx, "Start----Printing all associated VPV", log.Fields{"Device": vpv.Device, "Add": add})
	if vMap := GetApplication().GetAssociatedVpvsForDevice(vpv.Device, vpv.SVlan); vMap != nil {
		vMap.Range(func(key, value interface{}) bool {
			vpvEntry := key.(*VoltPortVnet)
			logger.Infow(ctx, "Associated VPVs", log.Fields{"SVlan": vpvEntry.SVlan, "CVlan": vpvEntry.CVlan, "UniVlan": vpvEntry.UniVlan})
			return true
		})
	}
	logger.Infow(ctx, "End----Printing all associated VPV", log.Fields{"Device": vpv.Device, "Add": add})
}

// GetCircuitID : The interface to be satisfied by the VoltPortVnet to be a DHCP relay
// session is implemented below. The main functions still remain in
// the service.go file.
func (vpv *VoltPortVnet) GetCircuitID() []byte {
	return []byte(vpv.CircuitID)
}

// GetRemoteID to get remote id
func (vpv *VoltPortVnet) GetRemoteID() []byte {
	return []byte(vpv.RemoteID)
}

// GetDhcpState to get dhcp state
func (vpv *VoltPortVnet) GetDhcpState() DhcpRelayState {
	return vpv.RelayState
}

// SetDhcpState to set the dhcp state
func (vpv *VoltPortVnet) SetDhcpState(state DhcpRelayState) {
	vpv.RelayState = state
}

// GetPppoeIaState to get pppoeia state
func (vpv *VoltPortVnet) GetPppoeIaState() PppoeIaState {
	return vpv.PPPoeState
}

// SetPppoeIaState to set pppoeia state
func (vpv *VoltPortVnet) SetPppoeIaState(state PppoeIaState) {
	vpv.PPPoeState = state
}

// GetDhcpv6State to get dhcpv6 state
func (vpv *VoltPortVnet) GetDhcpv6State() Dhcpv6RelayState {
	return vpv.RelayStatev6
}

// SetDhcpv6State to set dhcpv6 state
func (vpv *VoltPortVnet) SetDhcpv6State(state Dhcpv6RelayState) {
	vpv.RelayStatev6 = state
}

// DhcpResultInd for dhcp result indication
func (vpv *VoltPortVnet) DhcpResultInd(cntx context.Context, res *layers.DHCPv4) {
	vpv.ProcessDhcpResult(cntx, res)
}

// Dhcpv6ResultInd for dhcpv6 result indication
func (vpv *VoltPortVnet) Dhcpv6ResultInd(cntx context.Context, ipv6Addr net.IP, leaseTime uint32) {
	vpv.ProcessDhcpv6Result(cntx, ipv6Addr, leaseTime)
}

// GetNniVlans to get nni vlans
func (vpv *VoltPortVnet) GetNniVlans() (uint16, uint16) {
	switch vpv.VlanControl {
	case ONUCVlanOLTSVlan,
		OLTCVlanOLTSVlan:
		return uint16(vpv.SVlan), uint16(vpv.CVlan)
	case ONUCVlan,
		None:
		return uint16(vpv.SVlan), uint16(of.VlanNone)
	case OLTSVlan:
		return uint16(vpv.SVlan), uint16(of.VlanNone)
	}
	return uint16(of.VlanNone), uint16(of.VlanNone)
}

// GetService to get service
func (vpv *VoltPortVnet) GetService(name string) (*VoltService, bool) {
	service, ok := vpv.services.Load(name)
	if ok {
		return service.(*VoltService), ok
	}
	return nil, ok
}

// AddService to add service
func (vpv *VoltPortVnet) AddService(cntx context.Context, service *VoltService) {
	vpv.services.Store(service.Name, service)
	vpv.servicesCount.Inc()
	logger.Infow(ctx, "Service added/updated to VPV", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "Service": service.Name, "Count": vpv.servicesCount.Load()})
}

// DelService to delete service
func (vpv *VoltPortVnet) DelService(cntx context.Context, service *VoltService) {
	vpv.services.Delete(service.Name)
	vpv.servicesCount.Dec()

	// If the only Igmp Enabled service is removed, remove the Igmp trap flow along with it
	if service.IgmpEnabled {
		if err := vpv.DelIgmpFlows(cntx); err != nil {
			statusCode, statusMessage := errorCodes.GetErrorInfo(err)
			vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		}

		vpv.IgmpEnabled = false
	}
	logger.Infow(ctx, "Service deleted from VPV", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "Service": service.Name, "Count": vpv.servicesCount.Load()})
}

// ProcessDhcpResult to process dhcp results
func (vpv *VoltPortVnet) ProcessDhcpResult(cntx context.Context, res *layers.DHCPv4) {
	msgType := DhcpMsgType(res)
	if msgType == layers.DHCPMsgTypeAck {
		vpv.ProcessDhcpSuccess(cntx, res)
	} else if msgType == layers.DHCPMsgTypeNak {
		vpv.DhcpStatus = DhcpStatusNacked
	}
	vpv.WriteToDb(cntx)
}

// RangeOnServices to call a function on all services on the vpv
func (vpv *VoltPortVnet) RangeOnServices(cntx context.Context, callback func(cntx context.Context, key, value interface{}) bool) {
	vpv.services.Range(func(key, value interface{}) bool {
		return callback(cntx, key, value)
	})
}

// ProcessDhcpSuccess : Learn the IPv4 address allocated to the services and update the
// the services with the same. This also calls for adding flows
// for the services as the DHCP procedure is completed
func (vpv *VoltPortVnet) ProcessDhcpSuccess(cntx context.Context, res *layers.DHCPv4) {
	vpv.DhcpStatus = DhcpStatusAcked
	vpv.Ipv4Addr, _ = GetIpv4Addr(res)
	logger.Infow(ctx, "Received IPv4 Address", log.Fields{"IP Address": vpv.Ipv4Addr.String()})
	logger.Infow(ctx, "Services Configured", log.Fields{"Count": vpv.servicesCount.Load()})

	vpv.RangeOnServices(cntx, vpv.updateIPv4AndProvisionFlows)
	vpv.ProcessDhcpv4Options(res)
}

// ProcessDhcpv4Options : Currently we process lease time and store the validity of the
// IP address allocated.
func (vpv *VoltPortVnet) ProcessDhcpv4Options(res *layers.DHCPv4) {
	for _, o := range res.Options {
		switch o.Type {
		case layers.DHCPOptLeaseTime:
			leasetime := GetIPv4LeaseTime(o)
			vpv.DhcpExpiryTime = time.Now().Add((time.Duration(leasetime) * time.Second))
			logger.Infow(ctx, "Lease Expiry Set", log.Fields{"Time": vpv.DhcpExpiryTime})
		}
	}
}

// ProcessDhcpv6Result : Read the IPv6 address allocated to the device and store it on the
// VNET. The same IPv6 address is also passed to the services. When a
// service is fetched all the associated information such as MAC address,
// IPv4 address and IPv6 addresses can be provided.
func (vpv *VoltPortVnet) ProcessDhcpv6Result(cntx context.Context, ipv6Addr net.IP, leaseTime uint32) {
	// TODO: Status based hanlding of flows
	vpv.Dhcp6ExpiryTime = time.Now().Add((time.Duration(leaseTime) * time.Second))
	vpv.Ipv6Addr = ipv6Addr

	vpv.RangeOnServices(cntx, vpv.updateIPv6AndProvisionFlows)
	vpv.WriteToDb(cntx)
}

// AddSvcUsMeterToDevice to add service upstream meter info to device
func AddSvcUsMeterToDevice(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	logger.Infow(ctx, "Adding upstream meter profile to device", log.Fields{"ServiceName": svc.Name})
	if device, _ := GetApplication().GetDeviceFromPort(svc.Port); device != nil {
		GetApplication().AddMeterToDevice(svc.Port, device.Name, svc.UsMeterID, 0)
		return true
	}
	logger.Errorw(ctx, "Dropping US Meter request: Device not found", log.Fields{"Service": svc})
	return false
}

// PushFlowsForPortVnet - triggers flow construction and push for provided VPV
func (vpv *VoltPortVnet) PushFlowsForPortVnet(cntx context.Context, d *VoltDevice) {
	vp := d.GetPort(vpv.Port)

	//Ignore if UNI port is not found or not UP
	if vp == nil || vp.State != PortStateUp {
		logger.Warnw(ctx, "Ignoring Vlan UP Ind for VPV: Port Not Found/Ready", log.Fields{"Port": vp})
		return
	}

	if vpv.PonPort != 0xFF && vpv.PonPort != vp.PonPort {
		logger.Errorw(ctx, "UNI port discovered on wrong PON Port. Dropping Flow Configuration for VPV", log.Fields{"Device": d.Name, "Port": vpv.Port, "DetectedPon": vp.PonPort, "ExpectedPon": vpv.PonPort, "Vnet": vpv.VnetName})
		return
	}

	//Disable the flag so that flows can be pushed again
	// vpv.IgmpFlowsApplied = false
	// vpv.DsFlowsApplied = false
	// vpv.UsFlowsApplied = false
	vpv.VpvLock.Lock()
	vpv.PortUpInd(cntx, d, vpv.Port)
	vpv.VpvLock.Unlock()
}

// PortUpInd : When a port transistions to UP state, the indication is passed
// on to this module via the application. We read the VNET configuration
// again here to apply the latest configuration if the configuration
// changed. Thus, a reboot of ONT forces the new configuration to get
// applied.
func (vpv *VoltPortVnet) PortUpInd(cntx context.Context, device *VoltDevice, port string) {
	if vpv.DeleteInProgress {
		logger.Errorw(ctx, "Ignoring VPV Port UP Ind, VPV deleteion In-Progress", log.Fields{"Device": device, "Port": port, "Vnet": vpv.VnetName})
		return
	}
	vpv.setDevice(device.Name)
	logger.Infow(ctx, "Port UP Ind, pushing flows for the port", log.Fields{"Device": device, "Port": port, "VnetDhcp": vpv.DhcpRelay, "McastService": vpv.McastService})

	nni, _ := GetApplication().GetNniPort(device.Name)
	if nni == "" {
		logger.Warnw(ctx, "Ignoring Vnet Port UP indication: NNI is unavailable", log.Fields{"Port": vpv.Port, "Device": device.Name})
		return
	}

	if nniPort := device.GetPort(nni); nniPort != nil {
		//If NNI port is not mached to nb nni port dont send flows
		devConfig := GetApplication().GetDeviceConfig(device.SerialNum)
		if devConfig != nil {
			if devConfig.UplinkPort != strconv.Itoa(int(nniPort.ID)) {
				logger.Errorw(ctx, "NNI port not configured from NB, not pushing flows", log.Fields{"NB NNI Port": devConfig.UplinkPort, "SB NNI port": nniPort.ID})
				return
			}
		}
	}

	if vpv.Blocked {
		logger.Errorw(ctx, "VPV Bocked for Processing. Ignoring flow push request", log.Fields{"Port": vpv.Port, "Vnet": vpv.VnetName})
		return
	}

	if vpv.DhcpRelay || vpv.ArpRelay || vpv.PppoeIa {
		// If MAC Learning is true if no MAC is configured, push DS/US DHCP, US HSIA flows without MAC.
		// DS HSIA flows are installed after learning the MAC.
		logger.Infow(ctx, "Port Up - Trap Flows", log.Fields{"Device": device.Name, "Port": port})
		// no HSIA flows for multicast service and DPU_MGMT Service
		if !vpv.McastService && vpv.VnetType != DpuMgmtTraffic {
			vpv.RangeOnServices(cntx, AddUsHsiaFlows)
		}
		if vpv.VnetType == DpuMgmtTraffic {
			vpv.RangeOnServices(cntx, AddMeterToDevice)
		}
		vpv.AddTrapFlows(cntx)
		if vpv.MacLearning == MacLearningNone || NonZeroMacAddress(vpv.MacAddr) {
			logger.Infow(ctx, "Port Up - DS Flows", log.Fields{"Device": device.Name, "Port": port})
			/*In case of DPU_MGMT_TRAFFIC, need to install both US and DS traffic */
			if vpv.VnetType == DpuMgmtTraffic {
				vpv.RangeOnServices(cntx, AddUsHsiaFlows)
			}
			// US & DS DHCP, US HSIA flows are already installed
			// install only DS HSIA flow here.
			// no HSIA flows for multicast service
			if !vpv.McastService {
				vpv.RangeOnServices(cntx, AddDsHsiaFlows)
			}
		}
	} else {
		// DHCP relay is not configured. This implies that the service must use
		// 1:1 and does not require MAC learning. In a completely uncommon but
		// plausible case, the MAC address can be learnt from N:1 without DHCP
		// relay by configuring any unknown MAC address to be reported. This
		// however is not seen as a real use case.
		logger.Infow(ctx, "Port Up - Service Flows", log.Fields{"Device": device.Name, "Port": port})
		if !vpv.McastService {
			vpv.RangeOnServices(cntx, AddUsHsiaFlows)
		}
		vpv.AddTrapFlows(cntx)
		if !vpv.McastService {
			vpv.RangeOnServices(cntx, AddDsHsiaFlows)
		}
	}

	// Process IGMP proxy - install IGMP trap rules before DHCP trap rules
	if vpv.IgmpEnabled {
		logger.Infow(ctx, "Port Up - IGMP Flows", log.Fields{"Device": device.Name, "Port": port})
		vpv.RangeOnServices(cntx, AddSvcUsMeterToDevice)
		if err := vpv.AddIgmpFlows(cntx); err != nil {
			statusCode, statusMessage := errorCodes.GetErrorInfo(err)
			vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		}

		if vpv.McastService {
			vpv.RangeOnServices(cntx, PostAccessConfigSuccessInd)
		}
	}

	vpv.WriteToDb(cntx)
}

// PortDownInd : When the port status changes to down, we delete all configured flows
// The same indication is also passed to the services enqueued for them
// to take appropriate actions
func (vpv *VoltPortVnet) PortDownInd(cntx context.Context, device string, port string, nbRequest bool) {
	if !nbRequest && !GetApplication().OltFlowServiceConfig.RemoveFlowsOnDisable {
		logger.Info(ctx, "VPV Port DOWN Ind, Not deleting flows since RemoveOnDisable is disabled")
		return
	}
	logger.Infow(ctx, "VPV Port DOWN Ind, deleting all flows for services",
		log.Fields{"service count": vpv.servicesCount.Load()})

	//vpv.RangeOnServices(cntx, DelAllFlows)
	vpv.DelTrapFlows(cntx)
	vpv.DelHsiaFlows(cntx)
	vpv.WriteToDb(cntx)
	vpv.ClearServiceCounters(cntx)
}

// SetMacAddr : The MAC address is set when a MAC address is learnt through the
// packets received from the network. Currently, DHCP packets are
// only packets we learn the MAC address from
func (vpv *VoltPortVnet) SetMacAddr(cntx context.Context, addr net.HardwareAddr) {
	//Store Learnt MAC address and return if MACLearning is not enabled
	vpv.LearntMacAddr = addr
	if vpv.MacLearning == MacLearningNone || !NonZeroMacAddress(addr) ||
		(NonZeroMacAddress(vpv.MacAddr) && vpv.MacLearning == Learn) {
		return
	}

	// Compare the two MAC addresses to see if it is same
	// If they are same, we just return. If not, we perform
	// actions to address the change in MAC address
	//if NonZeroMacAddress(vpv.MacAddr) && !util.MacAddrsMatch(vpv.MacAddr, addr) {
	if !util.MacAddrsMatch(vpv.MacAddr, addr) {
		expectedPort := GetApplication().GetMacInPortMap(addr)
		if expectedPort != "" && expectedPort != vpv.Port {
			logger.Errorw(ctx, "mac-learnt-from-different-port-ignoring-setmacaddr",
				log.Fields{"ExpectedPort": expectedPort, "ReceivedPort": vpv.Port, "LearntMacAdrr": vpv.MacAddr, "NewMacAdrr": addr.String()})
			return
		}
		if NonZeroMacAddress(vpv.MacAddr) {
			logger.Warnw(ctx, "MAC Address Changed. Remove old flows (if added) and re-add with updated MAC", log.Fields{"UpdatedMAC": addr})

			// The newly learnt MAC address is different than earlier one.
			// The existing MAC based HSIA flows need to be undone as the device
			// may have been changed
			// Atleast one HSIA flow should be present in adapter to retain the TP and GEM
			// hence delete one after the other
			vpv.RangeOnServices(cntx, DelUsHsiaFlows)
			vpv.MacAddr = addr
			vpv.RangeOnServices(cntx, vpv.setLearntMAC)
			vpv.RangeOnServices(cntx, AddUsHsiaFlows)
			vpv.RangeOnServices(cntx, DelDsHsiaFlows)
			GetApplication().DeleteMacInPortMap(vpv.MacAddr)
		} else {
			vpv.MacAddr = addr
			vpv.RangeOnServices(cntx, vpv.setLearntMAC)
			logger.Infow(ctx, "MAC Address learnt from DHCP or ARP", log.Fields{"Learnt MAC": addr.String(), "Port": vpv.Port})
		}
		GetApplication().UpdateMacInPortMap(vpv.MacAddr, vpv.Port)
	} else {
		logger.Infow(ctx, "Leant MAC Address is same", log.Fields{"Learnt MAC": addr.String(), "Port": vpv.Port})
	}

	_, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		logger.Warnw(ctx, "Not pushing Service Flows: Error Getting Device", log.Fields{"Reason": err.Error()})
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		return
	}
	// Ds Hsia flows has to be pushed
	if vpv.FlowsApplied {
		// In case of DPU_MGMT_TRAFFIC install both US and DS Flows
		if vpv.VnetType == DpuMgmtTraffic {
			vpv.RangeOnServices(cntx, AddUsHsiaFlows)
		}
		// no HSIA flows for multicast service
		if !vpv.McastService {
			vpv.RangeOnServices(cntx, AddDsHsiaFlows)
		}
	}
	vpv.WriteToDb(cntx)
}

// MatchesVlans : If the VNET matches both S and C VLANs, return true. Else, return false
func (vpv *VoltPortVnet) MatchesVlans(svlan of.VlanType, cvlan of.VlanType, univlan of.VlanType) bool {
	if vpv.SVlan != svlan || vpv.CVlan != cvlan || vpv.UniVlan != univlan {
		return false
	}
	return true
}

// MatchesCvlan : If the VNET matches CVLAN, return true. Else, return false
func (vpv *VoltPortVnet) MatchesCvlan(cvlan []of.VlanType) bool {
	if len(cvlan) != 1 && !vpv.AllowTransparent {
		return false
	}
	if vpv.CVlan != cvlan[0] {
		return false
	}
	return true
}

// MatchesPriority : If the VNET matches priority of the incoming packet with any service, return true. Else, return false
func (vpv *VoltPortVnet) MatchesPriority(priority uint8) *VoltService {
	var service *VoltService
	pbitFound := false
	matchpbitsFunc := func(key, value interface{}) bool {
		svc := value.(*VoltService)
		for _, pbit := range svc.Pbits {
			if uint8(pbit) == priority || uint8(pbit) == uint8(of.PbitMatchAll) {
				logger.Infow(ctx, "Pbit match found with service",
					log.Fields{"Pbit": priority, "serviceName": svc.Name})
				pbitFound = true
				service = svc
				return false //Returning false to stop the Range loop
			}
		}
		return true
	}
	_ = pbitFound
	vpv.services.Range(matchpbitsFunc)
	return service
}

// GetRemarkedPriority : If the VNET matches priority of the incoming packet with any service, return true. Else, return false
func (vpv *VoltPortVnet) GetRemarkedPriority(priority uint8) uint8 {
	dsPbit := uint8(0)
	matchpbitsFunc := func(key, value interface{}) bool {
		svc := value.(*VoltService)
		if remarkPbit, ok := svc.DsRemarkPbitsMap[int(priority)]; ok {
			logger.Infow(ctx, "Pbit match found with service",
				log.Fields{"Pbit": priority, "serviceName": svc.Name, "remarkPbit": remarkPbit})
			dsPbit = uint8(remarkPbit)
			return false //Returning false to stop the Range loop
		}
		// When no remarking info is available, remark the incoming pbit
		// to highest pbit configured for the subscriber (across all subservices associated)
		svcPbit := uint8(svc.Pbits[0])
		if svcPbit > dsPbit {
			dsPbit = svcPbit
		}
		return true
	}
	vpv.services.Range(matchpbitsFunc)
	logger.Debugw(ctx, "Remarked Pbit Value", log.Fields{"Incoming": priority, "Remarked": dsPbit})
	return dsPbit
}

// AddSvc adds a service on the VNET on a port. The addition is
// triggered when NB requests for service addition
func (vpv *VoltPortVnet) AddSvc(cntx context.Context, svc *VoltService) {
	//vpv.services = append(vpv.services, svc)
	vpv.AddService(cntx, svc)
	logger.Debugw(ctx, "Added Service to VPV", log.Fields{"Num of SVCs": vpv.servicesCount.Load(), "SVC": svc})

	// Learn the circuit-id and remote-id from the service
	// TODO: There must be a better way of doing this. This
	// may be explored
	if svc.IgmpEnabled {
		vpv.IgmpEnabled = true
	}
	// first time service activation MacLearning will have default value as None.
	// to handle reciliency if anythng other then None we should retain it .
	if svc.MacLearning == MacLearningNone {
		if !vpv.DhcpRelay && !vpv.ArpRelay {
			svc.MacLearning = MacLearningNone
		} else if vpv.MacLearning == Learn {
			svc.MacLearning = Learn
		} else if vpv.MacLearning == ReLearn {
			svc.MacLearning = ReLearn
		}
	}

	// TODO: Temp Change - Need to address MAC Learning flow issues completely
	if (svc.MacLearning == Learn || svc.MacLearning == ReLearn) && NonZeroMacAddress(vpv.MacAddr) {
		svc.MacAddr = vpv.MacAddr
	} else if vpv.servicesCount.Load() == 1 {
		vpv.MacAddr = svc.MacAddr
	}

	vpv.MacLearning = svc.MacLearning
	vpv.PonPort = svc.PonPort
	logger.Debugw(ctx, "Added MAC to VPV", log.Fields{"MacLearning": vpv.MacLearning, "VPV": vpv})
	// Reconfigure Vlans based on Vlan Control type
	svc.VlanControl = vpv.VlanControl
	if svc.McastService {
		vpv.McastService = true
		vpv.McastTechProfileID = svc.TechProfileID
		// Assumption: Only one Pbit for mcast service
		vpv.McastPbit = svc.Pbits[0]
		vpv.McastUsMeterID = svc.UsMeterID
		vpv.SchedID = svc.SchedID
	}
	svc.ONTEtherTypeClassification = vpv.ONTEtherTypeClassification
	svc.AllowTransparent = vpv.AllowTransparent
	svc.SVlanTpid = vpv.SVlanTpid

	// Ensure configuring the mvlan profile only once
	// One subscriber cannot have multiple mvlan profiles. Only the first configuration is valid
	if svc.MvlanProfileName != "" {
		if vpv.MvlanProfileName == "" {
			vpv.MvlanProfileName = svc.MvlanProfileName
		} else {
			logger.Warnw(ctx, "Mvlan Profile already configured for subscriber. Ignoring new Mvlan", log.Fields{"Existing Mvlan": vpv.MvlanProfileName, "New Mvlan": svc.MvlanProfileName})
		}
	}

	voltDevice, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		logger.Warnw(ctx, "Not pushing Service Flows: Error Getting Device", log.Fields{"Reason": err.Error()})
		// statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		// TODO-COMM: 		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		return
	}
	if !svc.IsActivated {
		logger.Warn(ctx, "Not pushing Service Flows: Service Not activated")
		return
	}

	// If NNI port is not mached to nb nni port
	devConfig := GetApplication().GetDeviceConfig(voltDevice.SerialNum)

	if devConfig.UplinkPort != voltDevice.NniPort {
		logger.Errorw(ctx, "NNI port mismatch", log.Fields{"NB NNI Port": devConfig.UplinkPort, "SB NNI port": voltDevice.NniPort})
		return
	}
	// Push Service Flows if DHCP relay is not configured
	// or already DHCP flows are configured for the VPV
	// to which the serivce is associated
	if vpv.FlowsApplied {
		if NonZeroMacAddress(vpv.MacAddr) || svc.MacLearning == MacLearningNone {
			svc.AddHsiaFlows(cntx)
		} else {
			if err := svc.AddUsHsiaFlows(cntx); err != nil {
				logger.Warnw(ctx, "Add US hsia flow failed", log.Fields{"service": svc.Name, "Error": err})
			}
		}
	}

	// Assumption: Igmp will be enabled only for one service and SubMgr ensure the same
	// When already the port is UP and provisioned a service without igmp, then trap flows for subsequent
	// service with Igmp Enabled needs to be installed
	if svc.IgmpEnabled && vpv.FlowsApplied {
		logger.Infow(ctx, "Add Service - IGMP Flows", log.Fields{"Device": vpv.Device, "Port": vpv.Port})
		if err := vpv.AddIgmpFlows(cntx); err != nil {
			statusCode, statusMessage := errorCodes.GetErrorInfo(err)
			vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		}

		if vpv.McastService {
			// For McastService, send Service Activated indication once IGMP US flow is pushed
			vpv.RangeOnServices(cntx, PostAccessConfigSuccessInd)
		}
	}
	vpv.WriteToDb(cntx)
}

// setLearntMAC to set learnt mac
func (vpv *VoltPortVnet) setLearntMAC(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	svc.SetMacAddr(vpv.MacAddr)
	svc.WriteToDb(cntx)
	return true
}

// PostAccessConfigSuccessInd for posting access config success indication
func PostAccessConfigSuccessInd(cntx context.Context, key, value interface{}) bool {
	return true
}

// updateIPv4AndProvisionFlows to update ipv4 and provisional flows
func (vpv *VoltPortVnet) updateIPv4AndProvisionFlows(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	logger.Infow(ctx, "Updating Ipv4 address for service", log.Fields{"ServiceName": svc.Name})
	svc.SetIpv4Addr(vpv.Ipv4Addr)
	svc.WriteToDb(cntx)

	return true
}

// updateIPv6AndProvisionFlows to update ipv6 and provisional flow
func (vpv *VoltPortVnet) updateIPv6AndProvisionFlows(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	svc.SetIpv6Addr(vpv.Ipv6Addr)
	svc.WriteToDb(cntx)

	return true
}

// AddUsHsiaFlows to add upstream hsia flows
func AddUsHsiaFlows(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	if err := svc.AddUsHsiaFlows(cntx); err != nil {
		logger.Warnw(ctx, "Add US hsia flow failed", log.Fields{"service": svc.Name, "Error": err})
	}
	return true
}

// AddDsHsiaFlows to add downstream hsia flows
func AddDsHsiaFlows(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	if err := svc.AddDsHsiaFlows(cntx); err != nil {
		logger.Warnw(ctx, "Add DS hsia flow failed", log.Fields{"service": svc.Name, "Error": err})
	}
	return true
}

// ClearFlagsInService to clear the flags used in service
func ClearFlagsInService(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	svc.ServiceLock.Lock()
	svc.IgmpFlowsApplied = false
	svc.DsDhcpFlowsApplied = false
	svc.DsHSIAFlowsApplied = false
	svc.Icmpv6FlowsApplied = false
	svc.UsHSIAFlowsApplied = false
	svc.UsDhcpFlowsApplied = false
	svc.PendingFlows = make(map[string]bool)
	svc.AssociatedFlows = make(map[string]bool)
	svc.ServiceLock.Unlock()
	svc.WriteToDb(cntx)
	logger.Debugw(ctx, "Cleared Flow Flags for service", log.Fields{"name": svc.Name})
	return true
}

// DelDsHsiaFlows to delete hsia flows
func DelDsHsiaFlows(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	if err := svc.DelDsHsiaFlows(cntx); err != nil {
		logger.Warnw(ctx, "Delete DS hsia flow failed", log.Fields{"service": svc.Name, "Error": err})
	}
	return true
}

// DelUsHsiaFlows to delete upstream hsia flows
func DelUsHsiaFlows(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	if err := svc.DelUsHsiaFlows(cntx); err != nil {
		logger.Warnw(ctx, "Delete US hsia flow failed", log.Fields{"service": svc.Name, "Error": err})
	}
	return true
}

// ClearServiceCounters to clear the service counters
func ClearServiceCounters(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	//Delete the per service counter too
	GetApplication().ServiceCounters.Delete(svc.Name)
	if svc.IgmpEnabled && svc.EnableMulticastKPI {
		_ = db.DelAllServiceChannelCounter(cntx, svc.Name)
	}
	return true
}

// AddMeterToDevice to add meter config to device, used in FTTB case
func AddMeterToDevice(cntx context.Context, key, value interface{}) bool {
	svc := value.(*VoltService)
	if err := svc.AddMeterToDevice(cntx); err != nil {
		logger.Warnw(ctx, "Add Meter failed", log.Fields{"service": svc.Name, "Error": err})
	}
	return true
}

// AddTrapFlows - Adds US & DS Trap flows
func (vpv *VoltPortVnet) AddTrapFlows(cntx context.Context) {
	if !vpv.FlowsApplied || vgcRebooted {
		if vpv.DhcpRelay {
			if err := vpv.AddUsDhcpFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
			if err := vpv.AddDsDhcpFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
			logger.Infow(ctx, "ICMPv6 MC Group modification will not be triggered to rwcore for ",
				log.Fields{"port": vpv.Port})
			//vpv.updateICMPv6McGroup(true)
		} else if vpv.ArpRelay {
			if err := vpv.AddUsArpFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
			logger.Info(ctx, "ARP trap rules not added in downstream direction")
		} else if vpv.PppoeIa {
			if err := vpv.AddUsPppoeFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
			if err := vpv.AddDsPppoeFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
		}
		vpv.FlowsApplied = true
		vpv.WriteToDb(cntx)
	}
}

// DelTrapFlows - Removes all US & DS DHCP, IGMP trap flows.
func (vpv *VoltPortVnet) DelTrapFlows(cntx context.Context) {
	// Delete HSIA & DHCP flows before deleting IGMP flows
	if vpv.FlowsApplied || vgcRebooted {
		if vpv.DhcpRelay {
			if err := vpv.DelUsDhcpFlows(cntx); err != nil {
				logger.Warnw(ctx, "Delete US hsia flow failed", log.Fields{"port": vpv.Port, "SVlan": vpv.SVlan, "CVlan": vpv.CVlan,
					"UniVlan": vpv.UniVlan, "Error": err})
			}
			logger.Infow(ctx, "ICMPv6 MC Group modification will not be triggered to rwcore  for ",
				log.Fields{"port": vpv.Port})
			if err := vpv.DelDsDhcpFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
			//vpv.updateICMPv6McGroup(false)
		} else if vpv.ArpRelay {
			if err := vpv.DelUsArpFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
		} else if vpv.PppoeIa {
			if err := vpv.DelUsPppoeFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
			if err := vpv.DelDsPppoeFlows(cntx); err != nil {
				statusCode, statusMessage := errorCodes.GetErrorInfo(err)
				vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
			}
		}
		vpv.FlowsApplied = false
		vpv.WriteToDb(cntx)
	}
	if err := vpv.DelIgmpFlows(cntx); err != nil {
		logger.Warnw(ctx, "Delete igmp flow failed", log.Fields{"port": vpv.Port, "SVlan": vpv.SVlan, "CVlan": vpv.CVlan,
			"UniVlan": vpv.UniVlan, "Error": err})
	}
}

// DelHsiaFlows deletes the service flows
func (vpv *VoltPortVnet) DelHsiaFlows(cntx context.Context) {
	// no HSIA flows for multicast service
	if !vpv.McastService {
		vpv.RangeOnServices(cntx, DelUsHsiaFlows)
		vpv.RangeOnServices(cntx, DelDsHsiaFlows)
	}
}

// ClearServiceCounters - Removes all igmp counters for a service
func (vpv *VoltPortVnet) ClearServiceCounters(cntx context.Context) {
	//send flows deleted indication to submgr
	vpv.RangeOnServices(cntx, ClearServiceCounters)
}

// AddUsDhcpFlows pushes the DHCP flows to the VOLTHA via the controller
func (vpv *VoltPortVnet) AddUsDhcpFlows(cntx context.Context) error {
	var vd *VoltDevice
	device := vpv.Device

	if vd = GetApplication().GetDevice(device); vd != nil {
		if vd.State != controller.DeviceStateUP {
			logger.Errorw(ctx, "Skipping US DHCP Flow Push - Device state DOWN", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
			return nil
		}
	} else {
		logger.Errorw(ctx, "US DHCP Flow Push Failed- Device not found", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
		return errorCodes.ErrDeviceNotFound
	}

	flows, err := vpv.BuildUsDhcpFlows()
	if err == nil {
		logger.Debugw(ctx, "Adding US DHCP flows", log.Fields{"Device": device})
		if err1 := vpv.PushFlows(cntx, vd, flows); err1 != nil {
			// push ind here ABHI
			statusCode, statusMessage := errorCodes.GetErrorInfo(err1)
			vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		}
	} else {
		logger.Errorw(ctx, "US DHCP Flow Add Failed", log.Fields{"Reason": err.Error(), "Device": device})
		// push ind here ABHI
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
	}
	return nil
}

// AddDsDhcpFlows function pushes the DHCP flows to the VOLTHA via the controller
func (vpv *VoltPortVnet) AddDsDhcpFlows(cntx context.Context) error {
	var vd *VoltDevice
	device := vpv.Device

	if vd = GetApplication().GetDevice(device); vd != nil {
		if vd.State != controller.DeviceStateUP {
			logger.Errorw(ctx, "Skipping DS DHCP Flow Push - Device state DOWN", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
			return nil
		}
	} else {
		logger.Errorw(ctx, "DS DHCP Flow Push Failed- Device not found", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
		return errorCodes.ErrDeviceNotFound
	}
	if vd.GlobalDhcpFlowAdded {
		logger.Info(ctx, "Global Dhcp flow already exists")
		return nil
	}

	flows, err := vpv.BuildDsDhcpFlows()
	if err == nil {
		if err1 := vpv.PushFlows(cntx, vd, flows); err1 != nil {
			// push ind here and procced
			statusCode, statusMessage := errorCodes.GetErrorInfo(err1)
			vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		}
	} else {
		logger.Errorw(ctx, "DS DHCP Flow Add Failed", log.Fields{"Reason": err.Error()})
		// send ind here and proceed
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
	}
	if GetApplication().GetVendorID() != Radisys {
		vd.GlobalDhcpFlowAdded = true
	}
	return nil
}

// DelDhcpFlows deletes both US & DS DHCP flows applied for this Vnet instantiated on the port
func (vpv *VoltPortVnet) DelDhcpFlows(cntx context.Context) {
	if err := vpv.DelUsDhcpFlows(cntx); err != nil {
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
	}

	if err := vpv.DelDsDhcpFlows(cntx); err != nil {
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
	}
}

// DelUsDhcpFlows delete the DHCP flows applied for this Vnet instantiated on the port
// Write the status of the VPV to the DB once the delete is scheduled
// for dispatch
func (vpv *VoltPortVnet) DelUsDhcpFlows(cntx context.Context) error {
	device, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		return err
	}

	err = vpv.delDhcp4Flows(cntx, device)
	if err != nil {
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
	}

	return nil
}

func (vpv *VoltPortVnet) delDhcp4Flows(cntx context.Context, device *VoltDevice) error {
	flows, err := vpv.BuildUsDhcpFlows()
	if err == nil {
		return vpv.RemoveFlows(cntx, device, flows)
	}
	logger.Errorw(ctx, "US DHCP Flow Delete Failed", log.Fields{"Reason": err.Error()})
	return err
}

// DelDsDhcpFlows delete the DHCP flows applied for this Vnet instantiated on the port
// Write the status of the VPV to the DB once the delete is scheduled
// for dispatch
func (vpv *VoltPortVnet) DelDsDhcpFlows(cntx context.Context) error {
	device, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		return err
	}
	err = vpv.delDsDhcp4Flows(cntx, device)
	if err != nil {
		statusCode, statusMessage := errorCodes.GetErrorInfo(err)
		vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
	}
	/*
		err = vpv.delDsDhcp6Flows(device)
		if err != nil {
			statusCode, statusMessage := errorCodes.GetErrorInfo(err)
			vpv.FlowInstallFailure("VGC processing failure", statusCode, statusMessage)
		}*/
	return nil
}

func (vpv *VoltPortVnet) delDsDhcp4Flows(cntx context.Context, device *VoltDevice) error {
	flows, err := vpv.BuildDsDhcpFlows()
	if err == nil {
		return vpv.RemoveFlows(cntx, device, flows)
	}
	logger.Errorw(ctx, "DS DHCP Flow Delete Failed", log.Fields{"Reason": err.Error()})
	return err
}

/*
func (vpv *VoltPortVnet) delDsDhcp6Flows(device *VoltDevice) error {
	flows, err := vpv.BuildDsDhcp6Flows()
	if err == nil {
		return vpv.RemoveFlows(device, flows)
	}
	logger.Errorw(ctx, "DS DHCP6 Flow Delete Failed", log.Fields{"Reason": err.Error()})
	return err
}*/

// AddUsArpFlows pushes the ARP flows to the VOLTHA via the controller
func (vpv *VoltPortVnet) AddUsArpFlows(cntx context.Context) error {
	var vd *VoltDevice
	device := vpv.Device
	if vd = GetApplication().GetDevice(device); vd != nil {
		if vd.State != controller.DeviceStateUP {
			logger.Errorw(ctx, "Skipping US ARP Flow Push - Device state DOWN", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
			return nil
		}
	} else {
		logger.Errorw(ctx, "US ARP Flow Push Failed- Device not found", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
		return errorCodes.ErrDeviceNotFound
	}

	flows, err := vpv.BuildUsArpFlows()
	if err == nil {
		logger.Debugw(ctx, "Adding US ARP flows", log.Fields{"Device": device})
		if err1 := vpv.PushFlows(cntx, vd, flows); err1 != nil {
			return err1
		}
	} else {
		logger.Errorw(ctx, "US ARP Flow Add Failed", log.Fields{"Reason": err.Error(), "Device": device})
		return err
	}
	return nil
}

// DelUsArpFlows delete the ARP flows applied for this Vnet instantiated on the port
// Write the status of the VPV to the DB once the delete is scheduled
// for dispatch
func (vpv *VoltPortVnet) DelUsArpFlows(cntx context.Context) error {
	device, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		return err
	}
	flows, err := vpv.BuildUsArpFlows()
	if err == nil {
		return vpv.RemoveFlows(cntx, device, flows)
	}
	logger.Errorw(ctx, "US ARP Flow Delete Failed", log.Fields{"Reason": err.Error()})
	return err
}

// AddUsPppoeFlows pushes the PPPoE flows to the VOLTHA via the controller
func (vpv *VoltPortVnet) AddUsPppoeFlows(cntx context.Context) error {
	logger.Debugw(ctx, "Adding US PPPoE flows", log.Fields{"STAG": vpv.SVlan, "CTAG": vpv.CVlan, "Device": vpv.Device})

	var vd *VoltDevice
	device := vpv.Device

	if vd = GetApplication().GetDevice(device); vd != nil {
		if vd.State != controller.DeviceStateUP {
			logger.Errorw(ctx, "Skipping US PPPoE Flow Push - Device state DOWN", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
			return nil
		}
	} else {
		logger.Errorw(ctx, "US PPPoE Flow Push Failed- Device not found", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
		return errorCodes.ErrDeviceNotFound
	}

	if flows, err := vpv.BuildUsPppoeFlows(); err == nil {
		logger.Debugw(ctx, "Adding US PPPoE flows", log.Fields{"Device": device})

		if err1 := vpv.PushFlows(cntx, vd, flows); err1 != nil {
			return err1
		}
	} else {
		logger.Errorw(ctx, "US PPPoE Flow Add Failed", log.Fields{"Reason": err.Error(), "Device": device})
		return err
	}
	return nil
}

// AddDsPppoeFlows to add downstream pppoe flows
func (vpv *VoltPortVnet) AddDsPppoeFlows(cntx context.Context) error {
	logger.Debugw(ctx, "Adding DS PPPoE flows", log.Fields{"STAG": vpv.SVlan, "CTAG": vpv.CVlan, "Device": vpv.Device})
	var vd *VoltDevice
	device := vpv.Device

	if vd = GetApplication().GetDevice(device); vd != nil {
		if vd.State != controller.DeviceStateUP {
			logger.Errorw(ctx, "Skipping DS PPPoE Flow Push - Device state DOWN", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
			return nil
		}
	} else {
		logger.Errorw(ctx, "DS PPPoE Flow Push Failed- Device not found", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan, "device": device})
		return errorCodes.ErrDeviceNotFound
	}

	flows, err := vpv.BuildDsPppoeFlows()
	if err == nil {
		if err1 := vpv.PushFlows(cntx, vd, flows); err1 != nil {
			return err1
		}
	} else {
		logger.Errorw(ctx, "DS PPPoE Flow Add Failed", log.Fields{"Reason": err.Error()})
		return err
	}
	return nil
}

// DelUsPppoeFlows delete the PPPoE flows applied for this Vnet instantiated on the port
// Write the status of the VPV to the DB once the delete is scheduled
// for dispatch
func (vpv *VoltPortVnet) DelUsPppoeFlows(cntx context.Context) error {
	logger.Debugw(ctx, "Deleting US PPPoE flows", log.Fields{"STAG": vpv.SVlan, "CTAG": vpv.CVlan, "Device": vpv.Device})
	device, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		return err
	}
	flows, err := vpv.BuildUsPppoeFlows()
	if err == nil {
		return vpv.RemoveFlows(cntx, device, flows)
	}
	logger.Errorw(ctx, "US PPPoE Flow Delete Failed", log.Fields{"Reason": err.Error()})
	return err
}

// DelDsPppoeFlows delete the PPPoE flows applied for this Vnet instantiated on the port
// Write the status of the VPV to the DB once the delete is scheduled
// for dispatch
func (vpv *VoltPortVnet) DelDsPppoeFlows(cntx context.Context) error {
	logger.Debugw(ctx, "Deleting DS PPPoE flows", log.Fields{"STAG": vpv.SVlan, "CTAG": vpv.CVlan, "Device": vpv.Device})
	device, err := GetApplication().GetDeviceFromPort(vpv.Port)
	if err != nil {
		return err
	}
	flows, err := vpv.BuildDsPppoeFlows()
	if err == nil {
		return vpv.RemoveFlows(cntx, device, flows)
	}
	logger.Errorw(ctx, "DS PPPoE Flow Delete Failed", log.Fields{"Reason": err.Error()})
	return err
}

// AddIgmpFlows function pushes the IGMP flows to the VOLTHA via the controller
func (vpv *VoltPortVnet) AddIgmpFlows(cntx context.Context) error {
	if !vpv.IgmpFlowsApplied || vgcRebooted {
		if vpv.MvlanProfileName == "" {
			logger.Info(ctx, "Mvlan Profile not configured. Ignoring Igmp trap flow")
			return nil
		}
		device, err := GetApplication().GetDeviceFromPort(vpv.Port)
		if err != nil {
			logger.Errorw(ctx, "Error getting device from port", log.Fields{"Port": vpv.Port, "Reason": err.Error()})
			return err
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Ignoring US IGMP Flow Push", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan, "UNIVlan": vpv.UniVlan})
			return nil
		}
		flows, err := vpv.BuildIgmpFlows()
		if err == nil {
			for cookie := range flows.SubFlows {
				if vd := GetApplication().GetDevice(device.Name); vd != nil {
					cookie := strconv.FormatUint(cookie, 10)
					fe := &FlowEvent{
						eType:     EventTypeUsIgmpFlowAdded,
						cookie:    cookie,
						eventData: vpv,
					}
					vd.RegisterFlowAddEvent(cookie, fe)
				}
			}
			if err1 := cntlr.GetController().AddFlows(cntx, vpv.Port, device.Name, flows); err1 != nil {
				return err1
			}
		} else {
			logger.Errorw(ctx, "IGMP Flow Add Failed", log.Fields{"Reason": err.Error()})
			return err
		}
		vpv.IgmpFlowsApplied = true
		vpv.WriteToDb(cntx)
	}
	return nil
}

// DelIgmpFlows delete the IGMP flows applied for this Vnet instantiated on the port
// Write the status of the VPV to the DB once the delete is scheduled
// for dispatch
func (vpv *VoltPortVnet) DelIgmpFlows(cntx context.Context) error {
	if vpv.IgmpFlowsApplied || vgcRebooted {
		device, err := GetApplication().GetDeviceFromPort(vpv.Port)
		if err != nil {
			logger.Errorw(ctx, "Error getting device from port", log.Fields{"Port": vpv.Port, "Reason": err.Error()})
			return err
		}
		flows, err := vpv.BuildIgmpFlows()
		if err == nil {
			if err1 := vpv.RemoveFlows(cntx, device, flows); err1 != nil {
				return err1
			}
		} else {
			logger.Errorw(ctx, "IGMP Flow Add Failed", log.Fields{"Reason": err.Error()})
			return err
		}
		vpv.IgmpFlowsApplied = false
		vpv.WriteToDb(cntx)
	}
	return nil
}

// BuildUsDhcpFlows builds the US DHCP relay flows for a subscriber
// The flows included by this function cover US only as the DS is
// created either automatically by the VOLTHA or at the device level
// earlier
func (vpv *VoltPortVnet) BuildUsDhcpFlows() (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)

	logger.Infow(ctx, "Building US DHCP flow", log.Fields{"Port": vpv.Port})
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	if vpv.VnetType == DpuMgmtTraffic {
		subFlow.SetMatchVlan(vpv.CVlan)
		subFlow.SetMatchPbit(vpv.UsPonCTagPriority)
		subFlow.SetPcp(vpv.UsPonSTagPriority)
		subFlow.SetSetVlan(vpv.SVlan)
	} else {
		subFlow.SetMatchVlan(vpv.UniVlan)
		subFlow.SetSetVlan(vpv.CVlan)
		subFlow.SetPcp(vpv.DhcpPbit)
	}
	subFlow.SetUdpv4Match()
	subFlow.DstPort = 67
	subFlow.SrcPort = 68
	uniport, err := GetApplication().GetPortID(vpv.Port)
	if err != nil {
		logger.Errorw(ctx, "Failed to fetch uni port from vpv", log.Fields{"error": err, "port": vpv.Port})
		return nil, err
	}
	subFlow.SetInPort(uniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port
	subFlow.SetReportToController()

	// Set techprofile, meterid of first service
	vpv.services.Range(func(key, value interface{}) bool {
		vs := value.(*VoltService)
		var writemetadata uint64
		if vpv.VnetType == DpuMgmtTraffic {
			writemetadata = uint64(vs.TechProfileID)<<32 + uint64(vs.UsMeterID)
		} else {
			writemetadata = uint64(vs.TechProfileID) << 32
		}
		subFlow.SetWriteMetadata(writemetadata)
		subFlow.SetMeterID(vs.UsMeterID)
		return false
	})

	// metadata := uint64(uniport)
	// subFlow.SetWriteMetadata(metadata)
	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	if vpv.VnetType != DpuMgmtTraffic {
		metadata := uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
		subFlow.SetTableMetadata(metadata)
	}
	//| 12-bit cvlan | 4 bits empty | <32-bits uniport>| 16-bits dhcp mask or flow mask |
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<16 | of.DhcpArpFlowMask | of.UsFlowMask
	subFlow.Priority = of.DhcpFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built US DHCP flow ", log.Fields{"cookie": subFlow.Cookie, "flow": flow})
	return flow, nil
}

// BuildDsDhcpFlows to build the downstream dhcp flows
func (vpv *VoltPortVnet) BuildDsDhcpFlows() (*of.VoltFlow, error) {
	logger.Infow(ctx, "Building DS DHCP flow", log.Fields{"Port": vpv.Port, "ML": vpv.MacLearning, "Mac": vpv.MacAddr})
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)
	// match on vlan only for fttb case
	if vpv.VnetType == DpuMgmtTraffic {
		subFlow.SetMatchVlan(vpv.SVlan)
	}
	subFlow.SetUdpv4Match()
	subFlow.SrcPort = 67
	subFlow.DstPort = 68
	uniport, _ := GetApplication().GetPortID(vpv.Port)
	nni, err := GetApplication().GetNniPort(vpv.Device)
	if err != nil {
		return nil, err
	}
	nniport, err := GetApplication().GetPortID(nni)
	if err != nil {
		return nil, err
	}
	subFlow.SetInPort(nniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port
	// metadata := uint64(uniport)
	// subFlow.SetWriteMetadata(metadata)
	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	if vpv.VnetType != DpuMgmtTraffic {
		metadata := uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
		subFlow.SetTableMetadata(metadata)
		subFlow.Priority = of.DhcpFlowPriority
	}
	subFlow.SetReportToController()
	// | 12-bit cvlan | 4 bits empty | <32-bits uniport>| 16-bits dhcp mask or flow mask |
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<16 | of.DhcpArpFlowMask | of.DsFlowMask

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built DS DHCP flow ", log.Fields{"cookie": subFlow.Cookie, "Flow": flow})

	return flow, nil
}

// BuildUsDhcp6Flows to trap the DHCPv6 packets to be reported to the
// application.
func (vpv *VoltPortVnet) BuildUsDhcp6Flows() (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)

	logger.Infow(ctx, "Building US DHCPv6 flow", log.Fields{"Port": vpv.Port})
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	subFlow.SetMatchVlan(vpv.UniVlan)
	subFlow.SetSetVlan(vpv.CVlan)
	subFlow.SetUdpv6Match()
	subFlow.SrcPort = 546
	subFlow.DstPort = 547
	uniport, err := GetApplication().GetPortID(vpv.Port)
	if err != nil {
		return nil, err
	}
	// Set techprofile, meterid of first service
	vpv.services.Range(func(key, value interface{}) bool {
		svc := value.(*VoltService)
		writemetadata := uint64(svc.TechProfileID) << 32
		subFlow.SetWriteMetadata(writemetadata)
		subFlow.SetMeterID(svc.UsMeterID)
		return false
	})
	subFlow.SetInPort(uniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port
	// subFlow.SetMeterId(vpv.UsDhcpMeterId)
	// metadata := uint64(uniport)
	// subFlow.SetWriteMetadata(metadata)
	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	metadata := uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
	subFlow.SetTableMetadata(metadata)
	subFlow.SetReportToController()
	// | 12-bit cvlan | 4 bits empty | <32-bits uniport>| 16-bits dhcp mask or flow mask |
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<16 | of.Dhcpv6FlowMask | of.UsFlowMask
	subFlow.Priority = of.DhcpFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built US DHCPv6 flow", log.Fields{"cookie": subFlow.Cookie, "flow": flow})
	return flow, nil
}

// BuildDsDhcp6Flows to trap the DHCPv6 packets to be reported to the
// application.
func (vpv *VoltPortVnet) BuildDsDhcp6Flows() (*of.VoltFlow, error) {
	logger.Infow(ctx, "Building DS DHCPv6 flow", log.Fields{"Port": vpv.Port, "ML": vpv.MacLearning, "Mac": vpv.MacAddr})

	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	vpv.setDsMatchVlan(subFlow)
	subFlow.SetUdpv6Match()
	subFlow.SrcPort = 547
	subFlow.DstPort = 547
	uniport, _ := GetApplication().GetPortID(vpv.Port)
	nni, err := GetApplication().GetNniPort(vpv.Device)
	if err != nil {
		return nil, err
	}
	nniport, err := GetApplication().GetPortID(nni)
	if err != nil {
		return nil, err
	}
	subFlow.SetInPort(nniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port
	// metadata := uint64(uniport)
	// subFlow.SetWriteMetadata(metadata)
	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	metadata := uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
	subFlow.SetTableMetadata(metadata)
	subFlow.SetReportToController()
	// | 12-bit cvlan | 4 bits empty | <32-bits uniport>| 16-bits dhcp mask or flow mask |
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<16 | of.Dhcpv6FlowMask | of.DsFlowMask
	subFlow.Priority = of.DhcpFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built DS DHCPv6 flow", log.Fields{"cookie": subFlow.Cookie, "flow": flow})
	return flow, nil
}

// BuildUsArpFlows builds the US ARP relay flows for a subscriber
// The flows included by this function cover US only as the DS is
// created either automatically by the VOLTHA or at the device level
// earlier
func (vpv *VoltPortVnet) BuildUsArpFlows() (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)

	logger.Infow(ctx, "Building US ARP flow", log.Fields{"Port": vpv.Port})
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	if vpv.MacLearning == MacLearningNone && NonZeroMacAddress(vpv.MacAddr) {
		subFlow.SetMatchSrcMac(vpv.MacAddr)
	}

	subFlow.SetMatchDstMac(BroadcastMAC)
	if err := vpv.setUsMatchVlan(subFlow); err != nil {
		return nil, err
	}
	subFlow.SetArpMatch()
	uniport, err := GetApplication().GetPortID(vpv.Port)
	if err != nil {
		return nil, err
	}
	subFlow.SetInPort(uniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port
	subFlow.SetReportToController()
	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	metadata := uint64(uniport)
	subFlow.SetWriteMetadata(metadata)
	metadata = uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
	subFlow.SetTableMetadata(metadata)
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<32 | of.DhcpArpFlowMask | of.UsFlowMask
	subFlow.Priority = of.ArpFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built US ARP flow ", log.Fields{"cookie": subFlow.Cookie, "flow": flow})
	return flow, nil
}

// setUsMatchVlan to set upstream match vlan
func (vpv *VoltPortVnet) setUsMatchVlan(flow *of.VoltSubFlow) error {
	switch vpv.VlanControl {
	case None:
		flow.SetMatchVlan(vpv.SVlan)
	case ONUCVlanOLTSVlan:
		flow.SetMatchVlan(vpv.CVlan)
	case OLTCVlanOLTSVlan:
		flow.SetMatchVlan(vpv.UniVlan)
		//flow.SetSetVlan(vpv.CVlan)
	case ONUCVlan:
		flow.SetMatchVlan(vpv.SVlan)
	case OLTSVlan:
		flow.SetMatchVlan(vpv.UniVlan)
		//flow.SetSetVlan(vpv.SVlan)
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
		return errorCodes.ErrInvalidParamInRequest
	}
	return nil
}

// BuildUsPppoeFlows to build upstream pppoe flows
func (vpv *VoltPortVnet) BuildUsPppoeFlows() (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	logger.Infow(ctx, "Building US PPPoE flow", log.Fields{"Port": vpv.Port})
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	if vpv.MacLearning == MacLearningNone && NonZeroMacAddress(vpv.MacAddr) {
		subFlow.SetMatchSrcMac(vpv.MacAddr)
	}

	if err := vpv.setUsMatchVlan(subFlow); err != nil {
		return nil, err
	}
	subFlow.SetPppoeDiscoveryMatch()
	uniport, err := GetApplication().GetPortID(vpv.Port)
	if err != nil {
		return nil, err
	}
	subFlow.SetInPort(uniport)
	subFlow.SetReportToController()
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port

	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	metadata := uint64(uniport)
	subFlow.SetWriteMetadata(metadata)

	metadata = uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
	subFlow.SetTableMetadata(metadata)

	// | 12-bit cvlan | 4 bits empty | <32-bits uniport>| 16-bits pppoe mask or flow mask |
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<16 | of.PppoeFlowMask | of.UsFlowMask
	subFlow.Priority = of.PppoeFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built US PPPoE flow ", log.Fields{"cookie": subFlow.Cookie, "flow": flow})
	return flow, nil
}

// BuildDsPppoeFlows to build downstream pppoe flows
func (vpv *VoltPortVnet) BuildDsPppoeFlows() (*of.VoltFlow, error) {
	logger.Infow(ctx, "Building DS PPPoE flow", log.Fields{"Port": vpv.Port, "ML": vpv.MacLearning, "Mac": vpv.MacAddr})
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	vpv.setDsMatchVlan(subFlow)
	subFlow.SetPppoeDiscoveryMatch()

	if NonZeroMacAddress(vpv.MacAddr) {
		subFlow.SetMatchDstMac(vpv.MacAddr)
	}

	uniport, _ := GetApplication().GetPortID(vpv.Port)
	nni, err := GetApplication().GetNniPort(vpv.Device)
	if err != nil {
		return nil, err
	}
	nniport, err := GetApplication().GetPortID(nni)
	if err != nil {
		return nil, err
	}
	subFlow.SetInPort(nniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port
	metadata := uint64(uniport)
	subFlow.SetWriteMetadata(metadata)
	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	metadata = uint64(allowTransparent)<<56 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
	subFlow.SetTableMetadata(metadata)
	subFlow.SetReportToController()
	// | 12-bit cvlan | 4 bits empty | <32-bits uniport>| 16-bits dhcp mask or flow mask |
	subFlow.Cookie = uint64(vpv.CVlan)<<52 | uint64(uniport)<<16 | of.PppoeFlowMask | of.DsFlowMask
	subFlow.Priority = of.PppoeFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built DS DHCP flow ", log.Fields{"cookie": subFlow.Cookie, "Flow": flow})
	return flow, nil
}

// setDsMatchVlan to set downstream match vlan
func (vpv *VoltPortVnet) setDsMatchVlan(flow *of.VoltSubFlow) {
	switch vpv.VlanControl {
	case None:
		flow.SetMatchVlan(vpv.SVlan)
	case ONUCVlanOLTSVlan,
		OLTCVlanOLTSVlan,
		ONUCVlan,
		OLTSVlan:
		flow.SetMatchVlan(vpv.SVlan)
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
	}
}

// BuildIgmpFlows builds the US IGMP flows for a subscriber. IGMP requires flows only
// in the US direction.
func (vpv *VoltPortVnet) BuildIgmpFlows() (*of.VoltFlow, error) {
	logger.Infow(ctx, "Building US IGMP Flow", log.Fields{"Port": vpv.Port})
	mvp := GetApplication().GetMvlanProfileByName(vpv.MvlanProfileName)
	if mvp == nil {
		return nil, errors.New("Mvlan Profile configured not found")
	}
	mvlan := mvp.GetUsMatchVlan()
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()
	subFlow.SetTableID(0)

	subFlow.SetMatchVlan(vpv.UniVlan)
	subFlow.SetSetVlan(vpv.CVlan)

	uniport, err := GetApplication().GetPortID(vpv.Port)
	if err != nil {
		return nil, err
	}
	subFlow.SetInPort(uniport)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = uniport
	flow.PortName = vpv.Port

	if vpv.MacLearning == MacLearningNone && NonZeroMacAddress(vpv.MacAddr) {
		subFlow.SetMatchSrcMac(vpv.MacAddr)
	}
	logger.Infow(ctx, "Mvlan", log.Fields{"mvlan": mvlan})
	// metadata := uint64(mvlan)

	if vpv.McastService {
		metadata := uint64(vpv.McastUsMeterID)
		metadata = metadata | uint64(vpv.McastTechProfileID)<<32
		subFlow.SetMatchPbit(vpv.McastPbit)
		subFlow.SetMeterID(vpv.McastUsMeterID)
		subFlow.SetWriteMetadata(metadata)
	} else {
		// Set techprofile, meterid of first service
		vpv.services.Range(func(key, value interface{}) bool {
			svc := value.(*VoltService)
			writemetadata := uint64(svc.TechProfileID) << 32
			subFlow.SetWriteMetadata(writemetadata)
			subFlow.SetMeterID(svc.UsMeterID)
			return false
		})
	}

	allowTransparent := 0
	if vpv.AllowTransparent {
		allowTransparent = 1
	}
	metadata := uint64(allowTransparent)<<56 | uint64(vpv.SchedID)<<40 | uint64(vpv.ONTEtherTypeClassification)<<36 | uint64(vpv.VlanControl)<<32 | uint64(vpv.UniVlan)<<16 | uint64(vpv.CVlan)
	subFlow.SetTableMetadata(metadata)
	subFlow.SetIgmpMatch()
	subFlow.SetReportToController()
	// | 16 bits empty | <32-bits uniport>| 16-bits igmp mask or flow mask |
	subFlow.Cookie = uint64(uniport)<<16 | of.IgmpFlowMask | of.UsFlowMask
	subFlow.Priority = of.IgmpFlowPriority

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "Built US IGMP flow ", log.Fields{"cookie": subFlow.Cookie, "flow": flow})
	return flow, nil
}

// WriteToDb for writing to database
func (vpv *VoltPortVnet) WriteToDb(cntx context.Context) {
	if vpv.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Redis Update for VPV, VPV delete in progress", log.Fields{"Vnet": vpv.VnetName, "Port": vpv.Port})
		return
	}
	vpv.ForceWriteToDb(cntx)
}

// ForceWriteToDb force commit a VPV to the DB
func (vpv *VoltPortVnet) ForceWriteToDb(cntx context.Context) {
	vpv.PendingFlowLock.RLock()
	defer vpv.PendingFlowLock.RUnlock()
	vpv.Version = database.PresentVersionMap[database.VpvPath]
	if b, err := json.Marshal(vpv); err == nil {
		if err := db.PutVpv(cntx, vpv.Port, uint16(vpv.SVlan), uint16(vpv.CVlan), uint16(vpv.UniVlan), string(b)); err != nil {
			logger.Warnw(ctx, "VPV write to DB failed", log.Fields{"port": vpv.Port, "SVlan": vpv.SVlan, "CVlan": vpv.CVlan,
				"UniVlan": vpv.UniVlan, "Error": err})
		}
	}
}

// DelFromDb for deleting from database
func (vpv *VoltPortVnet) DelFromDb(cntx context.Context) {
	logger.Debugw(ctx, "Deleting VPV from DB", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan})
	_ = db.DelVpv(cntx, vpv.Port, uint16(vpv.SVlan), uint16(vpv.CVlan), uint16(vpv.UniVlan))
}

// ClearAllServiceFlags to clear all service flags
func (vpv *VoltPortVnet) ClearAllServiceFlags(cntx context.Context) {
	vpv.RangeOnServices(cntx, ClearFlagsInService)
}

// ClearAllVpvFlags to clear all vpv flags
func (vpv *VoltPortVnet) ClearAllVpvFlags(cntx context.Context) {
	vpv.PendingFlowLock.Lock()
	vpv.FlowsApplied = false
	vpv.IgmpFlowsApplied = false
	vpv.PendingDeleteFlow = make(map[string]bool)
	vpv.PendingFlowLock.Unlock()
	vpv.WriteToDb(cntx)
	logger.Debugw(ctx, "Cleared Flow Flags for VPV",
		log.Fields{"device": vpv.Device, "port": vpv.Port,
			"svlan": vpv.SVlan, "cvlan": vpv.CVlan, "univlan": vpv.UniVlan})
}

// CreateVpvFromString to create vpv from string
func (va *VoltApplication) CreateVpvFromString(b []byte, hash string) {
	var vpv VoltPortVnet
	if err := json.Unmarshal(b, &vpv); err == nil {
		vnetsByPortsSliceIntf, ok := va.VnetsByPort.Load(vpv.Port)
		if !ok {
			va.VnetsByPort.Store(vpv.Port, []*VoltPortVnet{})
			vnetsByPortsSliceIntf = []*VoltPortVnet{}
		}
		vpv.servicesCount = atomic.NewUint64(0)
		vnetsByPortsSlice := vnetsByPortsSliceIntf.([]*VoltPortVnet)
		vnetsByPortsSlice = append(vnetsByPortsSlice, &vpv)
		va.VnetsByPort.Store(vpv.Port, vnetsByPortsSlice)
		va.UpdateMacInPortMap(vpv.MacAddr, vpv.Port)
		if vnet := va.GetVnetByName(vpv.VnetName); vnet != nil {
			vnet.associatePortToVnet(vpv.Port)
		}

		if vpv.DeleteInProgress {
			va.VoltPortVnetsToDelete[&vpv] = true
			logger.Warnw(ctx, "VPV (restored) to be deleted", log.Fields{"Port": vpv.Port, "Vnet": vpv.VnetName})
		}
		logger.Debugw(ctx, "Added VPV from string", log.Fields{"port": vpv.Port, "svlan": vpv.SVlan, "cvlan": vpv.CVlan, "univlan": vpv.UniVlan})
	}
}

// RestoreVpvsFromDb to restore vpvs from database
func (va *VoltApplication) RestoreVpvsFromDb(cntx context.Context) {
	// VNETS must be learnt first
	vpvs, _ := db.GetVpvs(cntx)
	for hash, vpv := range vpvs {
		b, ok := vpv.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		va.CreateVpvFromString(b, hash)
	}
}

// GetVnetByPort : VNET related functionality of VOLT Application here on.
// Get the VNET from a port. The port identity is passed as device and port identities in string.
// The identity of the VNET is the SVLAN and the CVLAN. Only if the both match the VLAN
// is assumed to have matched. TODO: 1:1 should be treated differently and needs to be addressed
func (va *VoltApplication) GetVnetByPort(port string, svlan of.VlanType, cvlan of.VlanType, univlan of.VlanType) *VoltPortVnet {
	if _, ok := va.VnetsByPort.Load(port); !ok {
		return nil
	}
	vpvs, _ := va.VnetsByPort.Load(port)
	for _, vpv := range vpvs.([]*VoltPortVnet) {
		if vpv.MatchesVlans(svlan, cvlan, univlan) {
			return vpv
		}
	}
	return nil
}

// AddVnetToPort to add vnet to port
func (va *VoltApplication) AddVnetToPort(cntx context.Context, port string, vvnet *VoltVnet, vs *VoltService) *VoltPortVnet {
	// The VNET is not on the port and is to be added
	logger.Debugw(ctx, "Adding VNET to Port", log.Fields{"Port": port, "VNET": vvnet.Name})
	vpv := NewVoltPortVnet(vvnet)
	vpv.MacLearning = vvnet.MacLearning
	vpv.Port = port
	vvnet.associatePortToVnet(port)
	if _, ok := va.VnetsByPort.Load(port); !ok {
		va.VnetsByPort.Store(port, []*VoltPortVnet{})
	}
	vpvsIntf, _ := va.VnetsByPort.Load(port)
	vpvs := vpvsIntf.([]*VoltPortVnet)
	vpvs = append(vpvs, vpv)
	va.VnetsByPort.Store(port, vpvs)
	va.UpdateMacInPortMap(vpv.MacAddr, vpv.Port)

	vpv.VpvLock.Lock()
	defer vpv.VpvLock.Unlock()

	// Add the service that is causing the VNET to be added to the port
	vpv.AddSvc(cntx, vs)

	if !vs.IsActivated {
		logger.Warn(ctx, "Not Checking port state: Service Not activated")
		// Process the PORT UP if the port is already up
		d, err := va.GetDeviceFromPort(port)
		if err == nil {
			vpv.setDevice(d.Name)
		}
		vpv.WriteToDb(cntx)
		return vpv
	}

	// Process the PORT UP if the port is already up
	d, err := va.GetDeviceFromPort(port)
	if err == nil {
		vpv.setDevice(d.Name)
		p := d.GetPort(port)
		if p != nil {
			if vs.PonPort != 0xFF && vs.PonPort != p.PonPort {
				logger.Errorw(ctx, "UNI port discovered on wrong PON Port. Dropping Flow Push for VPV", log.Fields{"Device": d.Name, "Port": port, "DetectedPon": p.PonPort, "ExpectedPon": vs.PonPort, "Vnet": vpv.VnetName})
			} else {
				logger.Infow(ctx, "Checking UNI port state", log.Fields{"State": p.State})
				if d.State == controller.DeviceStateUP && p.State == PortStateUp {
					vpv.PortUpInd(cntx, d, port)
				}
			}
		}
	}
	vpv.WriteToDb(cntx)
	return vpv
}

// DelVnetFromPort for deleting vnet from port
func (va *VoltApplication) DelVnetFromPort(cntx context.Context, port string, vpv *VoltPortVnet) {
	// Delete DHCP Session
	delDhcpSessions(vpv.LearntMacAddr, vpv.SVlan, vpv.CVlan, vpv.DHCPv6DUID)

	// Delete PPPoE session
	delPppoeIaSessions(vpv.LearntMacAddr, vpv.SVlan, vpv.CVlan)

	// Delete Mac from MacPortMap
	va.DeleteMacInPortMap(vpv.MacAddr)

	// Delete VPV
	vpvsIntf, ok := va.VnetsByPort.Load(port)
	if !ok {
		return
	}
	vpvs := vpvsIntf.([]*VoltPortVnet)
	for i, lvpv := range vpvs {
		if lvpv == vpv {
			logger.Debugw(ctx, "Deleting VPV from port", log.Fields{"Port": vpv.Port, "SVLAN": vpv.SVlan, "CVLAN": vpv.CVlan,
				"UNIVLAN": vpv.UniVlan})

			vpvs = append(vpvs[0:i], vpvs[i+1:]...)

			vpv.DeleteInProgress = true
			vpv.ForceWriteToDb(cntx)

			va.VnetsByPort.Store(port, vpvs)
			vpv.DelTrapFlows(cntx)
			vpv.DelHsiaFlows(cntx)
			va.DisassociateVpvsFromDevice(vpv.Device, vpv)
			vpv.PendingFlowLock.RLock()
			if len(vpv.PendingDeleteFlow) == 0 {
				vpv.DelFromDb(cntx)
			}
			if vnet := va.GetVnetByName(vpv.VnetName); vnet != nil {
				vnet.disassociatePortFromVnet(cntx, vpv.Device, vpv.Port)
			}
			vpv.PendingFlowLock.RUnlock()
			return
		}
	}
}

// RestoreVnetsFromDb to restore vnet from port
func (va *VoltApplication) RestoreVnetsFromDb(cntx context.Context) {
	// VNETS must be learnt first
	vnets, _ := db.GetVnets(cntx)
	for _, net := range vnets {
		b, ok := net.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var vnet VoltVnet
		err := json.Unmarshal(b, &vnet)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of VNET failed")
			continue
		}
		logger.Debugw(ctx, "Retrieved VNET", log.Fields{"VNET": vnet.VnetConfig})
		if err := va.AddVnet(cntx, vnet.VnetConfig, &vnet.VnetOper); err != nil {
			logger.Warnw(ctx, "Add Vnet Failed", log.Fields{"Config": vnet.VnetConfig, "Error": err})
		}

		if vnet.DeleteInProgress {
			va.VnetsToDelete[vnet.Name] = true
			logger.Warnw(ctx, "Vnet (restored) to be deleted", log.Fields{"Vnet": vnet.Name})
		}
	}
}

// GetServiceFromCvlan : Locate a service based on the packet received. The packet contains VLANs that
// are used as the key to locate the service. If more than one service is on the
// same port (essentially a UNI of ONU), the services must be separated by different
// CVLANs
func (va *VoltApplication) GetServiceFromCvlan(device, port string, vlans []of.VlanType, priority uint8) *VoltService {
	// Fetch the device first to make sure the device exists
	dIntf, ok := va.DevicesDisc.Load(device)
	if !ok {
		return nil
	}
	d := dIntf.(*VoltDevice)

	// If the port is NNI port, the services dont exist on it. The svc then
	// must be obtained from a different context and is not included here
	if port == d.NniPort {
		return nil
	}

	// To return the matched service
	var service *VoltService

	// This is an access port and the port should have all the associated
	// services which can be uniquely identified by the VLANs in the packet
	vnets, ok := va.VnetsByPort.Load(port)

	if !ok {
		logger.Debugw(ctx, "No Vnets for port", log.Fields{"Port": port})
		return nil
	}
	logger.Debugw(ctx, "Matching for VLANs", log.Fields{"VLANs": vlans, "Priority": priority})
	for _, vnet := range vnets.([]*VoltPortVnet) {
		logger.Infow(ctx, "Vnet", log.Fields{"Vnet": vnet})
		switch vnet.VlanControl {
		case ONUCVlanOLTSVlan:
			service = vnet.MatchesPriority(priority)
			if vnet.MatchesCvlan(vlans) && service != nil {
				return service
			}
		case ONUCVlan,
			None:
			service = vnet.MatchesPriority(priority)
			// In case of DHCP Flow - cvlan == VlanNone
			// In case of HSIA Flow - cvlan == Svlan
			if len(vlans) == 1 && (vlans[0] == vnet.SVlan || vlans[0] == of.VlanNone) && service != nil {
				return service
			}
		case OLTCVlanOLTSVlan,
			OLTSVlan:
			service = vnet.MatchesPriority(priority)
			if len(vlans) == 1 && vlans[0] == vnet.UniVlan && service != nil {
				return service
			}
		default:
			logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vnet.VlanControl})
		}
	}
	return nil
}

// GetVnetFromFields : Locate a service based on the packet received. The packet contains VLANs that
// are used as the key to locate the service. If more than one service is on the
// same port (essentially a UNI of ONU), the services must be separated by different
// CVLANs
func (va *VoltApplication) GetVnetFromFields(device string, port string, vlans []of.VlanType, priority uint8) (*VoltPortVnet, *VoltService) {
	// Fetch the device first to make sure the device exists
	dIntf, ok := va.DevicesDisc.Load(device)
	if !ok {
		return nil, nil
	}
	d := dIntf.(*VoltDevice)

	// If the port is NNI port, the services dont exist on it. The svc then
	// must be obtained from a different context and is not included here
	if port == d.NniPort {
		return nil, nil
	}

	//To return the matched service
	var service *VoltService

	// This is an access port and the port should have all the associated
	// services which can be uniquely identified by the VLANs in the packet
	if vnets, ok := va.VnetsByPort.Load(port); ok {
		logger.Debugw(ctx, "Matching for VLANs", log.Fields{"VLANs": vlans, "Priority": priority})
		for _, vnet := range vnets.([]*VoltPortVnet) {
			logger.Infow(ctx, "Vnet", log.Fields{"Vnet": vnet})
			switch vnet.VlanControl {
			case ONUCVlanOLTSVlan:
				service = vnet.MatchesPriority(priority)
				if vnet.MatchesCvlan(vlans) && service != nil {
					return vnet, service
				}
			case ONUCVlan,
				None:
				service = vnet.MatchesPriority(priority)
				if (len(vlans) == 1 || vnet.AllowTransparent) && vlans[0] == vnet.SVlan && service != nil {
					return vnet, service
				}
			case OLTCVlanOLTSVlan,
				OLTSVlan:
				service = vnet.MatchesPriority(priority)
				if (len(vlans) == 1 || vnet.AllowTransparent) && vlans[0] == vnet.UniVlan && service != nil {
					return vnet, service
				}
			default:
				logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vnet.VlanControl})
			}
		}
	}
	return nil, nil
}

// GetVnetFromPkt : Locate a service based on the packet received. The packet contains VLANs that
// are used as the key to locate the service. If more than one service is on the
// same port (essentially a UNI of ONU), the services must be separated by different
// CVLANs
func (va *VoltApplication) GetVnetFromPkt(device string, port string, pkt gopacket.Packet) (*VoltPortVnet, *VoltService) {
	vlans := GetVlans(pkt)
	priority := GetPriority(pkt)
	return va.GetVnetFromFields(device, port, vlans, priority)
}

// PushDevFlowForVlan to push icmpv6 flows for vlan
func (va *VoltApplication) PushDevFlowForVlan(cntx context.Context, vnet *VoltVnet) {
	logger.Infow(ctx, "PushDevFlowForVlan", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan})
	pushflow := func(key interface{}, value interface{}) bool {
		device := value.(*VoltDevice)
		if !isDeviceInList(device.SerialNum, vnet.DevicesList) {
			logger.Infow(ctx, "Device not present in vnet device list", log.Fields{"Device": device.SerialNum})
			return true
		}
		if device.State != controller.DeviceStateUP {
			logger.Errorw(ctx, "Push Dev Flows Failed - Device state DOWN", log.Fields{"Port": device.NniPort, "Vlan": vnet.SVlan, "device": device})
			return true
		}
		if applied, ok := device.VlanPortStatus.Load(uint16(vnet.SVlan)); !ok || !applied.(bool) {
			logger.Errorw(ctx, "Push Dev Flows Failed - Vlan not enabled yet", log.Fields{"Port": device.NniPort, "Vlan": vnet.SVlan})
			return true
		}

		if vnetListIntf, ok := device.ConfiguredVlanForDeviceFlows.Get(VnetKey(vnet.SVlan, vnet.CVlan, 0)); ok {
			vnetList := vnetListIntf.(*util.ConcurrentMap)
			vnetList.Set(vnet.Name, true)
			device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
			logger.Infow(ctx, "Flow already pushed for these Vlans. Adding profile to list", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan, "vnetList-len": vnetList.Length()})
			return true
		}
		logger.Debugw(ctx, "Configuring Dev Flows Group for device ", log.Fields{"Device": device})
		err := ProcessIcmpv6McGroup(device.Name, false)
		if err != nil {
			logger.Warnw(ctx, "Configuring Dev Flows Group for device failed ", log.Fields{"Device": device.Name, "err": err})
			return true
		}
		if portID, err := va.GetPortID(device.NniPort); err == nil {
			if state, _ := cntlr.GetController().GetPortState(device.Name, device.NniPort); state != cntlr.PortStateUp {
				logger.Warnw(ctx, "Skipping Dev Flow Configuration - Port Down", log.Fields{"Device": device})
				return true
			}

			// Pushing ICMPv6 Flow
			flow := BuildICMPv6Flow(portID, vnet)
			err = cntlr.GetController().AddFlows(cntx, device.NniPort, device.Name, flow)
			if err != nil {
				logger.Warnw(ctx, "Configuring ICMPv6 Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
				return true
			}
			logger.Infow(ctx, "ICMPv6 Flow Added to Queue", log.Fields{"flow": flow})

			// Pushing ARP Flow
			flow = BuildDSArpFlow(portID, vnet)
			err = cntlr.GetController().AddFlows(cntx, device.NniPort, device.Name, flow)
			if err != nil {
				logger.Warnw(ctx, "Configuring ARP Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
				return true
			}
			logger.Infow(ctx, "ARP Flow Added to Queue", log.Fields{"flow": flow})

			vnetList := util.NewConcurrentMap()
			vnetList.Set(vnet.Name, true)
			device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
		}
		return true
	}
	va.DevicesDisc.Range(pushflow)
}

// PushDevFlowForDevice to push icmpv6 flows for device
func (va *VoltApplication) PushDevFlowForDevice(cntx context.Context, device *VoltDevice) {
	logger.Infow(ctx, "PushDevFlowForDevice", log.Fields{"device": device})

	logger.Debugw(ctx, "Configuring ICMPv6 Group for device ", log.Fields{"Device": device.Name})
	err := ProcessIcmpv6McGroup(device.Name, false)
	if err != nil {
		logger.Warnw(ctx, "Configuring ICMPv6 Group for device failed ", log.Fields{"Device": device.Name, "err": err})
		return
	}
	pushicmpv6 := func(key, value interface{}) bool {
		vnet := value.(*VoltVnet)
		if vnetListIntf, ok := device.ConfiguredVlanForDeviceFlows.Get(VnetKey(vnet.SVlan, vnet.CVlan, 0)); ok {
			vnetList := vnetListIntf.(*util.ConcurrentMap)
			vnetList.Set(vnet.Name, true)
			device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
			logger.Infow(ctx, "Flow already pushed for these Vlans. Adding profile to list", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan, "vnetList-len": vnetList.Length()})
			return true
		}
		nniPortID, err := va.GetPortID(device.NniPort)
		if err != nil {
			logger.Errorw(ctx, "Push ICMPv6 Failed - Failed to get NNI Port Id", log.Fields{"Port": device.NniPort, "Reason": err.Error})
		}
		if applied, ok := device.VlanPortStatus.Load(uint16(vnet.SVlan)); !ok || !applied.(bool) {
			logger.Warnw(ctx, "Push ICMPv6 Failed - Vlan not enabled yet", log.Fields{"Port": device.NniPort, "Vlan": vnet.SVlan})
			return true
		}
		flow := BuildICMPv6Flow(nniPortID, vnet)
		err = cntlr.GetController().AddFlows(cntx, device.NniPort, device.Name, flow)
		if err != nil {
			logger.Warnw(ctx, "Configuring ICMPv6 Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
			return true
		}
		logger.Infow(ctx, "ICMP Flow Added to Queue", log.Fields{"flow": flow})

		flow = BuildDSArpFlow(nniPortID, vnet)
		err = cntlr.GetController().AddFlows(cntx, device.NniPort, device.Name, flow)
		if err != nil {
			logger.Warnw(ctx, "Configuring ARP Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
			return true
		}
		logger.Infow(ctx, "ARP Flow Added to Queue", log.Fields{"flow": flow})

		vnetList := util.NewConcurrentMap()
		vnetList.Set(vnet.Name, true)
		device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
		return true
	}
	va.VnetsByName.Range(pushicmpv6)
}

// DeleteDevFlowForVlan to delete icmpv6 flow for vlan
func (va *VoltApplication) DeleteDevFlowForVlan(cntx context.Context, vnet *VoltVnet) {
	logger.Infow(ctx, "DeleteDevFlowForVlan", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan})
	delflows := func(key interface{}, value interface{}) bool {
		device := value.(*VoltDevice)

		if vnetListIntf, ok := device.ConfiguredVlanForDeviceFlows.Get(VnetKey(vnet.SVlan, vnet.CVlan, 0)); ok {
			vnetList := vnetListIntf.(*util.ConcurrentMap)
			vnetList.Remove(vnet.Name)
			device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
			if vnetList.Length() != 0 {
				logger.Warnw(ctx, "Similar VNet associated to diff service. Not removing ICMPv6 flow", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan, "vnetList-len": vnetList.Length()})
				return true
			}
		}
		if portID, err := va.GetPortID(device.NniPort); err == nil {
			if state, _ := cntlr.GetController().GetPortState(device.Name, device.NniPort); state != cntlr.PortStateUp {
				logger.Warnw(ctx, "Skipping ICMPv6 Flow Deletion - Port Down", log.Fields{"Device": device})
				return true
			}
			// Pushing ICMPv6 Flow
			flow := BuildICMPv6Flow(portID, vnet)
			flow.ForceAction = true
			err := vnet.RemoveFlows(cntx, device, flow)
			if err != nil {
				logger.Warnw(ctx, "De-Configuring ICMPv6 Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
				return true
			}
			logger.Infow(ctx, "ICMPv6 Flow Delete Added to Queue", log.Fields{"flow": flow})

			// Pushing ARP Flow
			flow = BuildDSArpFlow(portID, vnet)
			flow.ForceAction = true
			err = vnet.RemoveFlows(cntx, device, flow)
			if err != nil {
				logger.Warnw(ctx, "De-Configuring ARP Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
				return true
			}
			logger.Infow(ctx, "ARP Flow Delete Added to Queue", log.Fields{"flow": flow})

			device.ConfiguredVlanForDeviceFlows.Remove(VnetKey(vnet.SVlan, vnet.CVlan, 0))
		}
		return true
	}
	va.DevicesDisc.Range(delflows)
}

// DeleteDevFlowForDevice to delete icmpv6 flow for device
func (va *VoltApplication) DeleteDevFlowForDevice(cntx context.Context, device *VoltDevice) {
	logger.Infow(ctx, "DeleteDevFlowForDevice", log.Fields{"Device": device})
	delicmpv6 := func(key, value interface{}) bool {
		vnet := value.(*VoltVnet)
		if vnetListIntf, ok := device.ConfiguredVlanForDeviceFlows.Get(VnetKey(vnet.SVlan, vnet.CVlan, 0)); ok {
			vnetList := vnetListIntf.(*util.ConcurrentMap)
			vnetList.Remove(vnet.Name)
			device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
			if vnetList.Length() != 0 {
				logger.Warnw(ctx, "Similar VNet associated to diff service. Not removing ICMPv6 flow", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan, "vnetList-len": vnetList.Length()})
				return true
			}
		} else {
			logger.Warnw(ctx, "ICMPv6 Flow map entry not found for Vnet", log.Fields{"Vnet": vnet.VnetConfig})
			return true
		}
		nniPortID, err := va.GetPortID(device.NniPort)
		if err != nil {
			logger.Errorw(ctx, "Delete ICMPv6 Failed - Failed to get NNI Port Id", log.Fields{"Port": device.NniPort, "Reason": err.Error})
		}
		flow := BuildICMPv6Flow(nniPortID, vnet)
		flow.ForceAction = true
		err = vnet.RemoveFlows(cntx, device, flow)
		if err != nil {
			logger.Warnw(ctx, "De-Configuring ICMPv6 Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
			return true
		}

		flow = BuildDSArpFlow(nniPortID, vnet)
		flow.ForceAction = true
		err = vnet.RemoveFlows(cntx, device, flow)
		if err != nil {
			logger.Warnw(ctx, "De-Configuring ARP Flow for device failed ", log.Fields{"Device": device.Name, "err": err})
			return true
		}

		device.ConfiguredVlanForDeviceFlows.Remove(VnetKey(vnet.SVlan, vnet.CVlan, 0))
		logger.Infow(ctx, "ICMP Flow Delete Added to Queue", log.Fields{"flow": flow})
		return true
	}
	va.VnetsByName.Range(delicmpv6)
	logger.Debugw(ctx, "De-Configuring ICMPv6 Group for device ", log.Fields{"Device": device.Name})
	err := ProcessIcmpv6McGroup(device.Name, true)
	if err != nil {
		logger.Warnw(ctx, "De-Configuring ICMPv6 Group on device failed ", log.Fields{"Device": device.Name, "err": err})
		return
	}
}

// DeleteDevFlowForVlanFromDevice to delete icmpv6 flow for vlan from device
func (va *VoltApplication) DeleteDevFlowForVlanFromDevice(cntx context.Context, vnet *VoltVnet, deviceSerialNum string) {
	logger.Infow(ctx, "DeleteDevFlowForVlanFromDevice", log.Fields{"Device-serialNum": deviceSerialNum, "SVlan": vnet.SVlan, "CVlan": vnet.CVlan})
	delflows := func(key interface{}, value interface{}) bool {
		device := value.(*VoltDevice)
		if device.SerialNum != deviceSerialNum {
			return true
		}
		if vnetListIntf, ok := device.ConfiguredVlanForDeviceFlows.Get(VnetKey(vnet.SVlan, vnet.CVlan, 0)); ok {
			vnetList := vnetListIntf.(*util.ConcurrentMap)
			vnetList.Remove(vnet.Name)
			device.ConfiguredVlanForDeviceFlows.Set(VnetKey(vnet.SVlan, vnet.CVlan, 0), vnetList)
			if vnetList.Length() != 0 {
				logger.Warnw(ctx, "Similar VNet associated to diff service. Not removing ICMPv6 flow", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan, "vnetList-len": vnetList.Length()})
				return true
			}
		} else if !vgcRebooted && len(vnet.DevicesList) != 0 {
			// Return only in-case of non-reboot/delete scenario. Else, the flows need to be force removed
			// DeviceList check is there to avoid dangling flow in-case of pod restart during service de-activation.
			// The step will be as follow:
			// 1. Deact Service
			// 2. Pod Reboot
			// 3. Pending Delete Service triggered
			// 4. Del Service Ind followed by DelVnet req from NB
			// 5. If Vlan status response is awaited, the ConfiguredVlanForDeviceFlows cache will not have flow info
			// hence the flow will not be cleared
			logger.Warnw(ctx, "Dev Flow map entry not found for Vnet", log.Fields{"PodReboot": vgcRebooted, "VnetDeleteInProgress": vnet.DeleteInProgress})
			return true
		}
		if portID, err := va.GetPortID(device.NniPort); err == nil {
			if state, _ := cntlr.GetController().GetPortState(device.Name, device.NniPort); state != cntlr.PortStateUp {
				logger.Warnw(ctx, "Skipping ICMPv6 Flow Deletion - Port Down", log.Fields{"Device": device})
				return false
			}
			flow := BuildICMPv6Flow(portID, vnet)
			flow.ForceAction = true
			if err := vnet.RemoveFlows(cntx, device, flow); err != nil {
				logger.Warnw(ctx, "Delete Flow Failed", log.Fields{"Device": device, "Flow": flow, "Error": err})
			}
			logger.Infow(ctx, "ICMP Flow Delete Added to Queue", log.Fields{"flow": flow})

			flow = BuildDSArpFlow(portID, vnet)
			flow.ForceAction = true
			if err := vnet.RemoveFlows(cntx, device, flow); err != nil {
				logger.Warnw(ctx, "Delete Flow Failed", log.Fields{"Device": device, "Flow": flow, "Error": err})
			}
			logger.Infow(ctx, "ARP Flow Delete Added to Queue", log.Fields{"flow": flow})
			device.ConfiguredVlanForDeviceFlows.Remove(VnetKey(vnet.SVlan, vnet.CVlan, 0))
		}
		return false
	}
	va.DevicesDisc.Range(delflows)
}

// BuildICMPv6Flow to Build DS flow for ICMPv6
func BuildICMPv6Flow(inport uint32, vnet *VoltVnet) *of.VoltFlow {
	logger.Infow(ctx, "Building ICMPv6 MC Flow", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan})
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()

	subFlow.SetICMPv6Match()
	subFlow.SetMatchVlan(vnet.SVlan)
	subFlow.SetInPort(inport)
	subFlow.SetPopVlan()
	subFlow.SetOutGroup(ICMPv6ArpGroupID)
	subFlow.Cookie = uint64(vnet.CVlan)<<48 | uint64(vnet.SVlan)<<32 | of.IgmpFlowMask | of.DsFlowMask
	subFlow.Priority = of.McFlowPriority
	var metadata uint64
	if vnet.VlanControl == None {
		metadata = uint64(ONUCVlan)<<32 | uint64(vnet.CVlan)
	} else {
		metadata = uint64(vnet.VlanControl)<<32 | uint64(vnet.CVlan)
	}
	subFlow.SetTableMetadata(metadata)
	metadata = uint64(vnet.setPbitRemarking())

	logger.Infow(ctx, "ICMPv6 Pbit Remarking", log.Fields{"RemarkPbit": metadata})
	subFlow.SetWriteMetadata(metadata)
	flow.SubFlows[subFlow.Cookie] = subFlow
	return flow
}

// BuildDSArpFlow Builds DS flow for ARP
func BuildDSArpFlow(inport uint32, vnet *VoltVnet) *of.VoltFlow {
	logger.Infow(ctx, "Building ARP MC Flow", log.Fields{"SVlan": vnet.SVlan, "CVlan": vnet.CVlan})

	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
	subFlow := of.NewVoltSubFlow()

	BcastMAC, _ := net.ParseMAC("FF:FF:FF:FF:FF:FF")
	subFlow.SetArpMatch()
	subFlow.SetMatchDstMac(BcastMAC)
	subFlow.SetMatchVlan(vnet.SVlan)
	subFlow.SetInPort(inport)
	subFlow.SetPopVlan()
	subFlow.SetOutGroup(ICMPv6ArpGroupID)

	subFlow.Cookie = uint64(vnet.CVlan)<<48 | uint64(vnet.SVlan)<<32 | of.DsArpFlowMask | of.DsFlowMask
	subFlow.Priority = of.McFlowPriority

	var metadata uint64
	if vnet.VlanControl == None {
		metadata = uint64(ONUCVlan)<<32 | uint64(vnet.CVlan)
	} else {
		metadata = uint64(vnet.VlanControl)<<32 | uint64(vnet.CVlan)
	}
	subFlow.SetTableMetadata(metadata)
	metadata = uint64(vnet.setPbitRemarking())
	subFlow.SetWriteMetadata(metadata)

	flow.SubFlows[subFlow.Cookie] = subFlow
	logger.Infow(ctx, "ARP Pbit Remarking", log.Fields{"RemarkPbit": metadata})
	return flow
}

// setPbitRemarking to set Pbit remarking
func (vv *VoltVnet) setPbitRemarking() uint32 {
	// 	                              Remarkable
	// 	         Remarked Pbit          Pbit
	// |-----------------------------| |------|
	// |7| |6| |5| |4| |3| |2| |1| |0| 76543210
	// 000 000 000 000 000 000 000 000 00000000

	// Eg:
	// For 6:3 & 7:1
	// 001 011 000 000 000 000 000 000 11000000

	var remarkable uint8
	var remarked uint32
	for refPbit, remarkPbit := range vv.CtrlPktPbitRemark {
		remarkable = remarkable | 1<<refPbit
		remarked = remarked | uint32(remarkPbit)<<(refPbit*3)
	}
	return remarked<<8 | uint32(remarkable)
}

// ProcessIcmpv6McGroup to add icmpv6 multicast group
func ProcessIcmpv6McGroup(device string, delete bool) error {
	logger.Info(ctx, "Creating ICMPv6 MC Group")
	va := GetApplication()
	vd := va.GetDevice(device)
	group := &of.Group{}
	group.GroupID = ICMPv6ArpGroupID
	group.Device = device
	if delete {
		if !vd.icmpv6GroupAdded {
			logger.Info(ctx, "ICMPv6 MC Group is already deleted. Ignoring  icmpv6 group Delete")
			return nil //TODO
		}
		vd.icmpv6GroupAdded = false
		group.Command = of.GroupCommandDel
		group.ForceAction = true
	} else {
		if vd.icmpv6GroupAdded {
			logger.Info(ctx, "ICMPv6 MC Group is already added. Ignoring icmpv6 group Add")
			return nil //TODO
		}
		vd.icmpv6GroupAdded = true
		group.Command = of.GroupCommandAdd
		receivers := GetApplication().GetIcmpv6Receivers(device)
		group.Buckets = append(group.Buckets, receivers...)
	}
	logger.Infow(ctx, "ICMPv6 MC Group Action", log.Fields{"Device": device, "Delete": delete})
	port, _ := GetApplication().GetNniPort(device)
	err := cntlr.GetController().GroupUpdate(port, device, group)
	return err
}

// isVlanMatching - checks is vlans matches with vpv based on vlan control
func (vpv *VoltPortVnet) isVlanMatching(cvlan of.VlanType, svlan of.VlanType) bool {
	switch vpv.VlanControl {
	case ONUCVlanOLTSVlan,
		OLTCVlanOLTSVlan:
		if vpv.SVlan == svlan && vpv.CVlan == cvlan {
			return true
		}
	case ONUCVlan,
		OLTSVlan,
		None:
		if vpv.SVlan == svlan {
			return true
		}
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
	}
	return false
}

// PushFlows - Triggers flow addition after registering for flow indication event
func (vpv *VoltPortVnet) PushFlows(cntx context.Context, device *VoltDevice, flow *of.VoltFlow) error {
	for cookie := range flow.SubFlows {
		cookie := strconv.FormatUint(cookie, 10)
		fe := &FlowEvent{
			eType:     EventTypeControlFlowAdded,
			cookie:    cookie,
			eventData: vpv,
		}
		device.RegisterFlowAddEvent(cookie, fe)
	}
	return cntlr.GetController().AddFlows(cntx, vpv.Port, device.Name, flow)
}

// FlowInstallFailure - Process flow failure indication and triggers HSIA failure for all associated services
func (vpv *VoltPortVnet) FlowInstallFailure(cookie string, errorCode uint32, errReason string) {
	sendFlowFailureInd := func(key, value interface{}) bool {
		//svc := value.(*VoltService)
		//TODO-COMM: svc.triggerServiceFailureInd(errorCode, errReason)
		return true
	}
	logger.Errorw(ctx, "Control Flow Add Failure Notification", log.Fields{"uniPort": vpv.Port, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason})
	vpv.services.Range(sendFlowFailureInd)
}

// RemoveFlows - Triggers flow deletion after registering for flow indication event
func (vpv *VoltPortVnet) RemoveFlows(cntx context.Context, device *VoltDevice, flow *of.VoltFlow) error {
	vpv.PendingFlowLock.Lock()
	defer vpv.PendingFlowLock.Unlock()

	for cookie := range flow.SubFlows {
		cookie := strconv.FormatUint(cookie, 10)
		fe := &FlowEvent{
			eType:     EventTypeControlFlowRemoved,
			device:    device.Name,
			cookie:    cookie,
			eventData: vpv,
		}
		device.RegisterFlowDelEvent(cookie, fe)
		vpv.PendingDeleteFlow[cookie] = true
	}
	return cntlr.GetController().DelFlows(cntx, vpv.Port, device.Name, flow)
}

// CheckAndDeleteVpv - remove VPV from DB is there are no pending flows to be removed
func (vpv *VoltPortVnet) CheckAndDeleteVpv(cntx context.Context) {
	vpv.PendingFlowLock.RLock()
	defer vpv.PendingFlowLock.RUnlock()
	if !vpv.DeleteInProgress {
		return
	}
	if len(vpv.PendingDeleteFlow) == 0 && !vpv.FlowsApplied {
		logger.Infow(ctx, "All Flows removed for VPV. Triggering VPV Deletion from DB", log.Fields{"VPV Port": vpv.Port, "Device": vpv.Device, "Vnet": vpv.VnetName})
		vpv.DelFromDb(cntx)
		logger.Infow(ctx, "Deleted VPV from DB/Cache successfully", log.Fields{"VPV Port": vpv.Port, "Device": vpv.Device, "Vnet": vpv.VnetName})
	}
}

// FlowRemoveSuccess - Process flow success indication
func (vpv *VoltPortVnet) FlowRemoveSuccess(cntx context.Context, cookie string, device string) {
	vpv.PendingFlowLock.Lock()
	logger.Infow(ctx, "VPV Flow Remove Success Notification", log.Fields{"Port": vpv.Port, "Cookie": cookie, "Device": device})

	delete(vpv.PendingDeleteFlow, cookie)
	vpv.PendingFlowLock.Unlock()
	vpv.CheckAndDeleteVpv(cntx)
	vpv.WriteToDb(cntx)
}

// FlowRemoveFailure - Process flow failure indication and triggers Del HSIA failure for all associated services
func (vpv *VoltPortVnet) FlowRemoveFailure(cntx context.Context, cookie string, device string, errorCode uint32, errReason string) {
	vpv.PendingFlowLock.Lock()

	logger.Errorw(ctx, "VPV Flow Remove Failure Notification", log.Fields{"Port": vpv.Port, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason, "Device": device})

	sendFlowFailureInd := func(key, value interface{}) bool {
		svc := value.(*VoltService)
		svc.triggerServiceFailureInd(errorCode, errReason)
		return true
	}
	logger.Errorw(ctx, "Control Flow Del Failure Notification", log.Fields{"uniPort": vpv.Port, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason})
	vpv.services.Range(sendFlowFailureInd)

	if vpv.DeleteInProgress {
		delete(vpv.PendingDeleteFlow, cookie)
		vpv.PendingFlowLock.Unlock()
		vpv.CheckAndDeleteVpv(cntx)
	} else {
		vpv.PendingFlowLock.Unlock()
		vpv.WriteToDb(cntx)
	}
}

// RemoveFlows - Triggers flow deletion after registering for flow indication event
func (vv *VoltVnet) RemoveFlows(cntx context.Context, device *VoltDevice, flow *of.VoltFlow) error {
	vv.VnetLock.Lock()
	defer vv.VnetLock.Unlock()

	var flowMap map[string]bool
	var ok bool

	for cookie := range flow.SubFlows {
		cookie := strconv.FormatUint(cookie, 10)
		fe := &FlowEvent{
			eType:     EventTypeDeviceFlowRemoved,
			device:    device.Name,
			cookie:    cookie,
			eventData: vv,
		}
		device.RegisterFlowDelEvent(cookie, fe)
		if flowMap, ok = vv.PendingDeleteFlow[device.Name]; !ok {
			flowMap = make(map[string]bool)
		}
		flowMap[cookie] = true
		vv.PendingDeleteFlow[device.Name] = flowMap
	}
	vv.WriteToDb(cntx)
	return cntlr.GetController().DelFlows(cntx, device.NniPort, device.Name, flow)
}

// CheckAndDeleteVnet - remove Vnet from DB is there are no pending flows to be removed
func (vv *VoltVnet) CheckAndDeleteVnet(cntx context.Context, device string) {
	if !vv.DeleteInProgress {
		return
	}
	vv.VnetPortLock.RLock()
	if len(vv.PendingDeleteFlow[device]) == 0 && !vv.isAssociatedPortsPresent() {
		logger.Warnw(ctx, "Deleting Vnet : All flows removed", log.Fields{"Name": vv.Name, "AssociatedPorts": vv.AssociatedPorts, "Device": device})
		GetApplication().deleteVnetConfig(vv)
		_ = db.DelVnet(cntx, vv.Name)
		logger.Infow(ctx, "Deleted Vnet from DB/Cache successfully", log.Fields{"Device": device, "Vnet": vv.Name})
	} else {
		logger.Warnw(ctx, "Skipping Del Vnet", log.Fields{"Name": vv.Name, "AssociatedPorts": vv.AssociatedPorts, "PendingDelFlows": vv.PendingDeleteFlow[device]})
	}
	vv.VnetPortLock.RUnlock()
}

// FlowRemoveSuccess - Process flow success indication
func (vv *VoltVnet) FlowRemoveSuccess(cntx context.Context, cookie string, device string) {
	vv.VnetLock.Lock()
	defer vv.VnetLock.Unlock()

	logger.Infow(ctx, "Vnet Flow Remove Success Notification", log.Fields{"VnetProfile": vv.Name, "Cookie": cookie, "Device": device})

	if _, ok := vv.PendingDeleteFlow[device]; ok {
		delete(vv.PendingDeleteFlow[device], cookie)
	}

	//Check and update success for pending disable request
	if d := GetApplication().GetDevice(device); d != nil {
		_, present := d.ConfiguredVlanForDeviceFlows.Get(VnetKey(vv.SVlan, vv.CVlan, 0))
		if !present && len(vv.PendingDeleteFlow[device]) == 0 {
			vv.CheckAndDeleteVnet(cntx, device)
		}
	}
	vv.WriteToDb(cntx)
}

// FlowRemoveFailure - Process flow failure indication
func (vv *VoltVnet) FlowRemoveFailure(cntx context.Context, cookie string, device string, errorCode uint32, errReason string) {
	vv.VnetLock.Lock()
	defer vv.VnetLock.Unlock()

	if flowMap, ok := vv.PendingDeleteFlow[device]; ok {
		if _, ok := flowMap[cookie]; ok {
			logger.Errorw(ctx, "Device Flow Remove Failure Notification", log.Fields{"Vnet": vv.Name, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason, "Device": device})

			if vv.DeleteInProgress {
				delete(vv.PendingDeleteFlow[device], cookie)
				vv.CheckAndDeleteVnet(cntx, device)
			}
			return
		}
	}
	logger.Errorw(ctx, "Device Flow Remove Failure Notification for Unknown cookie", log.Fields{"Vnet": vv.Name, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason})
}

// IgmpFlowInstallFailure - Process flow failure indication and triggers HSIA failure for Igmp enabled services
func (vpv *VoltPortVnet) IgmpFlowInstallFailure(cookie string, errorCode uint32, errReason string) {
	// Note: Current implementation supports only for single service with Igmp Enabled for a subscriber
	// When multiple Igmp-suported service enabled, comment "return false"

	sendFlowFailureInd := func(key, value interface{}) bool {
		svc := value.(*VoltService)
		if svc.IgmpEnabled {
			svc.triggerServiceFailureInd(errorCode, errReason)
			return false
		}
		return true
	}
	logger.Errorw(ctx, "US IGMP Flow Failure Notification", log.Fields{"uniPort": vpv.Port, "Cookie": cookie, "ErrorCode": errorCode, "ErrorReason": errReason})
	vpv.services.Range(sendFlowFailureInd)
}

// GetMatchingMcastService to get matching multicast service
func (va *VoltApplication) GetMatchingMcastService(port string, device string, cvlan of.VlanType) *VoltService {
	var service *VoltService
	dIntf, ok := va.DevicesDisc.Load(device)
	if !ok {
		return nil
	}
	d := dIntf.(*VoltDevice)

	// If the port is NNI port, the services dont exist on it. The svc then
	// must be obtained from a different context and is not included here
	if port == d.NniPort {
		return nil
	}

	// This is an access port and the port should have all the associated
	// services which can be uniquely identified by the VLANs in the packet
	vnets, ok := va.VnetsByPort.Load(port)

	if !ok {
		logger.Debugw(ctx, "No Vnets for port", log.Fields{"Port": port})
		return nil
	}
	logger.Debugw(ctx, "Matching for VLANs", log.Fields{"VLANs": cvlan})
	getMcastService := func(key, value interface{}) bool {
		srv := value.(*VoltService)
		if srv.IgmpEnabled {
			service = srv

			//TODO: Current implementation supports only for single service with Igmp Enabled
			//FIX-ME:  When multiple service suports Igmp, update of logic required
			return false
		}
		return true
	}

	for _, vpv := range vnets.([]*VoltPortVnet) {
		if vpv.CVlan == cvlan {
			vpv.services.Range(getMcastService)
			if service != nil {
				break
			}
		}
	}
	return service
}

// TriggerAssociatedFlowDelete - Re-trigger delete for pending delete flows
func (vv *VoltVnet) TriggerAssociatedFlowDelete(cntx context.Context, device string) bool {
	vv.VnetLock.Lock()
	cookieList := []uint64{}
	flowMap := vv.PendingDeleteFlow[device]

	for cookie := range flowMap {
		cookieList = append(cookieList, convertToUInt64(cookie))
	}
	vv.VnetLock.Unlock()

	if len(cookieList) == 0 {
		return false
	}

	for _, cookie := range cookieList {
		if vd := GetApplication().GetDevice(device); vd != nil {
			flow := &of.VoltFlow{}
			flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
			subFlow := of.NewVoltSubFlow()
			subFlow.Cookie = cookie
			flow.SubFlows[cookie] = subFlow
			logger.Infow(ctx, "Retriggering Vnet Delete Flow", log.Fields{"Device": device, "Vnet": vv.Name, "Cookie": cookie})
			if err := vv.RemoveFlows(cntx, vd, flow); err != nil {
				logger.Warnw(ctx, "Vnet Delete Flow Failed", log.Fields{"Device": device, "Vnet": vv.Name, "Cookie": cookie, "Error": err})
			}
		}
	}
	return true
}

// JSONMarshal wrapper function for json Marshal VoltVnet
func (vv *VoltVnet) JSONMarshal() ([]byte, error) {
	return json.Marshal(VoltVnet{
		VnetConfig: vv.VnetConfig,
		Version:    vv.Version,
		VnetOper: VnetOper{
			PendingDeleteFlow:     vv.VnetOper.PendingDeleteFlow,
			DeleteInProgress:      vv.VnetOper.DeleteInProgress,
			PendingDeviceToDelete: vv.VnetOper.PendingDeviceToDelete,
		},
	})
}

// JSONMarshal wrapper function for json Marshal VoltPortVnet
func (vpv *VoltPortVnet) JSONMarshal() ([]byte, error) {
	return json.Marshal(VoltPortVnet{
		Device:                     vpv.Device,
		Port:                       vpv.Port,
		PonPort:                    vpv.PonPort,
		VnetName:                   vpv.VnetName,
		SVlan:                      vpv.SVlan,
		CVlan:                      vpv.CVlan,
		UniVlan:                    vpv.UniVlan,
		SVlanTpid:                  vpv.SVlanTpid,
		DhcpRelay:                  vpv.DhcpRelay,
		ArpRelay:                   vpv.ArpRelay,
		PppoeIa:                    vpv.PppoeIa,
		MacLearning:                vpv.MacLearning,
		DhcpStatus:                 vpv.DhcpStatus,
		DhcpExpiryTime:             vpv.DhcpExpiryTime,
		Dhcp6ExpiryTime:            vpv.Dhcp6ExpiryTime,
		FlowsApplied:               vpv.FlowsApplied,
		Ipv4Addr:                   vpv.Ipv4Addr,
		Ipv6Addr:                   vpv.Ipv6Addr,
		MacAddr:                    vpv.MacAddr,
		LearntMacAddr:              vpv.LearntMacAddr,
		CircuitID:                  vpv.CircuitID,
		RemoteID:                   vpv.RemoteID,
		IsOption82Disabled:         vpv.IsOption82Disabled,
		RelayState:                 vpv.RelayState,
		PPPoeState:                 vpv.PPPoeState,
		RelayStatev6:               vpv.RelayStatev6,
		IgmpEnabled:                vpv.IgmpEnabled,
		IgmpFlowsApplied:           vpv.IgmpFlowsApplied,
		McastService:               vpv.McastService,
		ONTEtherTypeClassification: vpv.ONTEtherTypeClassification,
		VlanControl:                vpv.VlanControl,
		MvlanProfileName:           vpv.MvlanProfileName,
		Version:                    vpv.Version,
		McastTechProfileID:         vpv.McastTechProfileID,
		McastPbit:                  vpv.McastPbit,
		McastUsMeterID:             vpv.McastUsMeterID,
		AllowTransparent:           vpv.AllowTransparent,
		SchedID:                    vpv.SchedID,
		DHCPv6DUID:                 vpv.DHCPv6DUID,
		PendingDeleteFlow:          vpv.PendingDeleteFlow,
		DeleteInProgress:           vpv.DeleteInProgress,
		Blocked:                    vpv.Blocked,
		DhcpPbit:                   vpv.DhcpPbit,
	})
}

func (vpv *VoltPortVnet) IsServiceActivated(cntx context.Context) bool {
	isActivated := false
	vpv.services.Range(func(key, value interface{}) bool {
		svc := value.(*VoltService)
		if svc.IsActivated {
			logger.Infow(ctx, "Found activated service on the vpv", log.Fields{"Name": svc.Name})
			isActivated = true
			return false //to exit loop
		}
		return true
	})
	return isActivated
}
