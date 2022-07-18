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
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	infraerrorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket/layers"

	"voltha-go-controller/internal/pkg/controller"
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

const (
	// DSLAttrEnabled constant
	DSLAttrEnabled string = "ENABLED"
)

// VoltServiceCfg structure
// Name -	Uniquely identifies a service across the entire application
// UniVlan -	The VLAN of the packets entering the UNI of ONU
// CVlan -	The VLAN to transalate to/from on the PON link
// SVlan -	The outer VLAN to be used on the NNI of OLT.
//       -	In general, 4096 is used as NO VLAN for all the above
// SVlanTpid - SVlan Tag Protocl Identifier
// Pbits -      Each bit of uint8 represents one p-bit. MSB is pbit 7
// DhcpRelay -	Whether it is turned on/off
// CircuitId -	The circuit id to be used with DHCP relay. Unused otherwise
// RemoveId - 	Same as above
// Port -	The access port for the service. Each service has a single access
//		port. The converse is not always true
// MacLearning - If MAC learning is turned on, the MAC address learned from the
//		the service activation is used in programming flows
// MacAddress -	The MAC hardware address learnt on the UNI interface
// MacAddresses - Not yet implemented. To be used to learn more MAC addresses
type VoltServiceCfg struct {
	Name                       string
	UniVlan                    of.VlanType
	CVlan                      of.VlanType
	SVlan                      of.VlanType
	SVlanTpid                  layers.EthernetType
	MacAddr                    net.HardwareAddr
	Pbits                      []of.PbitType
	DsRemarkPbitsMap           map[int]int // Ex: Remark case {0:0,1:0} and No-remark case {1:1}
	TechProfileID              uint16
	CircuitID                  string
	RemoteID                   []byte
	Port                       string
	PonPort                    uint32
	MacLearning                MacLearningType
	IsOption82Disabled         bool
	IgmpEnabled                bool
	McastService               bool
	ONTEtherTypeClassification int
	VlanControl                VlanControl
	UsMeterProfile             string
	DsMeterProfile             string
	AggDsMeterProfile          string
	VnetID                     string
	MvlanProfileName           string
	RemoteIDType               string
	SchedID                    int
	AllowTransparent           bool
	EnableMulticastKPI         bool
	DataRateAttr               string
	MinDataRateUs              uint32
	MinDataRateDs              uint32
	MaxDataRateUs              uint32
	MaxDataRateDs              uint32

	Trigger ServiceTrigger
}

// VoltServiceOper structure
type VoltServiceOper struct {
	//MacLearning  bool
	//MacAddr      net.HardwareAddr
	Device   string
	Ipv4Addr net.IP
	Ipv6Addr net.IP

	UsMeterID    uint32
	DsMeterID    uint32
	AggDsMeterID uint32

	//Multiservice-Fix
	UsHSIAFlowsApplied bool
	DsHSIAFlowsApplied bool
	UsDhcpFlowsApplied bool
	DsDhcpFlowsApplied bool
	IgmpFlowsApplied   bool
	Icmpv6FlowsApplied bool

	ServiceLock      sync.RWMutex `json:"-"`
	PendingFlows     map[string]bool
	AssociatedFlows  map[string]bool
	DeleteInProgress bool
	ForceDelete      bool
	BwAvailInfo      string

	UpdateInProgress bool
	Metadata         interface{}
}

// VoltService structure
type VoltService struct {
	VoltServiceCfg
	VoltServiceOper
	Version string
}

//ServiceTrigger - Service activation trigger
type ServiceTrigger int

const (
	//NBActivate - Service added due to NB Action
	NBActivate ServiceTrigger = 0
	//ServiceVlanUpdate - Service added due to Svlan Update
	ServiceVlanUpdate ServiceTrigger = 1
)

// AppMutexes structure
type AppMutexes struct {
	ServiceDataMutex sync.Mutex `json:"-"`
	VnetMutex        sync.Mutex `json:"-"`
}

//MigrateServiceMetadata - migrate services request metadata
type MigrateServiceMetadata struct {
	NewVnetID string
	RequestID string
}

// AppMutex variable
var AppMutex AppMutexes

// NewVoltService for constructor for volt service
func NewVoltService(cfg *VoltServiceCfg) *VoltService {
	var vs VoltService
	vs.VoltServiceCfg = *cfg
	vs.UsHSIAFlowsApplied = false
	vs.DsHSIAFlowsApplied = false
	vs.DeleteInProgress = false
	//vs.MacAddr, _ = net.ParseMAC("00:00:00:00:00:00")

	vs.MacAddr = cfg.MacAddr
	vs.Ipv4Addr = net.ParseIP("0.0.0.0")
	vs.Ipv6Addr = net.ParseIP("::")
	vs.PendingFlows = make(map[string]bool)
	vs.AssociatedFlows = make(map[string]bool)
	return &vs
}

// WriteToDb commit a service to the DB if service delete is not in-progress
func (vs *VoltService) WriteToDb() {

	vs.ServiceLock.RLock()
	defer vs.ServiceLock.RUnlock()

	if vs.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Redis Update for Service, Service delete in progress", log.Fields{"Service": vs.Name})
		return
	}
	vs.ForceWriteToDb()
}

//ForceWriteToDb force commit a service to the DB
func (vs *VoltService) ForceWriteToDb() {
	b, err := json.Marshal(vs)

	if err != nil {
		logger.Errorw(ctx, "Json Marshal Failed for Service", log.Fields{"Service": vs.Name})
		return
	}
	if err1 := db.PutService(vs.Name, string(b)); err1 != nil {
		logger.Errorw(ctx, "DB write oper failed for Service", log.Fields{"Service": vs.Name})
	}
}

// isDataRateAttrPresent to check if data attribute is present
func (vs *VoltService) isDataRateAttrPresent() bool {
	return vs.DataRateAttr == DSLAttrEnabled
}

// DelFromDb delete a service from DB
func (vs *VoltService) DelFromDb() {
	logger.Debugw(ctx, "Deleting Service from DB", log.Fields{"Name": vs.Name})
	//TODO - Need to understand and delete the second call
	//Calling twice has worked though don't know why
	_ = db.DelService(vs.Name)
	_ = db.DelService(vs.Name)
}

// MatchesVlans find the service that matches the VLANs. In this case it is
// purely based on CVLAN. The CVLAN can sufficiently be used to
// match a service
func (vs *VoltService) MatchesVlans(vlans []of.VlanType) bool {
	if len(vlans) != 1 {
		return false
	}

	if vlans[0] == vs.CVlan {
		return true
	}
	return false
}

// MatchesPbits allows matching a service to a pbit. This is used
// to search for a service matching the pbits, typically to identify
// attributes for other flows such as DHCP, IGMP, etc.
func (vs *VoltService) MatchesPbits(pbits []of.PbitType) bool {
	for _, pbit := range pbits {
		for _, pb := range vs.Pbits {
			if pb == pbit {
				return true
			}
		}
	}
	return false
}

// IsPbitExist allows matching a service to a pbit. This is used
// to search for a service matching the pbit
func (vs *VoltService) IsPbitExist(pbit of.PbitType) bool {
	for _, pb := range vs.Pbits {
		if pb == pbit {
			return true
		}
	}
	return false
}

// AddHsiaFlows - Adds US & DS HSIA Flows for the service
func (vs *VoltService) AddHsiaFlows() {
	if err := vs.AddUsHsiaFlows(); err != nil {
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}
	if err := vs.AddDsHsiaFlows(); err != nil {
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}
}

//DelHsiaFlows - Deletes US & DS HSIA Flows for the service
func (vs *VoltService) DelHsiaFlows() {
	if err := vs.DelUsHsiaFlows(); err != nil {
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}

	if err := vs.DelDsHsiaFlows(); err != nil {
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}
}

// AddUsHsiaFlows - Add US HSIA Flows for the service
func (vs *VoltService) AddUsHsiaFlows() error {

	if vs.DeleteInProgress || vs.UpdateInProgress {
		logger.Errorw(ctx, "Ignoring US HSIA Flow Push, Service deleteion In-Progress", log.Fields{"Device": vs.Device, "Service": vs.Name})
		return nil
	}

	va := GetApplication()
	logger.Infow(ctx, "Configuring US HSIA Service Flows", log.Fields{"ServiceName": vs.Name})
	if !vs.UsHSIAFlowsApplied || vgcRebooted {
		device, err := va.GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device", log.Fields{"Reason": err.Error()})
			return errorCodes.ErrDeviceNotFound
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Ignoring US HSIA Flow Push", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return nil
		}

		vs.Device = device.Name
		va.AddMeterToDevice(vs.Port, device.Name, vs.UsMeterID, 0)
		va.AddMeterToDevice(vs.Port, device.Name, vs.DsMeterID, vs.AggDsMeterID)

		logger.Infow(ctx, "Adding HSIA flows", log.Fields{"Name": vs.Name})
		pBits := vs.Pbits

		//If no pbits configured for service, hence add PbitNone for flows
		if len(vs.Pbits) == 0 {
			pBits = append(pBits, PbitMatchNone)
		}
		for _, pbits := range pBits {
			usflows, err := vs.BuildUsHsiaFlows(pbits)
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA US flows", log.Fields{"Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
				continue
			}
			usflows.MigrateCookie = vgcRebooted
			if err := vs.AddFlows(device, usflows); err != nil {
				logger.Errorw(ctx, "Error adding HSIA US flows", log.Fields{"Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		}
		vs.UsHSIAFlowsApplied = true
		logger.Infow(ctx, "Pushed US HSIA Service Flows", log.Fields{"ServiceName": vs.Name})
	}
	vs.WriteToDb()
	return nil
}

// AddDsHsiaFlows - Add DS HSIA Flows for the service
func (vs *VoltService) AddDsHsiaFlows() error {
	if vs.DeleteInProgress {
		logger.Errorw(ctx, "Ignoring DS HSIA Flow Push, Service deleteion In-Progress", log.Fields{"Device": vs.Device, "Service": vs.Name})
		return nil
	}

	va := GetApplication()
	logger.Infow(ctx, "Configuring DS HSIA Service Flows", log.Fields{"ServiceName": vs.Name})
	if !vs.DsHSIAFlowsApplied || vgcRebooted {
		device, err := va.GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device", log.Fields{"Reason": err.Error()})
			return errorCodes.ErrDeviceNotFound
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Ignoring DS HSIA Flow Push", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return nil
		}

		va.AddMeterToDevice(vs.Port, device.Name, vs.DsMeterID, vs.AggDsMeterID)
		logger.Infow(ctx, "Adding HSIA flows", log.Fields{"Name": vs.Name})

		//If no pbits configured for service, hence add PbitNone for flows
		if len(vs.DsRemarkPbitsMap) == 0 {
			dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(of.PbitMatchNone))
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Reason": err.Error()})
				return err
			}
			dsflows.MigrateCookie = vgcRebooted
			if err = vs.AddFlows(device, dsflows); err != nil {
				logger.Errorw(ctx, "Failed to add HSIA DS flows", log.Fields{"Reason": err})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		} else {
			// if all 8 p-bits are to be remarked to one-pbit, configure all-to-one remarking flow
			if _, ok := vs.DsRemarkPbitsMap[int(of.PbitMatchAll)]; ok {
				dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(of.PbitMatchAll))
				if err != nil {
					logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Reason": err.Error()})
					return err
				}
				logger.Debug(ctx, "Add-one-match-all-pbit-flow")
				dsflows.MigrateCookie = vgcRebooted
				if err := vs.AddFlows(device, dsflows); err != nil {
					logger.Errorw(ctx, "Failed to add HSIA DS flows", log.Fields{"Reason": err})
					statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
					vs.triggerServiceFailureInd(statusCode, statusMessage)
				}
			} else {
				for matchPbit := range vs.DsRemarkPbitsMap {
					dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(matchPbit))
					if err != nil {
						logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Reason": err.Error()})
						statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
						vs.triggerServiceFailureInd(statusCode, statusMessage)
						continue
					}
					dsflows.MigrateCookie = vgcRebooted
					if err := vs.AddFlows(device, dsflows); err != nil {
						logger.Errorw(ctx, "Failed to Add HSIA DS flows", log.Fields{"Reason": err})
						statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
						vs.triggerServiceFailureInd(statusCode, statusMessage)
					}
				}
			}
		}
		vs.DsHSIAFlowsApplied = true
		logger.Infow(ctx, "Pushed DS HSIA Service Flows", log.Fields{"ServiceName": vs.Name})
	}
	vs.WriteToDb()
	return nil
}

// DelUsHsiaFlows - Deletes US HSIA Flows for the service
func (vs *VoltService) DelUsHsiaFlows() error {

	logger.Infow(ctx, "Removing US HSIA Services", log.Fields{"Services": vs.Name})
	if vs.UsHSIAFlowsApplied || vgcRebooted {
		device, err := GetApplication().GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device", log.Fields{"Reason": err.Error()})
			return errorCodes.ErrDeviceNotFound
		}

		logger.Infow(ctx, "Removing HSIA flows", log.Fields{"Name": vs.Name})
		pBits := vs.Pbits

		//If no pbits configured for service, hence add PbitNone for flows
		if len(vs.Pbits) == 0 {
			pBits = append(pBits, PbitMatchNone)
		}
		for _, pbits := range pBits {
			usflows, err := vs.BuildUsHsiaFlows(pbits)
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA US flows", log.Fields{"Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
				continue
			}
			usflows.MigrateCookie = vgcRebooted
			if err = vs.DelFlows(device, usflows); err != nil {
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		}
		vs.UsHSIAFlowsApplied = false
	}
	vs.WriteToDb()
	return nil
}

// DelDsHsiaFlows - Deletes DS HSIA Flows for the service
func (vs *VoltService) DelDsHsiaFlows() error {

	logger.Infow(ctx, "Removing DS HSIA Services", log.Fields{"Services": vs.Name})
	if vs.DsHSIAFlowsApplied || vgcRebooted {
		device, err := GetApplication().GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device", log.Fields{"Reason": err.Error()})
			return errorCodes.ErrDeviceNotFound
		}

		logger.Infow(ctx, "Removing HSIA flows", log.Fields{"Name": vs.Name})
		var matchPbit int
		//If no pbits configured for service, hence add PbitNone for flows
		if len(vs.DsRemarkPbitsMap) == 0 {
			dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(PbitMatchNone))
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Reason": err.Error()})
				return err
			}
			dsflows.MigrateCookie = vgcRebooted
			if err = vs.DelFlows(device, dsflows); err != nil {
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		} else if _, ok := vs.DsRemarkPbitsMap[int(PbitMatchAll)]; ok {
			dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(int(PbitMatchAll)))
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Reason": err.Error()})
				return err
			}
			dsflows.MigrateCookie = vgcRebooted
			if err = vs.DelFlows(device, dsflows); err != nil {
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		} else {
			for matchPbit = range vs.DsRemarkPbitsMap {
				dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(matchPbit))
				if err != nil {
					logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Reason": err.Error()})
					statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
					vs.triggerServiceFailureInd(statusCode, statusMessage)
					continue
				}
				dsflows.MigrateCookie = vgcRebooted
				if err = vs.DelFlows(device, dsflows); err != nil {
					statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
					vs.triggerServiceFailureInd(statusCode, statusMessage)
				}
			}
		}
		vs.DsHSIAFlowsApplied = false
	}
	logger.Infow(ctx, "Deleted HSIA DS flows from DB successfuly", log.Fields{"ServiceName": vs.Name})
	// Post HSIA configuration success indication on message bus
	vs.WriteToDb()
	return nil
}

// BuildDsHsiaFlows build the DS HSIA flows
// Called for add/delete HSIA flows
func (vs *VoltService) BuildDsHsiaFlows(pbits of.PbitType) (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)

	// Get the out and in ports for the flows
	device, err := GetApplication().GetDeviceFromPort(vs.Port)
	if err != nil {
		return nil, errorCodes.ErrDeviceNotFound
	}
	inport, _ := GetApplication().GetPortID(device.NniPort)
	outport, _ := GetApplication().GetPortID(vs.Port)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = outport
	flow.PortName = vs.Port
	allowTransparent := 0
	if vs.AllowTransparent {
		allowTransparent = 1
	}

	// initialized actnPbit to 0 for cookie genration backward compatibility.
	var actnPbit of.PbitType
	remarkPbit, remarkExists := vs.DsRemarkPbitsMap[int(pbits)]

	generateDSCookie := func(vlan of.VlanType, valToShift uint64) uint64 {
		//| 12-bit cvlan/UniVlan | 4 bits action pbit | <32-bits uniport>| 16-bits HSIA mask OR flow mask OR pbit |
		cookie := uint64(vlan)<<52 + uint64(actnPbit)<<48 + uint64(outport)<<16 | of.HsiaFlowMask
		cookie = cookie | of.DsFlowMask
		cookie = cookie + (valToShift << 4) + uint64(pbits)
		return cookie
	}

	l2ProtoValue, err := GetMetadataForL2Protocol(vs.SVlanTpid)
	if err != nil {
		logger.Errorw(ctx, "DS HSIA flow push failed: Invalid SvlanTpid", log.Fields{"SvlanTpid": vs.SVlanTpid, "Service": vs.Name})
		return nil, err
	}

	// Add Table-0 flow that deals with the outer VLAN in pOLT
	{
		subflow1 := of.NewVoltSubFlow()
		subflow1.SetTableID(0)
		subflow1.SetGoToTable(1)
		subflow1.SetInPort(inport)

		if pbits != PbitMatchNone {
			subflow1.SetMatchPbit(pbits)
		}

		if remarkExists && (of.PbitType(remarkPbit) != pbits) {
			subflow1.SetPcp(of.PbitType(remarkPbit))
			// match & action pbits are different, set remark-pbit action
			actnPbit = of.PbitType(remarkPbit)
			// mask remark p-bit to 4bits
			actnPbit = actnPbit & 0x0F
		}

		if err := vs.setDSMatchActionVlanT0(subflow1); err != nil {
			return nil, err
		}
		logger.Info(ctx, "HSIA DS flows MAC Learning & MAC", log.Fields{"ML": vs.MacLearning, "Mac": vs.MacAddr})
		if NonZeroMacAddress(vs.MacAddr) {
			subflow1.SetMatchDstMac(vs.MacAddr)
		}
		subflow1.Priority = of.HsiaFlowPriority
		subflow1.SetMeterID(vs.DsMeterID)

		/* WriteMetaData 8 Byte(uint64) usage:
		| Byte8    | Byte7    | Byte6 | Byte5  | Byte4  | Byte3   | Byte2  | Byte1 |
		| reserved | reserved | TpID  | TpID   | uinID  | uniID   | uniID  | uniID | */
		metadata := uint64(vs.CVlan)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		subflow1.SetWriteMetadata(metadata)

		/* TableMetaData 8 Byte(uint64) Voltha usage:  (Considering MSB bit as 63rd bit and LSB bit as 0th bit)
		|               Byte8                   | Byte7    | Byte6    |      Byte5       |  Byte4    | Byte3    | Byte2    | Byte1   |
		| 0000     |    00     |    0     |  0  | 00000000 | 00000000 |  0000   0000     |  00000000 | 00000000 | 00000000 | 00000000|
		| reserved | svlanTpID |  Buff us |  AT | schedID  | schedID  | onteth  vlanCtrl |  unitag   | unitag   | ctag     | ctag    |  */

		//TODO-COMM:
		/* TableMetaData 8 Byte(uint64) Community usage:  (Considering MSB bit as 63rd bit and LSB bit as 0th bit)
		|               Byte8                   | Byte7    | Byte6    |      Byte5       |  Byte4    | Byte3    | Byte2    | Byte1   |
		| 0000     |    00     |    0     |  0  | 00000000 | 00000000 |  0000   0000     |  00000000 | 00000000 | 00000000 | 00000000|
		| reserved | svlanTpID |  Buff us |  AT | schedID  | schedID  | onteth  vlanCtrl |   ctag    |  ctag    |  ctag    | ctag    |  */

		metadata = uint64(l2ProtoValue)<<58 | uint64(allowTransparent)<<56 | uint64(vs.SchedID)<<40 | uint64(vs.ONTEtherTypeClassification)<<36 | uint64(vs.VlanControl)<<32 | uint64(vs.CVlan)
		subflow1.SetTableMetadata(metadata)
		// TODO - We are using cookie as key and must come up with better cookie
		// allocation algorithm
		/**
		 * Cokies may clash when -
		 * on same uni-port we have two sub-service
		 * 1. U=10, C=100, S=310, p-bit=4 - VLAN_Control = OLT_CVLAN_OLT_SVLAN
		 * 2. U=10, C=10,  S=320, p-bit=4 - VLAN_control = ONU_CVLAN_ONU_SVLAN
		 * However, this p-bit re-use will not be allowed by sub-mgr.
		 */
		if vs.VlanControl == OLTCVlanOLTSVlan {
			/**
			 * The new cookie generation is only for OLT_CVLAN_OLT_SVLAN case (TEF residential case) within a UNI.
			 * After vgc upgrade, if we have to deactivate an already existing TEF residential service, then we have to
			 * use old cookie.
			 */
			subflow1.Cookie = generateDSCookie(vs.UniVlan, 0)
			if vgcRebooted {
				subflow1.OldCookie = generateDSCookie(vs.CVlan, 0)
			}
		} else {
			// In case of Olt_Svlan , CVLAN=UNIVLAN so cookie can be constructed with CVLAN as well
			subflow1.Cookie = generateDSCookie(vs.CVlan, 0)
		}

		flow.SubFlows[subflow1.Cookie] = subflow1
		logger.Infow(ctx, "Building downstream HSIA flow for T0", log.Fields{"cookie": subflow1.Cookie,
			"subflow": subflow1})
	}

	//Add Table-1 flow that deals with inner VLAN at the ONU
	{
		subflow2 := of.NewVoltSubFlow()
		subflow2.SetTableID(1)
		subflow2.SetInPort(inport)
		if NonZeroMacAddress(vs.MacAddr) {
			subflow2.SetMatchDstMac(vs.MacAddr)
		}

		if err := vs.setDSMatchActionVlanT1(subflow2); err != nil {
			return nil, err
		}
		if pbits != PbitMatchNone {
			subflow2.SetMatchPbit(pbits)
		}

		if remarkExists && (of.PbitType(remarkPbit) != pbits) {
			subflow2.SetPcp(of.PbitType(remarkPbit))
		}

		subflow2.SetOutPort(outport)
		subflow2.SetMeterID(vs.DsMeterID)

		// refer Table-0 flow generation for byte information
		metadata := uint64(vs.CVlan)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		subflow2.SetWriteMetadata(metadata)

		// Table-1 and inport is NNI: It is a DS flow for ONU, add uniport in metadata to make it unique
		if util.IsNniPort(inport) {
			metadata = uint64(outport)
		} else {
			// refer Table-0 flow generation for byte information
			metadata = uint64(l2ProtoValue)<<58 | uint64(allowTransparent)<<56 | uint64(vs.SchedID)<<40 | uint64(vs.ONTEtherTypeClassification)<<36 | uint64(vs.VlanControl)<<32 | uint64(vs.CVlan)
		}
		subflow2.SetTableMetadata(metadata)
		// Setting of Cookie - TODO - Improve the allocation algorithm
		if vs.VlanControl == OLTCVlanOLTSVlan {
			/**
			 * The new cookie generation is only for OLT_CVLAN_OLT_SVLAN case (TEF residential case) within a UNI.
			 * After vgc upgrade, if we have to deactivate an already existing TEF residential service, then we have to
			 * use old cookie.
			 */
			subflow2.Cookie = generateDSCookie(vs.UniVlan, 1)
			if vgcRebooted {
				subflow2.OldCookie = generateDSCookie(vs.CVlan, 1)
			}
		} else {
			// In case of Olt_Svlan , CVLAN=UNIVLAN so cookie can be constructed with CVLAN as well
			subflow2.Cookie = generateDSCookie(vs.CVlan, 1)
		}

		subflow2.Priority = of.HsiaFlowPriority
		flow.SubFlows[subflow2.Cookie] = subflow2
		logger.Infow(ctx, "Building downstream HSIA flow for T1", log.Fields{"cookie": subflow2.Cookie,
			"subflow": subflow2})
	}

	return flow, nil
}

// BuildUsHsiaFlows build the US HSIA flows
// Called for add/delete HSIA flows
func (vs *VoltService) BuildUsHsiaFlows(pbits of.PbitType) (*of.VoltFlow, error) {
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)

	// Get the out and in ports for the flows
	device, err := GetApplication().GetDeviceFromPort(vs.Port)
	if err != nil {
		return nil, errorCodes.ErrDeviceNotFound
	}
	outport, _ := GetApplication().GetPortID(device.NniPort)
	inport, _ := GetApplication().GetPortID(vs.Port)
	// PortName and PortID to be used for validation of port before flow pushing
	flow.PortID = inport
	flow.PortName = vs.Port
	allowTransparent := 0
	reqBwInfo := 0
	if vs.AllowTransparent {
		allowTransparent = 1
	}
	if vs.BwAvailInfo == "" {
		reqBwInfo = 1
	}

	// Add Table-0 flow that deals with the inner VLAN in ONU
	{
		subflow1 := of.NewVoltSubFlow()
		subflow1.SetTableID(0)
		subflow1.SetGoToTable(1)
		subflow1.SetInPort(inport)

		if pbits != PbitMatchNone {
			subflow1.SetMatchPbit(pbits)
		}
		if err := vs.setUSMatchActionVlanT0(subflow1); err != nil {
			return nil, err
		}
		subflow1.SetMeterID(vs.UsMeterID)

		/* WriteMetaData 8 Byte(uint64) usage:
		| Byte8    | Byte7    | Byte6 | Byte5  | Byte4  | Byte3   | Byte2  | Byte1 |
		| reserved | reserved | TpID  | TpID   | uinID  | uniID   | uniID  | uniID | */
		metadata := uint64(vs.CVlan)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		subflow1.SetWriteMetadata(metadata)

		/* TableMetaData 8 Byte(uint64) usage: (Considering MSB bit as 63rd bit and LSB bit as 0th bit)
		|                         Byte8                     |  Byte7    |  Byte6    |      Byte5       |  Byte4    | Byte3    | Byte2    | Byte1   |
		| 000      |    0      |    00     |    0     |  0  |  00000000 |  00000000 |  0000   0000     |  00000000 | 00000000 | 00000000 | 00000000|
		| reserved | reqBwInfo | svlanTpID |  Buff us |  AT |  schedID  |  schedID  | onteth  vlanCtrl |  unitag   | unitag   | ctag     | ctag    | */
		metadata = uint64(reqBwInfo)<<60 | uint64(allowTransparent)<<56 | uint64(vs.SchedID)<<40 | uint64(vs.ONTEtherTypeClassification)<<36 | uint64(vs.VlanControl)<<32 | uint64(vs.CVlan)

		// // In case of MAC Learning enabled voltha will buffer the US flow installation.
		// if NonZeroMacAddress(vs.MacAddr) {
		// 	subflow1.SetMatchSrcMac(vs.MacAddr)
		// } else if vs.MacLearning != MacLearning {
		// 	metadata |= 1 << 57
		// 	logger.Infow(ctx, "Buffer us flow at adapter", log.Fields{"metadata": metadata})
		// }
		subflow1.SetTableMetadata(metadata)
		if vs.VlanControl == OLTCVlanOLTSVlan {
			/**
			 * The new cookie generation is only for OLT_CVLAN_OLT_SVLAN case (TEF residential case) within a UNI.
			 * After vgc upgrade, if we have to deactivate an already existing TEF residential service, then we have to
			 * use old cookie.
			 */
			subflow1.Cookie = vs.generateUSCookie(vs.UniVlan, 0, inport, pbits)
			if vgcRebooted {
				subflow1.OldCookie = vs.generateUSCookie(vs.CVlan, 0, inport, pbits)
			}
		} else {
			// In case of Olt_Svlan , CVLAN=UNIVLAN so cookie can be constructed with CVLAN as well
			subflow1.Cookie = vs.generateUSCookie(vs.CVlan, 0, inport, pbits)
		}
		subflow1.Priority = of.HsiaFlowPriority
		flow.SubFlows[subflow1.Cookie] = subflow1
		logger.Infow(ctx, "Building upstream HSIA flow for T0", log.Fields{"cookie": subflow1.Cookie, "subflow": subflow1})
	}

	//Add Table-1 flow that deals with the outer vlan in pOLT
	{
		subflow2 := of.NewVoltSubFlow()
		subflow2.SetTableID(1)
		subflow2.SetInPort(inport)

		if pbits != PbitMatchNone {
			subflow2.SetMatchPbit(pbits)
		}

		if err := vs.setUSMatchActionVlanT1(subflow2); err != nil {
			return nil, err
		}
		subflow2.SetInPort(inport)
		subflow2.SetOutPort(outport)
		subflow2.SetMeterID(vs.UsMeterID)

		// refer Table-0 flow generation for byte information
		metadata := uint64(vs.CVlan)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		subflow2.SetWriteMetadata(metadata)

		// refer Table-0 flow generation for byte information
		metadata = uint64(reqBwInfo)<<60 | uint64(allowTransparent)<<56 | uint64(vs.SchedID)<<40 | uint64(vs.ONTEtherTypeClassification)<<36 | uint64(vs.VlanControl)<<32 | uint64(vs.CVlan)
		// // In case of MAC Learning enabled voltha will buffer the US flow installation.
		// if NonZeroMacAddress(vs.MacAddr) {
		// 	subflow2.SetMatchSrcMac(vs.MacAddr)
		// } else if vs.MacLearning != MacLearningNone {
		// 	metadata |= 1 << 57
		// 	logger.Infow(ctx, "Buffer us flow at adapter", log.Fields{"metadata": metadata})
		// }
		subflow2.SetTableMetadata(metadata)
		if vs.VlanControl == OLTCVlanOLTSVlan {
			/**
			 * The new cookie generation is only for OLT_CVLAN_OLT_SVLAN case (TEF residential case) within a UNI.
			 * After vgc upgrade, if we have to deactivate an already existing TEF residential service, then we have to
			 * use old cookie.
			 */
			subflow2.Cookie = vs.generateUSCookie(vs.UniVlan, 1, inport, pbits)
			if vgcRebooted {
				subflow2.OldCookie = vs.generateUSCookie(vs.CVlan, 1, inport, pbits)
			}
		} else {
			// In case of Olt_Svlan , CVLAN=UNIVLAN so cookie can be constructed with CVLAN as well
			subflow2.Cookie = vs.generateUSCookie(vs.CVlan, 1, inport, pbits)
		}
		subflow2.Priority = of.HsiaFlowPriority

		flow.SubFlows[subflow2.Cookie] = subflow2
		logger.Infow(ctx, "Building upstream HSIA flow for T1", log.Fields{"cookie": subflow2.Cookie, "subflow": subflow2})
	}

	return flow, nil
}

func (vs *VoltService) generateUSCookie(vlan of.VlanType, valToShift uint64, inport uint32, pbits of.PbitType) uint64 {
	//| 12-bit cvlan/UniVlan | 4 bits empty | <32-bits uniport>| 16-bits HSIA mask OR flow mask OR pbit |
	cookie := uint64(vlan)<<52 + uint64(inport)<<16 | of.HsiaFlowMask
	cookie = cookie | of.UsFlowMask
	cookie = cookie + (valToShift << 4) + uint64(pbits)
	return cookie
}

// setUSMatchActionVlanT1 - Sets the Match & Action w.r.t Vlans for US Table-1
// based on different Vlan Controls
func (vs *VoltService) setUSMatchActionVlanT1(flow *of.VoltSubFlow) error {
	switch vs.VlanControl {
	case None:
		flow.SetMatchVlan(vs.SVlan)
	case ONUCVlanOLTSVlan:
		flow.SetMatchVlan(vs.CVlan)
		flow.SetPushVlan(vs.SVlan, vs.SVlanTpid)
	case OLTCVlanOLTSVlan:
		flow.SetMatchVlan(vs.UniVlan)
		flow.SetSetVlan(vs.CVlan)
		flow.SetPushVlan(vs.SVlan, vs.SVlanTpid)
	case ONUCVlan:
		flow.SetMatchVlan(vs.SVlan)
	case OLTSVlan:
		if vs.UniVlan != of.VlanAny && vs.UniVlan != of.VlanNone {
			flow.SetMatchVlan(vs.UniVlan)
			flow.SetSetVlan(vs.SVlan)
		} else if vs.UniVlan != of.VlanNone {
			flow.SetMatchVlan(vs.UniVlan)
			flow.SetPushVlan(vs.SVlan, layers.EthernetTypeDot1Q)
		} else {
			flow.SetPushVlan(vs.SVlan, layers.EthernetTypeDot1Q)
		}
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vs.VlanControl})
		return errorCodes.ErrInvalidParamInRequest
	}
	return nil
}

// setDSMatchActionVlanT0 - Sets the Match & Action w.r.t Vlans for DS Table-0
// based on different Vlan Controls
func (vs *VoltService) setDSMatchActionVlanT0(flow *of.VoltSubFlow) error {
	switch vs.VlanControl {
	case None:
		flow.SetMatchVlan(vs.SVlan)
	case ONUCVlanOLTSVlan:
		flow.SetMatchVlan(vs.SVlan)
		flow.SetPopVlan()
	case OLTCVlanOLTSVlan:
		flow.SetMatchVlan(vs.SVlan)
		flow.SetPopVlan()
		flow.SetSetVlan(vs.UniVlan)
	case ONUCVlan:
		flow.SetMatchVlan(vs.SVlan)
	case OLTSVlan:
		flow.SetMatchVlan(vs.SVlan)
		if vs.UniVlan != of.VlanNone && vs.UniVlan != of.VlanAny {
			flow.SetSetVlan(vs.UniVlan)
		} else {
			flow.SetPopVlan()
		}
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vs.VlanControl})
		return errorCodes.ErrInvalidParamInRequest
	}
	return nil
}

// setUSMatchActionVlanT0 - Sets the Match & Action w.r.t Vlans for US Table-0
// based on different Vlan Controls
func (vs *VoltService) setUSMatchActionVlanT0(flow *of.VoltSubFlow) error {
	switch vs.VlanControl {
	case None:
		flow.SetMatchVlan(vs.SVlan)
	case ONUCVlanOLTSVlan:
		if vs.UniVlan != of.VlanNone {
			flow.SetMatchVlan(vs.UniVlan)
			flow.SetSetVlan(vs.CVlan)
		} else {
			flow.SetPushVlan(vs.CVlan, layers.EthernetTypeDot1Q)
		}
	case OLTCVlanOLTSVlan:
		flow.SetMatchVlan(vs.UniVlan)
	case ONUCVlan:
		if vs.UniVlan != of.VlanNone {
			flow.SetMatchVlan(vs.UniVlan)
			flow.SetSetVlan(vs.SVlan)
		} else {
			flow.SetPushVlan(vs.SVlan, layers.EthernetTypeDot1Q)
		}
	case OLTSVlan:
		flow.SetMatchVlan(vs.UniVlan)
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vs.VlanControl})
		return errorCodes.ErrInvalidParamInRequest
	}
	return nil
}

// setDSMatchActionVlanT1 - Sets the Match & Action w.r.t Vlans for DS Table-1
// based on different Vlan Controls
func (vs *VoltService) setDSMatchActionVlanT1(flow *of.VoltSubFlow) error {
	switch vs.VlanControl {
	case None:
		flow.SetMatchVlan(vs.SVlan)
	case ONUCVlanOLTSVlan:
		flow.SetMatchVlan(vs.CVlan)
		if vs.UniVlan != of.VlanNone {
			flow.SetSetVlan(vs.UniVlan)
		} else {
			flow.SetPopVlan()
		}
	case OLTCVlanOLTSVlan:
		flow.SetMatchVlan(vs.UniVlan)
	case ONUCVlan:
		flow.SetMatchVlan(vs.SVlan)
		if vs.UniVlan != of.VlanNone {
			flow.SetSetVlan(vs.UniVlan)
		} else {
			flow.SetPopVlan()
		}
	case OLTSVlan:
		flow.SetMatchVlan(vs.UniVlan)
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vs.VlanControl})
		return errorCodes.ErrInvalidParamInRequest
	}
	return nil
}

// SvcUpInd for service up indication
func (vs *VoltService) SvcUpInd() {
	vs.AddHsiaFlows()
}

// SvcDownInd for service down indication
func (vs *VoltService) SvcDownInd() {
	vs.DelHsiaFlows()
}

// SetIpv4Addr to set ipv4 address
func (vs *VoltService) SetIpv4Addr(addr net.IP) {
	vs.Ipv4Addr = addr
}

// SetIpv6Addr to set ipv6 address
func (vs *VoltService) SetIpv6Addr(addr net.IP) {
	vs.Ipv6Addr = addr
}

// SetMacAddr to set mac address
func (vs *VoltService) SetMacAddr(addr net.HardwareAddr) {
	vs.MacAddr = addr
}

// ----------------------------------------------
// VOLT Application - Related to services
// ---------------------------------------------
// ---------------------------------------------------------------
// Service CRUD functions. These are exposed to the overall binary
// to be invoked from the point where the CRUD operations are received
// from the external entities

// AddService :  A service in the context of VOLT is a subscriber or service of a
// subscriber which is uniquely identified by a combination of MAC
// address, VLAN tags, 802.1p bits. However, in the context of the
// current implementation, a service is an entity that is identified by a
// unique L2 (MAC address + VLANs) or unique L3 (VLANs + IP address)
// FUNC: Add Service
func (va *VoltApplication) AddService(cfg VoltServiceCfg, oper *VoltServiceOper) error {
	var mmUs, mmDs *VoltMeter
	var err error

	//Take the  Device lock only in case of NB add request.
	// Allow internal adds since internal add happen only under
	// 1. Restore Service from DB
	// 2. Service Migration
	if oper == nil {
		if svc := va.GetService(cfg.Name); svc != nil {
			logger.Warnw(ctx, "Service Already Exists. Ignoring Add Service Request", log.Fields{"Name": cfg.Name})
			return errors.New("Service Already Exists")
		}
	}

	logger.Infow(ctx, "Service to be configured", log.Fields{"Cfg": cfg})
	// Service doesn't exist. So create it and add to the port
	vs := NewVoltService(&cfg)
	if oper != nil {
		vs.UsHSIAFlowsApplied = oper.UsHSIAFlowsApplied
		vs.DsHSIAFlowsApplied = oper.DsHSIAFlowsApplied
		vs.Ipv4Addr = oper.Ipv4Addr
		vs.Ipv6Addr = oper.Ipv6Addr
		vs.MacLearning = cfg.MacLearning
		vs.PendingFlows = oper.PendingFlows
		vs.AssociatedFlows = oper.AssociatedFlows
		vs.DeleteInProgress = oper.DeleteInProgress
		vs.BwAvailInfo = oper.BwAvailInfo
		vs.Device = oper.Device
	} else {

		//Sorting Pbit from highest
		sort.Slice(vs.Pbits, func(i, j int) bool {
			return vs.Pbits[i] > vs.Pbits[j]
		})
		logger.Infow(ctx, "Sorted Pbits", log.Fields{"Pbits": vs.Pbits})
	}
	logger.Infow(ctx, "VolthService...", log.Fields{"vs": vs.Name})

	// The bandwidth and shaper profile combined into meter
	if mmDs, err = va.GetMeter(cfg.DsMeterProfile); err == nil {
		vs.DsMeterID = mmDs.ID
	} else {
		return errors.New("DownStream meter profile not found")
	}

	// The aggregated downstream meter profile
	// if mmAg, err = va.GetMeter(cfg.AggDsMeterProfile); err == nil {
	// 	vs.AggDsMeterID = mmAg.ID
	// } else {
	// 	return errors.New("Aggregated meter profile not found")
	// }

	// if cfg.AggDsMeterProfile == cfg.UsMeterProfile {
	// 	vs.UsMeterID = mmAg.ID
	// } else {
	// The bandwidth and shaper profile combined into meter
	if mmUs, err = va.GetMeter(cfg.UsMeterProfile); err == nil {
		vs.UsMeterID = mmUs.ID
	} else {
		return errors.New("Upstream meter profile not found")
	}
	//}

	AppMutex.ServiceDataMutex.Lock()
	defer AppMutex.ServiceDataMutex.Unlock()

	// Add the service to the VNET
	vnet := va.GetVnet(cfg.SVlan, cfg.CVlan, cfg.UniVlan)
	if vnet != nil {
		if vpv := va.GetVnetByPort(vs.Port, cfg.SVlan, cfg.CVlan, cfg.UniVlan); vpv != nil {
			vpv.VpvLock.Lock()
			vpv.AddSvc(vs)
			vpv.VpvLock.Unlock()
		} else {
			va.AddVnetToPort(vs.Port, vnet, vs)
		}
	} else {
		logger.Error(ctx, "VNET-does-not-exist-for-service", log.Fields{"ServiceName": cfg.Name})
		return errors.New("VNET doesn't exist")
	}

	vs.Version = database.PresentVersionMap[database.ServicePath]
	// Add the service to the volt application
	va.ServiceByName.Store(vs.Name, vs)
	vs.WriteToDb()

	if nil == oper {

		if !vs.UsHSIAFlowsApplied {
			vs.triggerServiceInProgressInd()
		}

		//Update meter profiles service count if service is being added from northbound
		mmDs.AssociatedServices++
		va.UpdateMeterProf(*mmDs)
		if mmUs != nil {
			mmUs.AssociatedServices++
			va.UpdateMeterProf(*mmUs)
		}
		//mmAg.AssociatedServices++
		//va.UpdateMeterProf(*mmAg)
		logger.Debug(ctx, "northbound-service-add-sucessful", log.Fields{"ServiceName": vs.Name})
	}

	logger.Warnw(ctx, "Added Service to DB", log.Fields{"Name": vs.Name, "Port": (vs.Port), "ML": vs.MacLearning})
	return nil
}

//DelServiceWithPrefix - Deletes service with the provided prefix.
// Added for DT/TT usecase with sadis replica interface
func (va *VoltApplication) DelServiceWithPrefix(prefix string) {
	va.ServiceByName.Range(func(key, value interface{}) bool {
		srvName := key.(string)
		vs := value.(*VoltService)
		if strings.Contains(srvName, prefix) {
			va.DelService(srvName, true, nil, false)

			vnetName := strconv.FormatUint(uint64(vs.SVlan), 10) + "-"
			vnetName = vnetName + strconv.FormatUint(uint64(vs.CVlan), 10) + "-"
			vnetName = vnetName + strconv.FormatUint(uint64(vs.UniVlan), 10)

			if err := va.DelVnet(vnetName, ""); err != nil {
				logger.Warnw(ctx, "Delete Vnet Failed", log.Fields{"Name": vnetName, "Error": err})
			}
		}
		return true
	})
}

// DelService delete a service form the application
func (va *VoltApplication) DelService(name string, forceDelete bool, newSvc *VoltServiceCfg, serviceMigration bool) {

	AppMutex.ServiceDataMutex.Lock()
	defer AppMutex.ServiceDataMutex.Unlock()

	logger.Warnw(ctx, "Delete Service Request", log.Fields{"Service": name, "ForceDelete": forceDelete, "serviceMigration": serviceMigration})
	var noFlowsPresent bool

	vsIntf, ok := va.ServiceByName.Load(name)
	if !ok {
		logger.Warnw(ctx, "Service doesn't exist", log.Fields{"ServiceName": name})
		return
	}
	vs := vsIntf.(*VoltService)
	vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan)
	if vpv == nil {
		logger.Errorw(ctx, "Vpv Not found for Service", log.Fields{"vs": vs.Name})
		return
	}

	//Set this to avoid race-condition during flow result processing
	vs.DeleteInProgress = true
	vs.ForceDelete = forceDelete
	vs.ForceWriteToDb()

	if len(vs.AssociatedFlows) == 0 {
		noFlowsPresent = true
	}
	vpv.VpvLock.Lock()
	defer vpv.VpvLock.Unlock()

	vs.DelHsiaFlows()

	if vpv.IgmpEnabled {
		va.ReceiverDownInd(vpv.Device, vpv.Port)
	}
	logger.Infow(ctx, "Delete Service from VPV", log.Fields{"VPV_Port": vpv.Port, "VPV_SVlan": vpv.SVlan, "VPV_CVlan": vpv.CVlan, "VPV_UniVlan": vpv.UniVlan, "ServiceName": name})
	vpv.DelService(vs)
	if vpv.servicesCount.Load() == 0 {
		va.DelVnetFromPort(vs.Port, vpv)
	}

	// Delete the service immediately in case of Force Delete
	// This will be enabled when profile reconciliation happens after restore
	// of backedup data
	if vs.ForceDelete {
		vs.DelFromDb()
		GetApplication().ServiceByName.Delete(vs.Name)
		logger.Warnw(ctx, "Deleted service from DB/Cache successfully", log.Fields{"serviceName": vs.Name})
	}

	meterProfiles := make(map[*VoltMeter]bool)

	if nil != newSvc {
		logger.Infow(ctx, "Old Service meter profiles", log.Fields{"AGG": vs.AggDsMeterProfile, "DS": vs.DsMeterProfile, "US": vs.UsMeterProfile})
		logger.Infow(ctx, "New Service meter profiles", log.Fields{"AGG": newSvc.AggDsMeterProfile, "DS": newSvc.DsMeterProfile, "US": newSvc.UsMeterProfile})
	}
	skipMeterDeletion := false
	if aggMeter, ok := va.MeterMgr.GetMeterByID(vs.AggDsMeterID); ok {
		if nil != newSvc && aggMeter.Name == newSvc.AggDsMeterProfile {
			skipMeterDeletion = true
		}

		meterProfiles[aggMeter] = skipMeterDeletion
		skipMeterDeletion = false
	}
	if dsMeter, ok := va.MeterMgr.GetMeterByID(vs.DsMeterID); ok {
		if nil != newSvc && dsMeter.Name == newSvc.DsMeterProfile {
			skipMeterDeletion = true
		}
		meterProfiles[dsMeter] = skipMeterDeletion
		skipMeterDeletion = false
	}
	if vs.AggDsMeterID != vs.UsMeterID {
		if usMeter, ok := va.MeterMgr.GetMeterByID(vs.UsMeterID); ok {
			if nil != newSvc && usMeter.Name == newSvc.UsMeterProfile {
				skipMeterDeletion = true
			}
			meterProfiles[usMeter] = skipMeterDeletion
		}
	}

	for meter, skipMeterDeletion := range meterProfiles {
		if nil == meter {
			logger.Debug(ctx, "Null meter found, continuing")
			continue
		}
		if meter.AssociatedServices > 0 {
			meter.AssociatedServices--
			if meter.AssociatedServices == 0 && !skipMeterDeletion {
				logger.Info(ctx, "Meter should be deleted now\n", log.Fields{"MeterID": meter})
				va.UpdateMeterProf(*meter)
			}
		}
	}

	if noFlowsPresent || vs.ForceDelete {
		vs.CheckAndDeleteService()
	}

	//Delete the per service counter too
	va.ServiceCounters.Delete(name)
	if vs.IgmpEnabled && vs.EnableMulticastKPI {
		_ = db.DelAllServiceChannelCounter(name)
	}
}

//AddFlows - Adds the flow to the service
// Triggers flow addition after registering for flow indication event
func (vs *VoltService) AddFlows(device *VoltDevice, flow *of.VoltFlow) error {

	// Using locks instead of concurrent map for PendingFlows to avoid
	// race condition during flow response indication processing
	vs.ServiceLock.Lock()
	defer vs.ServiceLock.Unlock()

	for cookie := range flow.SubFlows {
		cookie := strconv.FormatUint(cookie, 10)
		fe := &FlowEvent{
			eType:     EventTypeServiceFlowAdded,
			device:    device.Name,
			cookie:    cookie,
			eventData: vs,
		}
		device.RegisterFlowAddEvent(cookie, fe)
		vs.PendingFlows[cookie] = true
	}
	return cntlr.GetController().AddFlows(vs.Port, device.Name, flow)
}

//FlowInstallSuccess - Called when corresponding service flow installation is success
// If no more pending flows, HSIA indication wil be triggered
func (vs *VoltService) FlowInstallSuccess(cookie string, bwAvailInfo of.BwAvailDetails) {
	if vs.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Flow Add Success Notification. Service deletion in-progress", log.Fields{"Cookie": cookie, "Service": vs.Name})
		return
	}
	vs.ServiceLock.Lock()

	if _, ok := vs.PendingFlows[cookie]; !ok {
		logger.Errorw(ctx, "Flow Add Success for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie})
		vs.ServiceLock.Unlock()
		return
	}

	delete(vs.PendingFlows, cookie)
	vs.AssociatedFlows[cookie] = true
	vs.ServiceLock.Unlock()
	var prevBwAvail, presentBwAvail string
	if bwAvailInfo.PrevBw != "" && bwAvailInfo.PresentBw != "" {
		prevBwAvail = bwAvailInfo.PrevBw
		presentBwAvail = bwAvailInfo.PresentBw
		vs.BwAvailInfo = prevBwAvail + "," + presentBwAvail
		logger.Debug(ctx, "Bandwidth-value-formed", log.Fields{"BwAvailInfo": vs.BwAvailInfo})
	}
	vs.WriteToDb()

	if len(vs.PendingFlows) == 0 && vs.DsHSIAFlowsApplied {

		device, err := GetApplication().GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device. Dropping HSIA Success indication to NB", log.Fields{"Reason": err.Error(), "Service": vs.Name, "Port": vs.Port})
			return
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Dropping HSIA Success indication to NB", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return
		}

		if vs.Trigger == ServiceVlanUpdate {
			vs.Trigger = NBActivate
			defer vs.WriteToDb()
		}
		logger.Infow(ctx, "All Flows installed for Service", log.Fields{"Service": vs.Name})
		return
	}
	logger.Infow(ctx, "Processed Service Flow Add Success Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "DsFlowsApplied": vs.DsHSIAFlowsApplied})
}

//FlowInstallFailure - Called when corresponding service flow installation is failed
// Trigger service failure indication to NB
func (vs *VoltService) FlowInstallFailure(cookie string, errorCode uint32, errReason string) {
	vs.ServiceLock.RLock()

	if _, ok := vs.PendingFlows[cookie]; !ok {
		logger.Errorw(ctx, "Flow Add Failure for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie})
		vs.ServiceLock.RUnlock()
		return
	}
	vs.ServiceLock.RUnlock()
	logger.Errorw(ctx, "HSIA Flow Add Failure Notification", log.Fields{"uniPort": vs.Port, "Cookie": cookie, "Service": vs.Name, "ErrorCode": errorCode, "ErrorReason": errReason})
	vs.triggerServiceFailureInd(errorCode, errReason)
}

//DelFlows - Deletes the flow from the service
// Triggers flow deletion after registering for flow indication event
func (vs *VoltService) DelFlows(device *VoltDevice, flow *of.VoltFlow) error {

	if !vs.ForceDelete {
		// Using locks instead of concurrent map for AssociatedFlows to avoid
		// race condition during flow response indication processing
		vs.ServiceLock.Lock()
		defer vs.ServiceLock.Unlock()

		for cookie := range flow.SubFlows {
			cookie := strconv.FormatUint(cookie, 10)
			fe := &FlowEvent{
				eType:     EventTypeServiceFlowRemoved,
				cookie:    cookie,
				eventData: vs,
			}
			device.RegisterFlowDelEvent(cookie, fe)
		}
	}
	return cntlr.GetController().DelFlows(vs.Port, device.Name, flow)
}

//CheckAndDeleteService - remove service from DB is there are no pending flows to be removed
func (vs *VoltService) CheckAndDeleteService() {
	if vs.DeleteInProgress && len(vs.AssociatedFlows) == 0 && !vs.DsHSIAFlowsApplied {
		vs.DelFromDb()
		GetApplication().ServiceByName.Delete(vs.Name)
		logger.Warnw(ctx, "Deleted service from DB/Cache successfully", log.Fields{"serviceName": vs.Name})
	}
}

//FlowRemoveSuccess - Called when corresponding service flow removal is success
// If no more associated flows, DelHSIA indication wil be triggered
func (vs *VoltService) FlowRemoveSuccess(cookie string) {

	// if vs.DeleteInProgress {
	// 	logger.Warnw(ctx, "Skipping Flow Remove Success Notification. Service deletion in-progress", log.Fields{"Cookie": cookie, "Service": vs.Name})
	// 	return
	// }
	vs.ServiceLock.Lock()
	logger.Infow(ctx, "Processing Service Flow Remove Success Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "Associated Flows": vs.AssociatedFlows, "DsFlowsApplied": vs.DsHSIAFlowsApplied})

	if _, ok := vs.AssociatedFlows[cookie]; ok {
		delete(vs.AssociatedFlows, cookie)
	} else if _, ok := vs.PendingFlows[cookie]; ok {
		logger.Errorw(ctx, "Service Flow Remove: Cookie Present in Pending Flow list. No Action", log.Fields{"Service": vs.Name, "Cookie": cookie, "AssociatedFlows": vs.AssociatedFlows, "PendingFlows": vs.PendingFlows})
	} else {
		logger.Errorw(ctx, "Service Flow Remove Success for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie, "AssociatedFlows": vs.AssociatedFlows, "PendingFlows": vs.PendingFlows})
	}

	vs.ServiceLock.Unlock()

	vs.WriteToDb()

	if len(vs.AssociatedFlows) == 0 && !vs.DsHSIAFlowsApplied {

		device := GetApplication().GetDevice(vs.Device)
		if device == nil {
			logger.Errorw(ctx, "Error Getting Device. Dropping DEL_HSIA Success indication to NB", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Dropping DEL_HSIA Success indication to NB", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return
		}

		if vs.UpdateInProgress {
			vs.updateVnetProfile(vs.Device)
			//Not sending DEL_HSIA Indication since it wil be generated internally by SubMgr
			return
		}
		logger.Infow(ctx, "All Flows removed for Service. Triggering Service De-activation Success indication to NB", log.Fields{"Service": vs.Name, "DeleteFlag": vs.DeleteInProgress})
		vs.CheckAndDeleteService()

		return
	}
	logger.Infow(ctx, "Processed Service Flow Remove Success Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "Associated Flows": vs.AssociatedFlows, "DsFlowsApplied": vs.DsHSIAFlowsApplied})
}

//FlowRemoveFailure - Called when corresponding service flow installation is failed
// Trigger service failure indication to NB
func (vs *VoltService) FlowRemoveFailure(cookie string, errorCode uint32, errReason string) {
	vs.ServiceLock.RLock()

	if _, ok := vs.AssociatedFlows[cookie]; !ok {
		logger.Errorw(ctx, "Flow Failure for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie})
		vs.ServiceLock.RUnlock()
		return
	}
	if vs.DeleteInProgress {
		delete(vs.AssociatedFlows, cookie)
	}
	vs.ServiceLock.RUnlock()
	logger.Errorw(ctx, "Service Flow Remove Failure Notification", log.Fields{"uniPort": vs.Port, "Cookie": cookie, "Service": vs.Name, "ErrorCode": errorCode, "ErrorReason": errReason})

	vs.triggerServiceFailureInd(errorCode, errReason)
	vs.CheckAndDeleteService()
}

func (vs *VoltService) triggerServiceFailureInd(errorCode uint32, errReason string) {
	device, err := GetApplication().GetDeviceFromPort(vs.Port)
	if err != nil {
		logger.Errorw(ctx, "Error Getting Device. Dropping DEL_HSIA Failure indication to NB", log.Fields{"Reason": err.Error(), "Service": vs.Name, "Port": vs.Port})
		return
	} else if device.State != controller.DeviceStateUP {
		logger.Warnw(ctx, "Device state Down. Dropping DEL_HSIA Failure indication to NB", log.Fields{"Service": vs.Name, "Port": vs.Port})
		return
	}
}

// RestoreSvcsFromDb read from the DB and restore all the services
func (va *VoltApplication) RestoreSvcsFromDb() {
	// VNETS must be learnt first
	vss, _ := db.GetServices()
	for _, vs := range vss {
		b, ok := vs.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		var vvs VoltService
		err := json.Unmarshal(b, &vvs)
		if err != nil {
			logger.Warn(ctx, "Unmarshal of VNET failed")
			continue
		}
		logger.Debugw(ctx, "Retrieved Service", log.Fields{"Service": vvs.VoltServiceCfg})
		if err := va.AddService(vvs.VoltServiceCfg, &vvs.VoltServiceOper); err != nil {
			logger.Warnw(ctx, "Add New Service Failed", log.Fields{"Service": vvs.Name, "Error": err})
		}

		if vvs.VoltServiceOper.DeleteInProgress {
			va.ServicesToDelete[vvs.VoltServiceCfg.Name] = true
			logger.Warnw(ctx, "Service (restored) to be deleted", log.Fields{"Service": vvs.Name})
		}
	}
}

// GetService to get service
func (va *VoltApplication) GetService(name string) *VoltService {
	if vs, ok := va.ServiceByName.Load(name); ok {
		return vs.(*VoltService)
	}
	return nil
}

// GetCircuitID to get circuit id
func (vs *VoltService) GetCircuitID() []byte {
	return []byte(vs.CircuitID)
}

// GetRemoteID to get remote id
func (vs *VoltService) GetRemoteID() []byte {
	return []byte(vs.RemoteID)
}

// IPAssigned to check if ip is assigned
func (vs *VoltService) IPAssigned() bool {
	if vs.Ipv4Addr != nil && !vs.Ipv4Addr.Equal(net.ParseIP("0.0.0.0")) {
		return true
	} else if vs.Ipv6Addr != nil && !vs.Ipv6Addr.Equal(net.ParseIP("0:0:0:0:0:0:0:0")) {
		return true
	}
	return false
}

// GetServiceNameFromCookie to get service name from cookie
func (va *VoltApplication) GetServiceNameFromCookie(cookie uint64, portName string, pbit uint8, device string, tableMetadata uint64) *VoltService {

	var vlan uint64
	vlanControl := (tableMetadata >> 32) & 0xF

	if vlanControl == uint64(OLTCVlanOLTSVlan) {
		// Fetching UniVlan for vlanControl OLTCVLANOLTSVLAN
		vlan = (tableMetadata >> 16) & 0xFFFF
	} else {
		//Fetching CVlan for other vlanControl
		vlan = cookie >> 52
	}
	logger.Infow(ctx, "Configured Params", log.Fields{"VlanControl": vlanControl, "vlan": vlan})
	var vlans []of.VlanType
	vlans = append(vlans, of.VlanType(vlan))
	service := GetApplication().GetServiceFromCvlan(device, portName, vlans, uint8(pbit))
	if nil != service {
		logger.Info(ctx, "Service Found for", log.Fields{"serviceName": service.Name, "portName": portName, "ctag": vlan})
	} else {
		logger.Errorw(ctx, "No Service for", log.Fields{"portName": portName, "ctag": vlan, "Pbit": pbit, "device": device, "VlanControl": vlanControl})
	}
	return service
}

//MigrateServicesReqStatus - update vnet request status
type MigrateServicesReqStatus string

const (
	//MigrateSrvsReqInit constant
	MigrateSrvsReqInit MigrateServicesReqStatus = "Init"
	//MigrateSrvsReqDeactTriggered constant
	MigrateSrvsReqDeactTriggered MigrateServicesReqStatus = "Profiles Deactivated"
	//MigrateSrvsReqCompleted constant
	MigrateSrvsReqCompleted MigrateServicesReqStatus = "Update Complete"
)

//MigrateServicesRequest - update vnet request params
type MigrateServicesRequest struct {
	ID                  string
	OldVnetID           string
	NewVnetID           string
	ServicesList        map[string]bool
	DeviceID            string
	Status              MigrateServicesReqStatus
	MigrateServicesLock sync.RWMutex
}

func newMigrateServicesRequest(id string, oldVnetID string, newVnetID string, serviceMap map[string]bool, deviceID string) *MigrateServicesRequest {

	var msr MigrateServicesRequest
	msr.OldVnetID = oldVnetID
	msr.NewVnetID = newVnetID
	msr.ID = id
	msr.ServicesList = serviceMap
	msr.DeviceID = deviceID
	msr.Status = MigrateSrvsReqInit
	return &msr
}

//GetMsrKey - generates migrate service request key
func (msr *MigrateServicesRequest) GetMsrKey() string {
	return msr.OldVnetID + "-" + msr.ID
}

// //isRequestComplete - return if all request has been processed and completed
// // RequestProcessed indicates that all the profile de-activation has been triggered
// // And the associated profiles indicates the profiles awaiting results
// func (msr *MigrateServicesRequest) isRequestComplete() bool {
// 	//return edr.RequestProcessed && (len(edr.AssociatedProfiles) == 0)
// 	return (len(edr.AssociatedProfiles) == 0)
// }

//WriteToDB - writes the udpate vnet request details ot DB
func (msr *MigrateServicesRequest) WriteToDB() {
	logger.Debugw(ctx, "Adding Migrate Service Request to DB", log.Fields{"OldVnet": msr.OldVnetID, "NewVnet": msr.NewVnetID, "Device": msr.DeviceID, "RequestID": msr.ID, "ServiceCount": len(msr.ServicesList)})
	if b, err := json.Marshal(msr); err == nil {
		if err = db.PutMigrateServicesReq(msr.DeviceID, msr.GetMsrKey(), string(b)); err != nil {
			logger.Warnw(ctx, "PutMigrateServicesReq Failed", log.Fields{"OldVnet": msr.OldVnetID, "NewVnet": msr.NewVnetID,
									"Device": msr.DeviceID, "Error": err})
		}
	}
}

//MigrateServices - updated vnet profile for services
func (va *VoltApplication) MigrateServices(serialNum string, reqID string, oldVnetID, newVnetID string, serviceList []string) error {

	logger.Warnw(ctx, "Migrate Serviec Request Received", log.Fields{"SerialNum": serialNum, "RequestID": reqID, "OldVnet": oldVnetID, "NewVnet": newVnetID, "ServiceList": serviceList})
	if _, ok := va.VnetsByName.Load(oldVnetID); !ok {
		return errors.New("Old Vnet Id not found")
	}
	if _, ok := va.VnetsByName.Load(newVnetID); !ok {
		return errors.New("New Vnet Id not found")
	}

	d := va.GetDeviceBySerialNo(serialNum)
	if d == nil {
		logger.Errorw(ctx, "Error Getting Device", log.Fields{"SerialNum": serialNum})
		return errorCodes.ErrDeviceNotFound
	}

	serviceMap := make(map[string]bool)

	for _, service := range serviceList {
		serviceMap[service] = false
	}
	msr := newMigrateServicesRequest(reqID, oldVnetID, newVnetID, serviceMap, d.Name)
	msr.WriteToDB()

	d.AddMigratingServices(msr)
	go msr.ProcessMigrateServicesProfRequest()
	return nil
}

//ProcessMigrateServicesProfRequest - collects all associated profiles
func (msr *MigrateServicesRequest) ProcessMigrateServicesProfRequest() {
	va := GetApplication()
	for srv, processed := range msr.ServicesList {

		//Indicates new service is already created and only deletion of old one is pending
		if processed {
			va.DelService(srv, true, nil, true)
			msr.serviceMigrated(srv)
			continue
		}

		logger.Infow(ctx, "Migrate Service Triggering", log.Fields{"Service": srv})
		if vsIntf, ok := va.ServiceByName.Load(srv); ok {
			vs := vsIntf.(*VoltService)
			vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan)
			if vpv == nil {
				logger.Errorw(ctx, "Vpv Not found for Service", log.Fields{"vs": vs.Name, "port": vs.Port, "Vnet": vs.VnetID})
				continue
			}
			logger.Infow(ctx, "Migrating Service", log.Fields{"Service": vs.Name, "UsFlowApplied": vs.UsHSIAFlowsApplied})
			vpv.Blocked = true

			// setDeactTrigger := func(key, value interface{}) bool {
			// 	vs := value.(*VoltService)
			vs.ServiceLock.Lock()
			vs.UpdateInProgress = true
			metadata := &MigrateServiceMetadata{
				NewVnetID: msr.NewVnetID,
				RequestID: msr.ID,
			}
			vs.Metadata = metadata
			vs.ServiceLock.Unlock()

			//vpv flows will be removed when last service is removed from it and
			// new vpv flows will be installed when new service is added
			if vs.UsHSIAFlowsApplied {
				vpv.DelTrapFlows()
				vs.DelHsiaFlows()
				logger.Info(ctx, "Remove Service Flows Triggered", log.Fields{"Service": srv, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied})
			} else {
				vs.updateVnetProfile(msr.DeviceID)
			}
		} else {
			logger.Warnw(ctx, "Migrate Service Failed: Service Not Found", log.Fields{"Service": srv, "Vnet": msr.OldVnetID})
		}
	}
}

//AddMigratingServices - store msr info to device obj
func (d *VoltDevice) AddMigratingServices(msr *MigrateServicesRequest) {

	var msrMap *util.ConcurrentMap
	if msrMapIntf, ok := d.MigratingServices.Get(msr.OldVnetID); !ok {
		msrMap = util.NewConcurrentMap()
	} else {
		msrMap = msrMapIntf.(*util.ConcurrentMap)
	}

	msrMap.Set(msr.ID, msr)
	logger.Infow(ctx, "1: MsrListLen", log.Fields{"Len": msrMap.Length(), "Vnet": msr.OldVnetID})

	d.MigratingServices.Set(msr.OldVnetID, msrMap)
	logger.Infow(ctx, "1: DeviceMsr", log.Fields{"Device": d.Name, "Vnet": msr.OldVnetID, "Len": d.MigratingServices.Length()})

}

//getMigrateServicesRequest - fetches msr info from device
func (va *VoltApplication) getMigrateServicesRequest(deviceID string, oldVnetID string, requestID string) *MigrateServicesRequest {
	if vd := va.GetDevice(deviceID); vd != nil {
		logger.Infow(ctx, "2: DeviceMsr", log.Fields{"Device": deviceID, "Vnet": oldVnetID, "Len": vd.MigratingServices.Length()})
		if msrListIntf, ok := vd.MigratingServices.Get(oldVnetID); ok {
			msrList := msrListIntf.(*util.ConcurrentMap)
			logger.Infow(ctx, "2: MsrListLen", log.Fields{"Len": msrList.Length(), "Vnet": oldVnetID})
			if msrObj, ok := msrList.Get(requestID); ok {
				return msrObj.(*MigrateServicesRequest)
			}

		}
	}
	logger.Errorw(ctx, "Device Not Found", log.Fields{"Device": deviceID})
	return nil
}

//updateMigrateServicesRequest - Updates the device with updated msr
func (va *VoltApplication) updateMigrateServicesRequest(deviceID string, oldVnetID string, requestID string, msr *MigrateServicesRequest) {
	if vd := va.GetDevice(deviceID); vd != nil {
		if msrList, ok := vd.MigratingServices.Get(oldVnetID); ok {
			if _, ok := msrList.(*util.ConcurrentMap).Get(requestID); ok {
				msrList.(*util.ConcurrentMap).Set(requestID, msr)
			}
		}
	}
}

//updateVnetProfile - Called on flow process completion
// Removes old service and creates new VPV & service with udpated vnet profile
func (vs *VoltService) updateVnetProfile(deviceID string) {

	logger.Info(ctx, "Update Vnet Profile Triggering", log.Fields{"Service": vs.Name, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied})

	nvs := VoltService{}
	nvs.VoltServiceCfg = vs.VoltServiceCfg
	nvs.Device = vs.Device
	nvs.Ipv4Addr = vs.Ipv4Addr
	nvs.Ipv6Addr = vs.Ipv6Addr
	nvs.UsMeterID = vs.UsMeterID
	nvs.DsMeterID = vs.DsMeterID
	nvs.AggDsMeterID = vs.AggDsMeterID
	nvs.UsHSIAFlowsApplied = vs.UsHSIAFlowsApplied
	nvs.DsHSIAFlowsApplied = vs.DsHSIAFlowsApplied
	nvs.UsDhcpFlowsApplied = vs.UsDhcpFlowsApplied
	nvs.DsDhcpFlowsApplied = vs.DsDhcpFlowsApplied
	nvs.IgmpFlowsApplied = vs.IgmpFlowsApplied
	nvs.Icmpv6FlowsApplied = vs.Icmpv6FlowsApplied
	nvs.PendingFlows = vs.PendingFlows
	nvs.AssociatedFlows = vs.AssociatedFlows
	nvs.DeleteInProgress = vs.DeleteInProgress
	nvs.ForceDelete = vs.ForceDelete
	nvs.BwAvailInfo = vs.BwAvailInfo
	nvs.UpdateInProgress = vs.UpdateInProgress

	if nvs.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Service Migration. Service Delete in Progress", log.Fields{"Device": deviceID, "Service": vs.Name, "Vnet": vs.VnetID})
		return
	}

	metadata := vs.Metadata.(*MigrateServiceMetadata)
	oldVnetID := vs.VnetID
	nvs.VnetID = metadata.NewVnetID
	id := metadata.RequestID
	oldSrvName := vs.Name

	if metadata == nil || metadata.NewVnetID == "" {
		logger.Errorw(ctx, "Migrate Service Metadata not found. Dropping vnet profile update request", log.Fields{"Service": vs.Name, "Vnet": vs.VnetID})
		return
	}

	//First add the new service and then only delete the old service
	// Since if post del service in case of pod crash or reboot, the service data will be lost
	va := GetApplication()
	msr := va.getMigrateServicesRequest(deviceID, oldVnetID, id)
	vnets := strings.Split(metadata.NewVnetID, "-")
	svlan, _ := strconv.Atoi(vnets[0])
	nvs.SVlan = of.VlanType(svlan)
	nvs.UpdateInProgress = false
	nvs.Metadata = nil
	nvs.Trigger = ServiceVlanUpdate

	svcName := vs.Port + "-" + strconv.FormatUint(uint64(nvs.SVlan), 10) + "-"
	svcName = svcName + strconv.FormatUint(uint64(vs.CVlan), 10) + "-"
	nvs.Name = svcName + strconv.FormatUint(uint64(vs.TechProfileID), 10)

	//TODO:Nav Pass a copy, not the pointer
	logger.Infow(ctx, "Add New Service Triggering", log.Fields{"Service": nvs.Name, "US": nvs.UsHSIAFlowsApplied, "DS": nvs.DsHSIAFlowsApplied, "DelFlag": nvs.DeleteInProgress})
	if err := va.AddService(nvs.VoltServiceCfg, &nvs.VoltServiceOper); err != nil {
		logger.Warnw(ctx, "Add New Service Failed", log.Fields{"Service": nvs.Name, "Error": err})
	}
	logger.Infow(ctx, "Add New Service Triggered", log.Fields{"Service": nvs.Name, "US": nvs.UsHSIAFlowsApplied, "DS": nvs.DsHSIAFlowsApplied, "DelFlag": nvs.DeleteInProgress})

	msr.ServicesList[oldSrvName] = true
	va.updateMigrateServicesRequest(deviceID, oldVnetID, id, msr)
	msr.WriteToDB()

	logger.Infow(ctx, "Del Old Service Triggering", log.Fields{"Service": oldSrvName, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied, "DelFlag": vs.DeleteInProgress})
	va.DelService(oldSrvName, true, nil, true)
	logger.Infow(ctx, "Del Old Service Triggered", log.Fields{"Service": oldSrvName, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied, "DelFlag": vs.DeleteInProgress})
	msr.serviceMigrated(oldSrvName)
}

//serviceMigrated - called on successful service updation
// Removes the service entry from servicelist and deletes the request on process completion
func (msr *MigrateServicesRequest) serviceMigrated(serviceName string) {

	msr.MigrateServicesLock.Lock()
	defer msr.MigrateServicesLock.Unlock()

	delete(msr.ServicesList, serviceName)

	if len(msr.ServicesList) == 0 {
		_ = db.DelMigrateServicesReq(msr.DeviceID, msr.GetMsrKey())
		return
	}
	msr.WriteToDB()
	//TODO:Nav - Need for any Response to SubMgr?
}

//TriggerPendingMigrateServicesReq - trigger pending service request
func (va *VoltApplication) TriggerPendingMigrateServicesReq(device string) {
	va.FetchAndProcessAllMigrateServicesReq(device, storeAndProcessMigrateSrvRequest)
}

//FetchAndProcessAllMigrateServicesReq - fetch all pending migrate services req from DB and process based on provided func
func (va *VoltApplication) FetchAndProcessAllMigrateServicesReq(device string, msrAction func(*MigrateServicesRequest)) {

	msrList, _ := db.GetAllMigrateServicesReq(device)
	for _, msr := range msrList {
		b, ok := msr.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		msr := va.createMigrateServicesFromString(b)
		msrAction(msr)
		logger.Warnw(ctx, "Triggering Pending Migrate Services Req", log.Fields{"OldVnet": msr.OldVnetID, "NewVnet": msr.NewVnetID, "Device": device, "PendingProfiles": len(msr.ServicesList)})

	}
}

// createMigrateServicesFromString to create Service from string
func (va *VoltApplication) createMigrateServicesFromString(b []byte) *MigrateServicesRequest {
	var msr MigrateServicesRequest
	if err := json.Unmarshal(b, &msr); err == nil {
		logger.Debugw(ctx, "Adding Migrate Services Request From Db", log.Fields{"Vlan": msr.OldVnetID})

	} else {
		logger.Warn(ctx, "Unmarshal failed")
	}
	return &msr
}

//storeAndProcessMigrateSrvRequest - stores the msr info in device obj and triggers req
func storeAndProcessMigrateSrvRequest(msr *MigrateServicesRequest) {
	d := GetApplication().GetDevice(msr.DeviceID)
	d.AddMigratingServices(msr)
	msr.ProcessMigrateServicesProfRequest()
}

//forceUpdateAllServices - force udpate services with new vnet profile
func forceUpdateAllServices(msr *MigrateServicesRequest) {
	for srv := range msr.ServicesList {
		if vsIntf, ok := GetApplication().ServiceByName.Load(srv); ok {
			vsIntf.(*VoltService).updateVnetProfile(msr.DeviceID)
		}
	}
	_ = db.DelMigrateServicesReq(msr.DeviceID, msr.GetMsrKey())
}

//DeepEqualServicecfg - checks if the given service cfgs are same
func (va *VoltApplication) DeepEqualServicecfg(evs *VoltServiceCfg, nvs *VoltServiceCfg) bool {
	if nvs.Name != evs.Name {
		return false
	}
	if nvs.UniVlan != evs.UniVlan {
		return false
	}
	if nvs.CVlan != evs.CVlan {
		return false
	}
	if nvs.SVlan != evs.SVlan {
		return false
	}
	if nvs.SVlanTpid != 0 && nvs.SVlanTpid != evs.SVlanTpid {
		return false
	}
	if !util.IsPbitSliceSame(nvs.Pbits, evs.Pbits) {
		return false
	}
	if !reflect.DeepEqual(nvs.DsRemarkPbitsMap, evs.DsRemarkPbitsMap) {
		return false
	}
	if nvs.TechProfileID != evs.TechProfileID {
		return false
	}
	if nvs.CircuitID != evs.CircuitID {
		return false
	}
	if !bytes.Equal(nvs.RemoteID, evs.RemoteID) {
		return false
	}
	if nvs.Port != evs.Port {
		return false
	}
	if nvs.PonPort != evs.PonPort {
		return false
	}
	if evs.MacLearning == MacLearningNone && !util.MacAddrsMatch(nvs.MacAddr, evs.MacAddr) {
		return false
	}
	if nvs.IsOption82Disabled != evs.IsOption82Disabled {
		return false
	}
	if nvs.IgmpEnabled != evs.IgmpEnabled {
		return false
	}
	if nvs.McastService != evs.McastService {
		return false
	}
	if nvs.ONTEtherTypeClassification != evs.ONTEtherTypeClassification {
		return false
	}
	if nvs.UsMeterProfile != evs.UsMeterProfile {
		return false
	}
	if nvs.DsMeterProfile != evs.DsMeterProfile {
		return false
	}
	if nvs.AggDsMeterProfile != evs.AggDsMeterProfile {
		return false
	}
	if nvs.VnetID != evs.VnetID {
		return false
	}
	if nvs.MvlanProfileName != evs.MvlanProfileName {
		return false
	}
	if nvs.RemoteIDType != evs.RemoteIDType {
		return false
	}
	if nvs.SchedID != evs.SchedID {
		return false
	}
	if nvs.AllowTransparent != evs.AllowTransparent {
		return false
	}
	if nvs.EnableMulticastKPI != evs.EnableMulticastKPI {
		return false
	}
	if nvs.DataRateAttr != evs.DataRateAttr {
		return false
	}
	if nvs.MinDataRateUs != evs.MinDataRateUs {
		return false
	}
	if nvs.MinDataRateDs != evs.MinDataRateDs {
		return false
	}
	if nvs.MaxDataRateUs != evs.MaxDataRateUs {
		return false
	}
	if nvs.MaxDataRateDs != evs.MaxDataRateDs {
		return false
	}

	return true
}

//TriggerAssociatedFlowDelete - re-trigger service flow delete for pending delete flows
func (vs *VoltService) TriggerAssociatedFlowDelete() bool {

	//Clear the Flows flag if already set
	//This case happens only in case of some race condition
	if vs.UsHSIAFlowsApplied {
		if err := vs.DelUsHsiaFlows(); err != nil {
			logger.Errorw(ctx, "DelUsHsiaFlows Failed", log.Fields{"Device": vs.Device, "Service": vs.Name, "Error": err})
		}
	}

	if vs.DsHSIAFlowsApplied {
		if err := vs.DelDsHsiaFlows(); err != nil {
			logger.Errorw(ctx, "DelDsHsiaFlows Failed", log.Fields{"Device": vs.Device, "Service": vs.Name, "Error": err})
		}
	}

	vs.ServiceLock.Lock()
	cookieList := []uint64{}
	for cookie := range vs.AssociatedFlows {
		cookieList = append(cookieList, convertToUInt64(cookie))
	}
	vs.ServiceLock.Unlock()

	if len(cookieList) == 0 {
		return false
	}

	//Trigger Flow Delete
	for _, cookie := range cookieList {
		if vd := GetApplication().GetDevice(vs.Device); vd != nil {
			flow := &of.VoltFlow{}
			flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
			subFlow := of.NewVoltSubFlow()
			subFlow.Cookie = cookie
			flow.SubFlows[cookie] = subFlow
			logger.Infow(ctx, "Retriggering Service Delete Flow", log.Fields{"Device": vs.Device, "Service": vs.Name, "Cookie": cookie})
			if err := vs.DelFlows(vd, flow); err != nil {
				logger.Errorw(ctx, "DelFlows Failed", log.Fields{"Device": vs.Device, "Service": vs.Name, "Cookie": cookie, "Error": err})
			}
		}
	}
	return true
}

//triggerServiceInProgressInd - Indication is generated when Service is not provisioned after add serviec req from NB
func (vs *VoltService) triggerServiceInProgressInd() {
}

// JsonMarshal wrapper function for json Marshal VoltService
func (vs *VoltService) JsonMarshal() ([]byte, error) {
	return json.Marshal(VoltService{
		VoltServiceCfg: vs.VoltServiceCfg,
		VoltServiceOper: VoltServiceOper{
			Device:             vs.VoltServiceOper.Device,
			Ipv4Addr:           vs.VoltServiceOper.Ipv4Addr,
			Ipv6Addr:           vs.VoltServiceOper.Ipv6Addr,
			UsMeterID:          vs.VoltServiceOper.UsMeterID,
			DsMeterID:          vs.VoltServiceOper.DsMeterID,
			AggDsMeterID:       vs.VoltServiceOper.AggDsMeterID,
			UsHSIAFlowsApplied: vs.VoltServiceOper.UsHSIAFlowsApplied,
			DsHSIAFlowsApplied: vs.VoltServiceOper.DsHSIAFlowsApplied,
			UsDhcpFlowsApplied: vs.VoltServiceOper.UsDhcpFlowsApplied,
			DsDhcpFlowsApplied: vs.VoltServiceOper.DsDhcpFlowsApplied,
			IgmpFlowsApplied:   vs.VoltServiceOper.IgmpFlowsApplied,
			Icmpv6FlowsApplied: vs.VoltServiceOper.Icmpv6FlowsApplied,
			PendingFlows:       vs.VoltServiceOper.PendingFlows,
			AssociatedFlows:    vs.VoltServiceOper.AssociatedFlows,
			DeleteInProgress:   vs.VoltServiceOper.DeleteInProgress,
			ForceDelete:        vs.VoltServiceOper.ForceDelete,
			BwAvailInfo:        vs.VoltServiceOper.BwAvailInfo,
			UpdateInProgress:   vs.VoltServiceOper.UpdateInProgress,
			Metadata:           vs.VoltServiceOper.Metadata,
		},
	})
}
