/* -----------------------------------------------------------------------
 * Copyright 2022-2024 Open Networking Foundation Contributors
 *
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
 * -----------------------------------------------------------------------
 * SPDX-FileCopyrightText: 2022-2024 Open Networking Foundation Contributors
 * SPDX-License-Identifier: Apache-2.0
 * -----------------------------------------------------------------------
 */

package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	infraerrorCodes "voltha-go-controller/internal/pkg/errorcodes"

	"github.com/google/gopacket/layers"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/controller"
	cntlr "voltha-go-controller/internal/pkg/controller"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

const (
	// DSLAttrEnabled constant
	DSLAttrEnabled string = "ENABLED"
	// DeviceAny constant
	DeviceAny string = "DEVICE-ANY"

	ALL_FLOWS_PROVISIONED string = "ALL_FLOWS_PROVISIONED"

	NO_FLOWS_PROVISIONED string = "NO_FLOWS_PROVISIONED"

	FLOWS_PROVISIONED_PARTIALLY string = "FLOWS_PROVISIONED_PARTIALLY"

	SUBSCRIBER_DISABLED_IN_CONTROLLER string = "DISABLED_IN_CONTROLLER"

	SUBSCRIBER_NOT_IN_CONTROLLER string = "NOT_IN_CONTROLLER"

	ONT_FLOWS_PROVISION_STATE_UNUSED string = "ONT_FLOWS_PROVISION_STATE_UNUSED"
)

// VoltServiceCfg structure
// Name -	Uniquely identifies a service across the entire application
// UniVlan -	The VLAN of the packets entering the UNI of ONU
// CVlan -	The VLAN to transalate to/from on the PON link
// SVlan -	The outer VLAN to be used on the NNI of OLT.
// -	In general, 4096 is used as NO VLAN for all the above
// SVlanTpid - SVlan Tag Protocol Identifier
// Pbits -      Each bit of uint8 represents one p-bit. MSB is pbit 7
// DhcpRelay -	Whether it is turned on/off
// CircuitId -	The circuit id to be used with DHCP relay. Unused otherwise
// RemoveId - 	Same as above
// Port -	The access port for the service. Each service has a single access
// port. The converse is not always true
// MacLearning - If MAC learning is turned on, the MAC address learned from the
// the service activation is used in programming flows
// MacAddress -	The MAC hardware address learnt on the UNI interface
// MacAddresses - Not yet implemented. To be used to learn more MAC addresses
type VoltServiceCfg struct {
	FlowPushCount              map[string]int64 // Tracks the number of flow install/delete failure attempts per cookie in order to throttle flow auditing
	DsRemarkPbitsMap           map[int]int      // Ex: Remark case {0:0,1:0} and No-remark case {1:1}
	Name                       string
	CircuitID                  string
	Port                       string
	UsMeterProfile             string
	DsMeterProfile             string
	AggDsMeterProfile          string
	VnetID                     string
	MvlanProfileName           string
	RemoteIDType               string
	DataRateAttr               string
	ServiceType                string
	Pbits                      []of.PbitType
	RemoteID                   []byte
	MacAddr                    net.HardwareAddr
	Trigger                    ServiceTrigger
	MacLearning                MacLearningType
	ONTEtherTypeClassification int
	SchedID                    int
	PonPort                    uint32
	MinDataRateUs              uint32
	MinDataRateDs              uint32
	MaxDataRateUs              uint32
	MaxDataRateDs              uint32
	SVlanTpid                  layers.EthernetType
	TechProfileID              uint16
	UniVlan                    of.VlanType
	CVlan                      of.VlanType
	SVlan                      of.VlanType
	UsPonCTagPriority          of.PbitType
	UsPonSTagPriority          of.PbitType
	DsPonSTagPriority          of.PbitType
	DsPonCTagPriority          of.PbitType
	ServiceDeactivateReason    SvcDeactivateReason // Mentions why the service was deactivated
	VlanControl                VlanControl
	IsOption82Enabled          bool
	IgmpEnabled                bool
	McastService               bool
	AllowTransparent           bool
	EnableMulticastKPI         bool
	IsActivated                bool
}

// VoltServiceOper structure
type VoltServiceOper struct {
	Metadata        interface{}
	PendingFlows    map[string]bool
	AssociatedFlows map[string]bool
	BwAvailInfo     string
	//MacLearning  bool
	//MacAddr      net.HardwareAddr
	Device               string
	Ipv4Addr             net.IP
	Ipv6Addr             net.IP
	ServiceLock          sync.RWMutex `json:"-"`
	UsMeterID            uint32
	DsMeterID            uint32
	AggDsMeterID         uint32
	UpdateInProgress     bool
	DeleteInProgress     bool
	DeactivateInProgress bool
	ForceDelete          bool
	// Multiservice-Fix
	UsHSIAFlowsApplied bool
	DsHSIAFlowsApplied bool
	UsDhcpFlowsApplied bool
	DsDhcpFlowsApplied bool
	IgmpFlowsApplied   bool
	Icmpv6FlowsApplied bool
}

// VoltService structure
type VoltService struct {
	Version string
	VoltServiceOper
	VoltServiceCfg
}

// ServiceTrigger - Service activation trigger
type ServiceTrigger int

const (
	// NBActivate - Service added due to NB Action
	NBActivate ServiceTrigger = 0
	// ServiceVlanUpdate - Service added due to Svlan Update
	ServiceVlanUpdate ServiceTrigger = 1
)

// SvcDeactivateReason - Reason for service deactivation
type SvcDeactivateReason uint8

const (
	// Service deactivated reason - none
	SvcDeacRsn_None SvcDeactivateReason = 0
	// Service deactivate reason - NB
	SvcDeacRsn_NB SvcDeactivateReason = 1
	// Service deactivate reason - Controller
	SvcDeacRsn_Controller SvcDeactivateReason = 2
)

// AppMutexes structure
type AppMutexes struct {
	ServiceDataMutex sync.Mutex `json:"-"`
	VnetMutex        sync.Mutex `json:"-"`
}

// MigrateServiceMetadata - migrate services request metadata
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
	vs.DeactivateInProgress = false
	vs.ServiceDeactivateReason = SvcDeacRsn_None
	//vs.MacAddr, _ = net.ParseMAC("00:00:00:00:00:00")

	vs.IsOption82Enabled = cfg.IsOption82Enabled
	vs.MacAddr = cfg.MacAddr
	vs.Ipv4Addr = net.ParseIP("0.0.0.0")
	vs.Ipv6Addr = net.ParseIP("::")
	vs.PendingFlows = make(map[string]bool)
	vs.AssociatedFlows = make(map[string]bool)
	vs.FlowPushCount = make(map[string]int64)
	return &vs
}

// WriteToDb commit a service to the DB if service delete is not in-progress
func (vs *VoltService) WriteToDb(cntx context.Context) {
	vs.ServiceLock.RLock()
	defer vs.ServiceLock.RUnlock()

	if vs.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Redis Update for Service, Service delete in progress", log.Fields{"Service": vs.Name})
		return
	}
	vs.ForceWriteToDb(cntx)
}

// ForceWriteToDb force commit a service to the DB
func (vs *VoltService) ForceWriteToDb(cntx context.Context) {
	b, err := json.Marshal(vs)

	if err != nil {
		logger.Errorw(ctx, "Json Marshal Failed for Service", log.Fields{"Service": vs.Name})
		return
	}
	if err1 := db.PutService(cntx, vs.Name, string(b)); err1 != nil {
		logger.Errorw(ctx, "DB write oper failed for Service", log.Fields{"Service": vs.Name})
	}
}

// isDataRateAttrPresent to check if data attribute is present
func (vs *VoltService) isDataRateAttrPresent() bool {
	return vs.DataRateAttr == DSLAttrEnabled
}

// DelFromDb delete a service from DB
func (vs *VoltService) DelFromDb(cntx context.Context) {
	logger.Debugw(ctx, "Deleting Service from DB", log.Fields{"Name": vs.Name})
	// TODO - Need to understand and delete the second call
	// Calling twice has worked though don't know why
	_ = db.DelService(cntx, vs.Name)
	_ = db.DelService(cntx, vs.Name)
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
	logger.Debugw(ctx, "Request for IsPbitExist", log.Fields{"pbit": pbit})
	for _, pb := range vs.Pbits {
		if pb == pbit {
			return true
		}
	}
	return false
}

// AddHsiaFlows - Adds US & DS HSIA Flows for the service
func (vs *VoltService) AddHsiaFlows(cntx context.Context) {
	logger.Debugw(ctx, "Add US & DS HSIA Flows for the service", log.Fields{"ServiceName": vs.Name})
	if err := vs.AddUsHsiaFlows(cntx); err != nil {
		logger.Errorw(ctx, "Error adding US HSIA Flows", log.Fields{"Service": vs.Name, "Port": vs.Port, "Reason": err.Error()})
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}
	if err := vs.AddDsHsiaFlows(cntx); err != nil {
		logger.Errorw(ctx, "Error adding DS HSIA Flows", log.Fields{"Service": vs.Name, "Port": vs.Port, "Reason": err.Error()})
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}
}

// DelHsiaFlows - Deletes US & DS HSIA Flows for the service
func (vs *VoltService) DelHsiaFlows(cntx context.Context) {
	logger.Debugw(ctx, "Delete US & DS HSIA Flows for the service", log.Fields{"ServiceName": vs.Name})
	if err := vs.DelUsHsiaFlows(cntx, false); err != nil {
		logger.Errorw(ctx, "Error deleting US HSIA Flows", log.Fields{"Service": vs.Name, "Port": vs.Port, "Reason": err.Error()})
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}

	if err := vs.DelDsHsiaFlows(cntx, false); err != nil {
		logger.Errorw(ctx, "Error deleting DS HSIA Flows", log.Fields{"Service": vs.Name, "Port": vs.Port, "Reason": err.Error()})
		statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
		vs.triggerServiceFailureInd(statusCode, statusMessage)
	}
}

func (vs *VoltService) AddMeterToDevice(cntx context.Context) error {
	logger.Debugw(ctx, "Add Meter To Device for the service", log.Fields{"ServiceName": vs.Name})
	if vs.DeleteInProgress || vs.UpdateInProgress {
		logger.Warnw(ctx, "Ignoring Meter Push, Service deleteion In-Progress", log.Fields{"Device": vs.Device, "Service": vs.Name})
	}
	va := GetApplication()
	logger.Infow(ctx, "Configuring Meters for FTTB", log.Fields{"ServiceName": vs.Name})
	device, err := va.GetDeviceFromPort(vs.Port)
	if err != nil {
		return fmt.Errorf("Error during Getting Device from Port %s for service %s : %w", vs.Port, vs.Name, err)
	} else if device.State != controller.DeviceStateUP {
		logger.Warnw(ctx, "Device state Down. Ignoring Meter Push", log.Fields{"Service": vs.Name, "Port": vs.Port})
		return nil
	}
	va.AddMeterToDevice(vs.Port, device.Name, vs.UsMeterID, 0)
	va.AddMeterToDevice(vs.Port, device.Name, vs.DsMeterID, vs.AggDsMeterID)
	return nil
}

// AddUsHsiaFlows - Add US HSIA Flows for the service
func (vs *VoltService) AddUsHsiaFlows(cntx context.Context) error {
	logger.Infow(ctx, "Configuring US HSIA Service Flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Port": vs.Port})
	if vs.DeleteInProgress || vs.UpdateInProgress {
		logger.Warnw(ctx, "Ignoring US HSIA Flow Push, Service deleteion In-Progress", log.Fields{"Device": vs.Device, "Service": vs.Name})
		return nil
	}

	va := GetApplication()
	if !vs.UsHSIAFlowsApplied || vgcRebooted {
		device, err := va.GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device for Service and Port", log.Fields{"Service": vs.Name, "Port": vs.Port, "Error": err})
			return fmt.Errorf("Error Getting Device for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Ignoring US HSIA Flow Push", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return nil
		}

		vs.Device = device.Name
		/* In case of DPU_MGMT_TRAFFIC the meters will be configured before US flow creation*/
		if vs.ServiceType != DpuMgmtTraffic {
			va.AddMeterToDevice(vs.Port, device.Name, vs.UsMeterID, 0)
			va.AddMeterToDevice(vs.Port, device.Name, vs.DsMeterID, vs.AggDsMeterID)
		}
		pBits := vs.Pbits

		// If no pbits configured for service, hence add PbitNone for flows
		if len(vs.Pbits) == 0 {
			pBits = append(pBits, PbitMatchNone)
		}
		for _, pbits := range pBits {
			usflows, err := vs.BuildUsHsiaFlows(pbits)
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA US flows", log.Fields{"Device": vs.Device, "Service": vs.Name, "Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
				continue
			}
			usflows.MigrateCookie = vgcRebooted
			if err := vs.AddFlows(cntx, device, usflows); err != nil {
				logger.Errorw(ctx, "Error adding HSIA US flows", log.Fields{"Device": vs.Device, "Service": vs.Name, "Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		}
		vs.UsHSIAFlowsApplied = true
		logger.Debugw(ctx, "Pushed US HSIA Service Flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name})
	}
	vs.WriteToDb(cntx)
	return nil
}

// AddDsHsiaFlows - Add DS HSIA Flows for the service
func (vs *VoltService) AddDsHsiaFlows(cntx context.Context) error {
	logger.Infow(ctx, "Configuring DS HSIA Service Flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Port": vs.Port})
	if vs.DeleteInProgress {
		logger.Warnw(ctx, "Ignoring DS HSIA Flow Push, Service deleteion In-Progress", log.Fields{"Device": vs.Device, "Service": vs.Name})
		return nil
	}

	va := GetApplication()
	if !vs.DsHSIAFlowsApplied || vgcRebooted {
		device, err := va.GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device for Service and Port", log.Fields{"Service": vs.Name, "Port": vs.Port, "Error": err})
			return fmt.Errorf("Error Getting Device for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Ignoring DS HSIA Flow Push", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return nil
		}

		va.AddMeterToDevice(vs.Port, device.Name, vs.DsMeterID, vs.AggDsMeterID)

		//If no pbits configured for service, hence add PbitNone for flows
		if len(vs.DsRemarkPbitsMap) == 0 {
			dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(of.PbitMatchNone))
			if err != nil {
				return fmt.Errorf("Error Building HSIA DS flows for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
			}
			dsflows.MigrateCookie = vgcRebooted
			if err = vs.AddFlows(cntx, device, dsflows); err != nil {
				logger.Errorw(ctx, "Failed to add HSIA DS flows", log.Fields{"Device": vs.Device, "Service": vs.Name, "Reason": err})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		} else {
			// if all 8 p-bits are to be remarked to one-pbit, configure all-to-one remarking flow
			if _, ok := vs.DsRemarkPbitsMap[int(of.PbitMatchAll)]; ok {
				dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(of.PbitMatchAll))
				if err != nil {
					return fmt.Errorf("Error Building HSIA DS flows for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
				}
				logger.Debug(ctx, "Add-one-match-all-pbit-flow")
				dsflows.MigrateCookie = vgcRebooted
				if err := vs.AddFlows(cntx, device, dsflows); err != nil {
					logger.Errorw(ctx, "Failed to add HSIA DS flows", log.Fields{"Device": vs.Device, "Service": vs.Name, "Reason": err})
					statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
					vs.triggerServiceFailureInd(statusCode, statusMessage)
				}
			} else {
				for matchPbit := range vs.DsRemarkPbitsMap {
					dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(matchPbit))
					if err != nil {
						logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Device": vs.Device, "Service": vs.Name, "Reason": err.Error()})
						statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
						vs.triggerServiceFailureInd(statusCode, statusMessage)
						continue
					}
					dsflows.MigrateCookie = vgcRebooted
					if err := vs.AddFlows(cntx, device, dsflows); err != nil {
						logger.Errorw(ctx, "Failed to Add HSIA DS flows", log.Fields{"Device": vs.Device, "Service": vs.Name, "Reason": err})
						statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
						vs.triggerServiceFailureInd(statusCode, statusMessage)
					}
				}
			}
		}
		vs.DsHSIAFlowsApplied = true
		logger.Debugw(ctx, "Pushed DS HSIA Service Flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name})
	}
	vs.WriteToDb(cntx)
	return nil
}

// DelUsHsiaFlows - Deletes US HSIA Flows for the service
func (vs *VoltService) DelUsHsiaFlows(cntx context.Context, delFlowsInDevice bool) error {
	logger.Infow(ctx, "Removing US HSIA Services", log.Fields{"Device": vs.Device, "ServiceName": vs.Name})
	if vs.UsHSIAFlowsApplied || vgcRebooted {
		device, err := GetApplication().GetDeviceFromPort(vs.Port)
		if err != nil {
			logger.Errorw(ctx, "Error Getting Device for Servic and Port", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err})
			return fmt.Errorf("Error Getting Device for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
		}
		pBits := vs.Pbits

		// If no pbits configured for service, hence add PbitNone for flows
		if len(vs.Pbits) == 0 {
			pBits = append(pBits, PbitMatchNone)
		}
		for _, pbits := range pBits {
			usflows, err := vs.BuildUsHsiaFlows(pbits)
			if err != nil {
				logger.Errorw(ctx, "Error Building HSIA US flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
				continue
			}
			usflows.MigrateCookie = vgcRebooted
			if err = vs.DelFlows(cntx, device, usflows, delFlowsInDevice); err != nil {
				logger.Errorw(ctx, "Error Deleting HSIA US flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		}
		vs.UsHSIAFlowsApplied = false
	}
	vs.WriteToDb(cntx)
	return nil
}

// DelDsHsiaFlows - Deletes DS HSIA Flows for the service
func (vs *VoltService) DelDsHsiaFlows(cntx context.Context, delFlowsInDevice bool) error {
	logger.Infow(ctx, "Removing DS HSIA Services", log.Fields{"Device": vs.Device, "ServiceName": vs.Name})
	if vs.DsHSIAFlowsApplied || vgcRebooted {
		device, err := GetApplication().GetDeviceFromPort(vs.Port)
		if err != nil {
			return fmt.Errorf("Error Getting Device for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
		}

		var matchPbit int
		// If no pbits configured for service, hence add PbitNone for flows
		if len(vs.DsRemarkPbitsMap) == 0 {
			dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(PbitMatchNone))
			if err != nil {
				return fmt.Errorf("Error Building HSIA DS flows for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
			}
			dsflows.MigrateCookie = vgcRebooted
			if err = vs.DelFlows(cntx, device, dsflows, delFlowsInDevice); err != nil {
				logger.Errorw(ctx, "Error Deleting HSIA DS flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		} else if _, ok := vs.DsRemarkPbitsMap[int(PbitMatchAll)]; ok {
			dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(int(PbitMatchAll)))
			if err != nil {
				return fmt.Errorf("Error Building HSIA DS flows for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
			}
			dsflows.MigrateCookie = vgcRebooted
			if err = vs.DelFlows(cntx, device, dsflows, delFlowsInDevice); err != nil {
				logger.Errorw(ctx, "Error Deleting HSIA DS flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err.Error()})
				statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
				vs.triggerServiceFailureInd(statusCode, statusMessage)
			}
		} else {
			for matchPbit = range vs.DsRemarkPbitsMap {
				dsflows, err := vs.BuildDsHsiaFlows(of.PbitType(matchPbit))
				if err != nil {
					logger.Errorw(ctx, "Error Building HSIA DS flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err.Error()})
					statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
					vs.triggerServiceFailureInd(statusCode, statusMessage)
					continue
				}
				dsflows.MigrateCookie = vgcRebooted
				if err = vs.DelFlows(cntx, device, dsflows, delFlowsInDevice); err != nil {
					logger.Errorw(ctx, "Error Deleting HSIA DS flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Reason": err.Error()})
					statusCode, statusMessage := infraerrorCodes.GetErrorInfo(err)
					vs.triggerServiceFailureInd(statusCode, statusMessage)
				}
			}
		}
		vs.DsHSIAFlowsApplied = false
	}
	logger.Infow(ctx, "Deleted HSIA DS flows from DB successfully", log.Fields{"Device": vs.Device, "ServiceName": vs.Name})
	// Post HSIA configuration success indication on message bus
	vs.WriteToDb(cntx)
	return nil
}

// BuildDsHsiaFlows build the DS HSIA flows
// Called for add/delete HSIA flows
func (vs *VoltService) BuildDsHsiaFlows(pbits of.PbitType) (*of.VoltFlow, error) {
	logger.Debugw(ctx, "Building DS HSIA Service Flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name})
	flow := &of.VoltFlow{}
	flow.SubFlows = make(map[uint64]*of.VoltSubFlow)

	// Get the out and in ports for the flows
	device, err := GetApplication().GetDeviceFromPort(vs.Port)
	if err != nil {
		return nil, fmt.Errorf("Error Getting Device for Service %s and Port %s  : %w", vs.Name, vs.Port, err)
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
		// | 12-bit cvlan/UniVlan | 4 bits action pbit | <32-bits uniport>| 16-bits HSIA mask OR flow mask OR pbit |
		cookie := uint64(vlan)<<52 + uint64(actnPbit)<<48 + uint64(outport)<<16 | of.HsiaFlowMask
		cookie = cookie | of.DsFlowMask
		cookie = cookie + (valToShift << 4) + uint64(pbits)
		return cookie
	}

	l2ProtoValue, err := GetMetadataForL2Protocol(vs.SVlanTpid)
	if err != nil {
		return nil, fmt.Errorf("DS HSIA flow push failed: Invalid SvlanTpid for Service %s and SvlanTpid %s  : %w", vs.SVlanTpid, vs.Port, err)
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
		logger.Infow(ctx, "HSIA DS flows MAC Learning & MAC", log.Fields{"ML": vs.MacLearning, "Mac": vs.MacAddr})
		if NonZeroMacAddress(vs.MacAddr) {
			subflow1.SetMatchDstMac(vs.MacAddr)
		}
		subflow1.Priority = of.HsiaFlowPriority
		subflow1.SetMeterID(vs.DsMeterID)

		/* WriteMetaData 8 Byte(uint64) usage:
		| Byte8    | Byte7    | Byte6 | Byte5  | Byte4  | Byte3   | Byte2  | Byte1 |
		| reserved | reserved | TpID  | TpID   | uinID  | uniID   | uniID  | uniID | */
		metadata := uint64(vs.CVlan)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		if vs.ServiceType == FttbSubscriberTraffic {
			metadata = uint64(of.VlanAny)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		}
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

		if vs.ServiceType != FttbSubscriberTraffic {
			metadata = uint64(l2ProtoValue)<<58 | uint64(allowTransparent)<<56 | uint64(vs.SchedID)<<40 | uint64(vs.ONTEtherTypeClassification)<<36 | uint64(vs.VlanControl)<<32 | uint64(vs.CVlan)
			subflow1.SetTableMetadata(metadata)
		}
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

	// Add Table-1 flow that deals with inner VLAN at the ONU
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
		if vs.ServiceType == FttbSubscriberTraffic {
			metadata = uint64(of.VlanAny)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		}
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
	logger.Debugw(ctx, "Building US HSIA Service Flows", log.Fields{"Device": vs.Device, "ServiceName": vs.Name, "Port": vs.Port})
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

	// Add Table-0 flow that deals with the inner VLAN in ONU
	{
		subflow1 := of.NewVoltSubFlow()
		subflow1.SetTableID(0)
		subflow1.SetGoToTable(1)
		subflow1.SetInPort(inport)

		if vs.ServiceType == DpuMgmtTraffic {
			subflow1.SetMatchPbit(vs.UsPonCTagPriority)
			subflow1.SetPcp(vs.UsPonSTagPriority)
		} else if vs.ServiceType == DpuAncpTraffic {
			subflow1.SetPcp(vs.UsPonSTagPriority)
		}
		if err := vs.setUSMatchActionVlanT0(subflow1); err != nil {
			return nil, err
		}
		subflow1.SetMeterID(vs.UsMeterID)

		/* WriteMetaData 8 Byte(uint64) usage:
		| Byte8    | Byte7    | Byte6 | Byte5  | Byte4  | Byte3   | Byte2  | Byte1 |
		| reserved | reserved | TpID  | TpID   | uinID  | uniID   | uniID  | uniID | */
		//metadata := uint64(vs.CVlan)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		metadata := uint64(vs.TechProfileID)<<32 + uint64(outport)
		if vs.ServiceType == FttbSubscriberTraffic {
			metadata = uint64(of.VlanAny)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		}
		subflow1.SetWriteMetadata(metadata)

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

	// Add Table-1 flow that deals with the outer vlan in pOLT
	{
		subflow2 := of.NewVoltSubFlow()
		subflow2.SetTableID(1)
		subflow2.SetInPort(inport)

		if err := vs.setUSMatchActionVlanT1(subflow2); err != nil {
			return nil, err
		}
		if vs.ServiceType == DpuMgmtTraffic {
			subflow2.SetMatchSrcMac(vs.MacAddr)
		}
		subflow2.SetInPort(inport)
		subflow2.SetOutPort(outport)
		subflow2.SetMeterID(vs.UsMeterID)

		// refer Table-0 flow generation for byte information
		metadata := uint64(vs.TechProfileID)<<32 + uint64(outport)
		if vs.ServiceType == FttbSubscriberTraffic {
			metadata = uint64(of.VlanAny)<<48 + uint64(vs.TechProfileID)<<32 + uint64(outport)
		}
		subflow2.SetWriteMetadata(metadata)

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
	// | 12-bit cvlan/UniVlan | 4 bits empty | <32-bits uniport>| 16-bits HSIA mask OR flow mask OR pbit |
	logger.Debugw(ctx, "Generate US Cookie", log.Fields{"Vlan": vlan, "ValToShift": vlan, "Inport": inport, "Pbits": pbits})
	cookie := uint64(vlan)<<52 + uint64(inport)<<16 | of.HsiaFlowMask
	cookie = cookie | of.UsFlowMask
	cookie = cookie + (valToShift << 4) + uint64(pbits)
	return cookie
}

// setUSMatchActionVlanT1 - Sets the Match & Action w.r.t Vlans for US Table-1
// based on different Vlan Controls
func (vs *VoltService) setUSMatchActionVlanT1(flow *of.VoltSubFlow) error {
	logger.Debugw(ctx, "Set US Match Action Vlan T1", log.Fields{"Value": vs.VlanControl})
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
		err := errorCodes.ErrInvalidParamInRequest
		return fmt.Errorf("Invalid Vlan Control Option %d : %w", vs.VlanControl, err)
	}
	return nil
}

// setDSMatchActionVlanT0 - Sets the Match & Action w.r.t Vlans for DS Table-0
// based on different Vlan Controls
func (vs *VoltService) setDSMatchActionVlanT0(flow *of.VoltSubFlow) error {
	logger.Debugw(ctx, "Set DS Match Action Vlan T0", log.Fields{"Value": vs.VlanControl})
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
		err := errorCodes.ErrInvalidParamInRequest
		return fmt.Errorf("Invalid Vlan Control Option %d : %w", vs.VlanControl, err)
	}
	return nil
}

// setUSMatchActionVlanT0 - Sets the Match & Action w.r.t Vlans for US Table-0
// based on different Vlan Controls
func (vs *VoltService) setUSMatchActionVlanT0(flow *of.VoltSubFlow) error {
	logger.Debugw(ctx, "Set US Match Action Vlan T0", log.Fields{"Value": vs.VlanControl})
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
		err := errorCodes.ErrInvalidParamInRequest
		return fmt.Errorf("Invalid Vlan Control Option %d : %w", vs.VlanControl, err)
	}
	return nil
}

// setDSMatchActionVlanT1 - Sets the Match & Action w.r.t Vlans for DS Table-1
// based on different Vlan Controls
func (vs *VoltService) setDSMatchActionVlanT1(flow *of.VoltSubFlow) error {
	logger.Debugw(ctx, "Set DS Match Action Vlan T1", log.Fields{"Value": vs.VlanControl})
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
		err := errorCodes.ErrInvalidParamInRequest
		return fmt.Errorf("Invalid Vlan Control Option %d : %w", vs.VlanControl, err)
	}
	return nil
}

// SvcUpInd for service up indication
func (vs *VoltService) SvcUpInd(cntx context.Context) {
	vs.AddHsiaFlows(cntx)
}

// SvcDownInd for service down indication
func (vs *VoltService) SvcDownInd(cntx context.Context) {
	vs.DelHsiaFlows(cntx)
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
func (va *VoltApplication) AddService(cntx context.Context, cfg VoltServiceCfg, oper *VoltServiceOper) error {
	logger.Infow(ctx, "Service to be configured", log.Fields{"Cfg": cfg})
	var mmUs, mmDs *VoltMeter
	var err error

	// Take the  Device lock only in case of NB add request.
	// Allow internal adds since internal add happen only under
	// 1. Restore Service from DB
	// 2. Service Migration
	if oper == nil {
		if svc := va.GetService(cfg.Name); svc != nil {
			logger.Warnw(ctx, "Service Already Exists. Ignoring Add Service Request", log.Fields{"Name": cfg.Name})
			return errors.New("service already exists")
		}
	}

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
		vs.DeactivateInProgress = oper.DeactivateInProgress
		vs.BwAvailInfo = oper.BwAvailInfo
		vs.Device = oper.Device
		vs.ServiceDeactivateReason = cfg.ServiceDeactivateReason
	} else {
		// Sorting Pbit from highest
		sort.Slice(vs.Pbits, func(i, j int) bool {
			return vs.Pbits[i] > vs.Pbits[j]
		})
		logger.Debugw(ctx, "Sorted Pbits", log.Fields{"Pbits": vs.Pbits})
	}
	logger.Infow(ctx, "VolthService...", log.Fields{"vs": vs.Name})

	// The bandwidth and shaper profile combined into meter
	if mmDs, err = va.GetMeter(cfg.DsMeterProfile); err == nil {
		vs.DsMeterID = mmDs.ID
	} else {
		return errors.New("downStream meter profile not found")
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
		return errors.New("upstream meter profile not found")
	}
	//}

	AppMutex.ServiceDataMutex.Lock()
	defer AppMutex.ServiceDataMutex.Unlock()

	// Add the service to the VNET
	vnet := va.GetVnet(cfg.SVlan, cfg.CVlan, cfg.UniVlan)
	if vnet != nil {
		if vpv := va.GetVnetByPort(vs.Port, cfg.SVlan, cfg.CVlan, cfg.UniVlan); vpv != nil {
			vpv.VpvLock.Lock()
			vpv.AddSvc(cntx, vs)
			vpv.VpvLock.Unlock()
		} else {
			va.AddVnetToPort(cntx, vs.Port, vnet, vs)
		}
	} else {
		logger.Warnw(ctx, "VNET-does-not-exist-for-service", log.Fields{"ServiceName": cfg.Name})
		return errors.New("vnet doesn't exist")
	}

	// If the device is already discovered, update the device name in service
	d, err := va.GetDeviceFromPort(vs.Port)
	if err == nil {
		vs.Device = d.Name
	}

	vs.Version = database.PresentVersionMap[database.ServicePath]
	// Add the service to the volt application
	va.ServiceByName.Store(vs.Name, vs)
	vs.WriteToDb(cntx)

	if nil == oper {
		if !vs.UsHSIAFlowsApplied {
			vs.triggerServiceInProgressInd()
		}

		// Update meter profiles service count if service is being added from northbound
		mmDs.AssociatedServices++
		va.UpdateMeterProf(cntx, *mmDs)
		if mmUs != nil {
			mmUs.AssociatedServices++
			va.UpdateMeterProf(cntx, *mmUs)
		}
		//mmAg.AssociatedServices++
		//va.UpdateMeterProf(*mmAg)
		logger.Debugw(ctx, "northbound-service-add-successful", log.Fields{"ServiceName": vs.Name})
	}

	logger.Debugw(ctx, "Added Service to DB", log.Fields{"Name": vs.Name, "Port": (vs.Port), "ML": vs.MacLearning})
	return nil
}

// DelServiceWithPrefix - Deletes service with the provided prefix.
// Added for DT/TT usecase with sadis replica interface
func (va *VoltApplication) DelServiceWithPrefix(cntx context.Context, prefix string) error {
	logger.Debugw(ctx, "Delete Service With provided Prefix", log.Fields{"Prefix": prefix})
	var isServiceExist bool
	va.ServiceByName.Range(func(key, value interface{}) bool {
		srvName := key.(string)
		vs := value.(*VoltService)
		if strings.Contains(srvName, prefix) {
			isServiceExist = true
			va.DelService(cntx, srvName, true, nil, false)

			vnetName := strconv.FormatUint(uint64(vs.SVlan), 10) + "-"
			vnetName = vnetName + strconv.FormatUint(uint64(vs.CVlan), 10) + "-"
			vnetName = vnetName + strconv.FormatUint(uint64(vs.UniVlan), 10)

			if err := va.DelVnet(cntx, vnetName, ""); err != nil {
				logger.Warnw(ctx, "Delete Vnet Failed", log.Fields{"Name": vnetName, "Error": err})
			}
		}
		return true
	})

	if !isServiceExist {
		return errorCodes.ErrServiceNotFound
	}
	return nil
}

// DelService delete a service form the application
func (va *VoltApplication) DelService(cntx context.Context, name string, forceDelete bool, newSvc *VoltServiceCfg, serviceMigration bool) {
	AppMutex.ServiceDataMutex.Lock()
	defer AppMutex.ServiceDataMutex.Unlock()

	logger.Infow(ctx, "Delete Service Request", log.Fields{"Service": name, "ForceDelete": forceDelete, "serviceMigration": serviceMigration})
	var noFlowsPresent bool

	vsIntf, ok := va.ServiceByName.Load(name)
	if !ok {
		logger.Warnw(ctx, "Service doesn't exist", log.Fields{"ServiceName": name})
		return
	}
	vs := vsIntf.(*VoltService)
	vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan)
	if vpv == nil {
		logger.Warnw(ctx, "Vpv Not found for Service", log.Fields{"vs": vs.Name})
		return
	}

	// Set this to avoid race-condition during flow result processing
	vs.DeleteInProgress = true
	vs.ForceDelete = forceDelete
	vs.ForceWriteToDb(cntx)

	vs.ServiceLock.RLock()
	if len(vs.AssociatedFlows) == 0 {
		noFlowsPresent = true
	}
	vs.ServiceLock.RUnlock()

	vpv.VpvLock.Lock()
	defer vpv.VpvLock.Unlock()

	vs.DelHsiaFlows(cntx)

	if vpv.IgmpEnabled {
		va.ReceiverDownInd(cntx, vpv.Device, vpv.Port)
	}
	logger.Infow(ctx, "Delete Service from VPV", log.Fields{"VPV_Port": vpv.Port, "VPV_SVlan": vpv.SVlan, "VPV_CVlan": vpv.CVlan, "VPV_UniVlan": vpv.UniVlan, "ServiceName": name})
	vpv.DelService(cntx, vs)
	if vpv.servicesCount.Load() == 0 {
		va.DelVnetFromPort(cntx, vs.Port, vpv)
	}

	// Delete the service immediately in case of Force Delete
	// This will be enabled when profile reconciliation happens after restore
	// of backedup data
	if vs.ForceDelete {
		vs.DelFromDb(cntx)
		GetApplication().ServiceByName.Delete(vs.Name)
		logger.Debugw(ctx, "Deleted service from DB/Cache successfully", log.Fields{"serviceName": vs.Name})
	}

	if nil != newSvc {
		logger.Infow(ctx, "Old Service meter profiles", log.Fields{"AGG": vs.AggDsMeterProfile, "DS": vs.DsMeterProfile, "US": vs.UsMeterProfile})
		logger.Infow(ctx, "New Service meter profiles", log.Fields{"AGG": newSvc.AggDsMeterProfile, "DS": newSvc.DsMeterProfile, "US": newSvc.UsMeterProfile})
	}

	logger.Infow(ctx, "About to mark meter for deletion\n", log.Fields{"serviceName": vs.Name})

	if aggMeter, ok := va.MeterMgr.GetMeterByID(vs.AggDsMeterID); ok {
		if nil == newSvc || (nil != newSvc && aggMeter.Name != newSvc.AggDsMeterProfile) {
			if aggMeter.AssociatedServices > 0 {
				aggMeter.AssociatedServices--
				logger.Infow(ctx, "Agg Meter associated services updated\n", log.Fields{"MeterID": aggMeter})
				va.UpdateMeterProf(cntx, *aggMeter)
			}
		}
	}
	if dsMeter, ok := va.MeterMgr.GetMeterByID(vs.DsMeterID); ok {
		if nil == newSvc || (nil != newSvc && dsMeter.Name != newSvc.DsMeterProfile) {
			if dsMeter.AssociatedServices > 0 {
				dsMeter.AssociatedServices--
				logger.Infow(ctx, "DS Meter associated services updated\n", log.Fields{"MeterID": dsMeter})
				va.UpdateMeterProf(cntx, *dsMeter)
			}
		}
	}
	if vs.AggDsMeterID != vs.UsMeterID {
		if usMeter, ok := va.MeterMgr.GetMeterByID(vs.UsMeterID); ok {
			if nil == newSvc || (nil != newSvc && usMeter.Name != newSvc.UsMeterProfile) {
				if usMeter.AssociatedServices > 0 {
					usMeter.AssociatedServices--
					logger.Infow(ctx, "US Meter associated services updated\n", log.Fields{"MeterID": usMeter})
					va.UpdateMeterProf(cntx, *usMeter)
				}
			}
		}
	}

	if noFlowsPresent || vs.ForceDelete {
		vs.CheckAndDeleteService(cntx)
	}

	// Delete the per service counter too
	va.ServiceCounters.Delete(name)
	if vs.IgmpEnabled && vs.EnableMulticastKPI {
		_ = db.DelAllServiceChannelCounter(cntx, name)
	}
}

// AddFlows - Adds the flow to the service
// Triggers flow addition after registering for flow indication event
func (vs *VoltService) AddFlows(cntx context.Context, device *VoltDevice, flow *of.VoltFlow) error {
	// Using locks instead of concurrent map for PendingFlows to avoid
	// race condition during flow response indication processing
	vs.ServiceLock.Lock()
	defer vs.ServiceLock.Unlock()
	logger.Debugw(ctx, "Adds the flow to the service", log.Fields{"Port": vs.Port, "Device": device.Name})

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
	return cntlr.GetController().AddFlows(cntx, vs.Port, device.Name, flow)
}

// FlowInstallSuccess - Called when corresponding service flow installation is success
// If no more pending flows, HSIA indication wil be triggered
func (vs *VoltService) FlowInstallSuccess(cntx context.Context, cookie string, bwAvailInfo of.BwAvailDetails) {
	logger.Debugw(ctx, "Flow Add Success Notification", log.Fields{"Cookie": cookie, "bwAvailInfo": bwAvailInfo, "Service": vs.Name})
	if vs.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Flow Add Success Notification. Service deletion in-progress", log.Fields{"Cookie": cookie, "Service": vs.Name})
		return
	}
	vs.ServiceLock.Lock()

	if _, ok := vs.PendingFlows[cookie]; !ok {
		logger.Warnw(ctx, "Flow Add Success for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie})
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
		logger.Debugw(ctx, "Bandwidth-value-formed", log.Fields{"BwAvailInfo": vs.BwAvailInfo})
	}
	vs.WriteToDb(cntx)

	vs.ServiceLock.RLock()
	if len(vs.PendingFlows) == 0 && vs.DsHSIAFlowsApplied {
		vs.ServiceLock.RUnlock()
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
			defer vs.WriteToDb(cntx)
		}
		logger.Infow(ctx, "All Flows installed for Service", log.Fields{"Service": vs.Name})
		return
	}
	vs.ServiceLock.RUnlock()
	logger.Debugw(ctx, "Processed Service Flow Add Success Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "DsFlowsApplied": vs.DsHSIAFlowsApplied})
}

// FlowInstallFailure - Called when corresponding service flow installation is failed
// Trigger service failure indication to NB
func (vs *VoltService) FlowInstallFailure(cntx context.Context, cookie string, errorCode uint32, errReason string) {
	logger.Debugw(ctx, "Service flow installation failure", log.Fields{"Service": vs.Name, "Cookie": cookie, "errorCode": errorCode, "errReason": errReason})
	vs.ServiceLock.RLock()

	if _, ok := vs.PendingFlows[cookie]; !ok {
		logger.Errorw(ctx, "Flow Add Failure for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie})
		vs.ServiceLock.RUnlock()
		return
	}
	vs.ServiceLock.RUnlock()
	logger.Debugw(ctx, "HSIA Flow Add Failure Notification", log.Fields{"uniPort": vs.Port, "Cookie": cookie, "Service": vs.Name, "ErrorCode": errorCode, "ErrorReason": errReason})
	vs.triggerServiceFailureInd(errorCode, errReason)
}

// DelFlows - Deletes the flow from the service
// Triggers flow deletion after registering for flow indication event
func (vs *VoltService) DelFlows(cntx context.Context, device *VoltDevice, flow *of.VoltFlow, delFlowsInDevice bool) error {
	logger.Infow(ctx, "Delete the flow from the service", log.Fields{"Port": vs.Port, "Device": device.Name, "cookie": flow.MigrateCookie})
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
	return cntlr.GetController().DelFlows(cntx, vs.Port, device.Name, flow, delFlowsInDevice)
}

// CheckAndDeleteService - remove service from DB is there are no pending flows to be removed
func (vs *VoltService) CheckAndDeleteService(cntx context.Context) {
	logger.Debugw(ctx, "Delete service from DB/Cache", log.Fields{"serviceName": vs.Name})
	if vs.DeleteInProgress && len(vs.AssociatedFlows) == 0 && !vs.DsHSIAFlowsApplied {
		vs.DelFromDb(cntx)
		GetApplication().ServiceByName.Delete(vs.Name)
		logger.Debugw(ctx, "Deleted service from DB/Cache successfully", log.Fields{"serviceName": vs.Name})
	}
}

// FlowRemoveSuccess - Called when corresponding service flow removal is success
// If no more associated flows, DelHSIA indication wil be triggered
func (vs *VoltService) FlowRemoveSuccess(cntx context.Context, cookie string) {
	// if vs.DeleteInProgress {
	// 	logger.Warnw(ctx, "Skipping Flow Remove Success Notification. Service deletion in-progress", log.Fields{"Cookie": cookie, "Service": vs.Name})
	// 	return
	// }

	vs.ServiceLock.Lock()
	logger.Debugw(ctx, "Processing Service Flow Remove Success Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "Associated Flows": vs.AssociatedFlows, "DsFlowsApplied": vs.DsHSIAFlowsApplied})

	if _, ok := vs.AssociatedFlows[cookie]; ok {
		delete(vs.AssociatedFlows, cookie)
	} else if _, ok := vs.PendingFlows[cookie]; ok {
		logger.Debugw(ctx, "Service Flow Remove: Cookie Present in Pending Flow list. No Action", log.Fields{"Service": vs.Name, "Cookie": cookie, "AssociatedFlows": vs.AssociatedFlows, "PendingFlows": vs.PendingFlows})
	} else {
		logger.Debugw(ctx, "Service Flow Remove Success for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie, "AssociatedFlows": vs.AssociatedFlows, "PendingFlows": vs.PendingFlows})
	}
	vs.ServiceLock.Unlock()
	vs.WriteToDb(cntx)

	vs.ServiceLock.RLock()
	if len(vs.AssociatedFlows) == 0 && !vs.DsHSIAFlowsApplied {
		vs.ServiceLock.RUnlock()
		device := GetApplication().GetDevice(vs.Device)
		if device == nil {
			logger.Errorw(ctx, "Error Getting Device. Dropping DEL_HSIA Success indication to NB", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return
		} else if device.State != controller.DeviceStateUP {
			logger.Warnw(ctx, "Device state Down. Dropping DEL_HSIA Success indication to NB", log.Fields{"Service": vs.Name, "Port": vs.Port})
			return
		}

		if vs.UpdateInProgress {
			vs.updateVnetProfile(cntx, vs.Device)
			// Not sending DEL_HSIA Indication since it wil be generated internally by SubMgr
			return
		}
		logger.Infow(ctx, "All Flows removed for Service. Triggering Service De-activation Success indication to NB", log.Fields{"Service": vs.Name, "DeleteFlag": vs.DeleteInProgress})
		// Get the service from application before proceeding to delete, as the service might have been activated
		// by the time the flow removal response is received from SB
		svc := GetApplication().GetService(vs.Name)
		if svc != nil {
			svc.CheckAndDeleteService(cntx)
		}

		return
	}
	vs.ServiceLock.RUnlock()
	logger.Debugw(ctx, "Processed Service Flow Remove Success Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "Associated Flows": vs.AssociatedFlows, "DsFlowsApplied": vs.DsHSIAFlowsApplied})
}

// FlowRemoveFailure - Called when corresponding service flow installation is failed
// Trigger service failure indication to NB
func (vs *VoltService) FlowRemoveFailure(cntx context.Context, cookie string, errorCode uint32, errReason string) {
	vs.ServiceLock.Lock()
	logger.Debugw(ctx, "Processing Service Flow Remove Failure Indication", log.Fields{"Cookie": cookie, "Service": vs.Name, "Associated Flows": vs.AssociatedFlows, "DsFlowsApplied": vs.DsHSIAFlowsApplied})

	if _, ok := vs.AssociatedFlows[cookie]; !ok {
		logger.Warnw(ctx, "Flow Failure for unknown Cookie", log.Fields{"Service": vs.Name, "Cookie": cookie})
		vs.ServiceLock.Unlock()
		return
	}
	if vs.DeleteInProgress {
		delete(vs.AssociatedFlows, cookie)
	}
	vs.ServiceLock.Unlock()
	logger.Debugw(ctx, "Service Flow Remove Failure Notification", log.Fields{"uniPort": vs.Port, "Cookie": cookie, "Service": vs.Name, "ErrorCode": errorCode, "ErrorReason": errReason})

	vs.triggerServiceFailureInd(errorCode, errReason)
	// Get the service from application before proceeding to delete, as the service might have been activated
	// by the time the flow removal response is received from SB
	svc := GetApplication().GetService(vs.Name)
	if svc != nil {
		svc.CheckAndDeleteService(cntx)
	}
}

func (vs *VoltService) triggerServiceFailureInd(errorCode uint32, errReason string) {
	logger.Debugw(ctx, "Trigger Service Failure Ind", log.Fields{"Service": vs.Name, "Port": vs.Port})
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
func (va *VoltApplication) RestoreSvcsFromDb(cntx context.Context) {
	// VNETS must be learnt first
	logger.Debug(ctx, "Restore Svcs From Db")
	vss, _ := db.GetServices(cntx)
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
		if err := va.AddService(cntx, vvs.VoltServiceCfg, &vvs.VoltServiceOper); err != nil {
			logger.Warnw(ctx, "Add New Service Failed", log.Fields{"Service": vvs.Name, "Error": err})
		}

		if vvs.VoltServiceOper.DeactivateInProgress {
			va.ServicesToDeactivate.Store(vvs.VoltServiceCfg.Name, true)
			logger.Warnw(ctx, "Service (restored) to be deactivated", log.Fields{"Service": vvs.Name})
		}

		if vvs.VoltServiceOper.DeleteInProgress {
			va.ServicesToDelete.Store(vvs.VoltServiceCfg.Name, true)
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
	logger.Debugw(ctx, "Get Service Name From Cookie", log.Fields{"Cookie": cookie, "PortName": portName, "Pbit": pbit, "Device": device, "TableMetadata": tableMetadata})
	var vlan uint64
	vlanControl := (tableMetadata >> 32) & 0xF

	if vlanControl == uint64(OLTCVlanOLTSVlan) {
		// Fetching UniVlan for vlanControl OLTCVLANOLTSVLAN
		vlan = (tableMetadata >> 16) & 0xFFFF
	} else {
		// Fetching CVlan for other vlanControl
		vlan = cookie >> 52
	}
	logger.Debugw(ctx, "Configured Params", log.Fields{"VlanControl": vlanControl, "vlan": vlan})
	var vlans []of.VlanType
	vlans = append(vlans, of.VlanType(vlan))
	service := GetApplication().GetServiceFromCvlan(device, portName, vlans, uint8(pbit))
	if nil != service {
		logger.Infow(ctx, "Service Found for", log.Fields{"serviceName": service.Name, "portName": portName, "ctag": vlan})
	} else {
		logger.Warnw(ctx, "No Service for", log.Fields{"portName": portName, "ctag": vlan, "Pbit": pbit, "device": device, "VlanControl": vlanControl})
	}
	return service
}

// MigrateServicesReqStatus - update vnet request status
type MigrateServicesReqStatus string

const (
	// MigrateSrvsReqInit constant
	MigrateSrvsReqInit MigrateServicesReqStatus = "Init"
	// MigrateSrvsReqDeactTriggered constant
	MigrateSrvsReqDeactTriggered MigrateServicesReqStatus = "Profiles Deactivated"
	// MigrateSrvsReqCompleted constant
	MigrateSrvsReqCompleted MigrateServicesReqStatus = "Update Complete"
)

// MigrateServicesRequest - update vnet request params
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

// GetMsrKey - generates migrate service request key
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

// WriteToDB - writes the udpate vnet request details ot DB
func (msr *MigrateServicesRequest) WriteToDB(cntx context.Context) {
	logger.Debugw(ctx, "Adding Migrate Service Request to DB", log.Fields{"OldVnet": msr.OldVnetID, "NewVnet": msr.NewVnetID, "Device": msr.DeviceID, "RequestID": msr.ID, "ServiceCount": len(msr.ServicesList)})
	if b, err := json.Marshal(msr); err == nil {
		if err = db.PutMigrateServicesReq(cntx, msr.DeviceID, msr.GetMsrKey(), string(b)); err != nil {
			logger.Warnw(ctx, "PutMigrateServicesReq Failed", log.Fields{"OldVnet": msr.OldVnetID, "NewVnet": msr.NewVnetID,
				"Device": msr.DeviceID, "Error": err})
		}
	}
}

// MigrateServices - updated vnet profile for services
func (va *VoltApplication) MigrateServices(cntx context.Context, serialNum string, reqID string, oldVnetID, newVnetID string, serviceList []string) error {
	logger.Debugw(ctx, "Migrate Serviec Request Received", log.Fields{"SerialNum": serialNum, "RequestID": reqID, "OldVnet": oldVnetID, "NewVnet": newVnetID, "ServiceList": serviceList})
	if _, ok := va.VnetsByName.Load(oldVnetID); !ok {
		return errors.New("old vnet id not found")
	}
	if _, ok := va.VnetsByName.Load(newVnetID); !ok {
		return errors.New("new vnet id not found")
	}

	d, _ := va.GetDeviceBySerialNo(serialNum)
	if d == nil {
		logger.Errorw(ctx, "Error Getting Device", log.Fields{"SerialNum": serialNum})
		return errorCodes.ErrDeviceNotFound
	}

	serviceMap := make(map[string]bool)

	for _, service := range serviceList {
		serviceMap[service] = false
	}
	msr := newMigrateServicesRequest(reqID, oldVnetID, newVnetID, serviceMap, d.Name)
	msr.WriteToDB(cntx)

	d.AddMigratingServices(msr)
	go msr.ProcessMigrateServicesProfRequest(cntx)
	return nil
}

// ProcessMigrateServicesProfRequest - collects all associated profiles
func (msr *MigrateServicesRequest) ProcessMigrateServicesProfRequest(cntx context.Context) {
	logger.Debug(ctx, "Process Migrate Services Prof Request")
	va := GetApplication()
	for srv, processed := range msr.ServicesList {
		// Indicates new service is already created and only deletion of old one is pending
		if processed {
			va.DelService(cntx, srv, true, nil, true)
			msr.serviceMigrated(cntx, srv)
			continue
		}

		logger.Infow(ctx, "Migrate Service Triggering", log.Fields{"Service": srv})
		if vsIntf, ok := va.ServiceByName.Load(srv); ok {
			vs := vsIntf.(*VoltService)
			vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan)
			if vpv == nil {
				logger.Warnw(ctx, "Vpv Not found for Service", log.Fields{"vs": vs.Name, "port": vs.Port, "Vnet": vs.VnetID})
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

			// vpv flows will be removed when last service is removed from it and
			// new vpv flows will be installed when new service is added
			if vs.UsHSIAFlowsApplied {
				vpv.DelTrapFlows(cntx)
				vs.DelHsiaFlows(cntx)
				logger.Infow(ctx, "Remove Service Flows Triggered", log.Fields{"Service": srv, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied})
			} else {
				vs.updateVnetProfile(cntx, msr.DeviceID)
			}
		} else {
			logger.Warnw(ctx, "Migrate Service Failed: Service Not Found", log.Fields{"Service": srv, "Vnet": msr.OldVnetID})
		}
	}
}

// AddMigratingServices - store msr info to device obj
func (d *VoltDevice) AddMigratingServices(msr *MigrateServicesRequest) {
	logger.Infow(ctx, "Add Migrating Services", log.Fields{"Vnet": msr.OldVnetID})
	var msrMap *util.ConcurrentMap
	if msrMapIntf, ok := d.MigratingServices.Get(msr.OldVnetID); !ok {
		msrMap = util.NewConcurrentMap()
	} else {
		msrMap = msrMapIntf.(*util.ConcurrentMap)
	}

	msrMap.Set(msr.ID, msr)
	logger.Debugw(ctx, "1: MsrListLen", log.Fields{"Len": msrMap.Length(), "Vnet": msr.OldVnetID})

	d.MigratingServices.Set(msr.OldVnetID, msrMap)
	logger.Debugw(ctx, "1: DeviceMsr", log.Fields{"Device": d.Name, "Vnet": msr.OldVnetID, "Len": d.MigratingServices.Length()})
}

// getMigrateServicesRequest - fetches msr info from device
func (va *VoltApplication) getMigrateServicesRequest(deviceID string, oldVnetID string, requestID string) *MigrateServicesRequest {
	logger.Debugw(ctx, "Get Migrate Services Request", log.Fields{"DeviceID": deviceID, "OldVnetID": oldVnetID, "RequestID": requestID})
	if vd := va.GetDevice(deviceID); vd != nil {
		logger.Debugw(ctx, "2: DeviceMsr", log.Fields{"Device": deviceID, "Vnet": oldVnetID, "Len": vd.MigratingServices.Length()})
		if msrListIntf, ok := vd.MigratingServices.Get(oldVnetID); ok {
			msrList := msrListIntf.(*util.ConcurrentMap)
			logger.Debugw(ctx, "2: MsrListLen", log.Fields{"Len": msrList.Length(), "Vnet": oldVnetID})
			if msrObj, ok := msrList.Get(requestID); ok {
				return msrObj.(*MigrateServicesRequest)
			}
		}
	}
	logger.Warnw(ctx, "Device Not Found", log.Fields{"DeviceID": deviceID})
	return nil
}

// updateMigrateServicesRequest - Updates the device with updated msr
func (va *VoltApplication) updateMigrateServicesRequest(deviceID string, oldVnetID string, requestID string, msr *MigrateServicesRequest) {
	logger.Debugw(ctx, "Update Migrate Services Request", log.Fields{"DeviceID": deviceID, "OldVnetID": oldVnetID, "RequestID": requestID})
	if vd := va.GetDevice(deviceID); vd != nil {
		if msrList, ok := vd.MigratingServices.Get(oldVnetID); ok {
			if _, ok := msrList.(*util.ConcurrentMap).Get(requestID); ok {
				msrList.(*util.ConcurrentMap).Set(requestID, msr)
			}
		}
	}
}

// updateVnetProfile - Called on flow process completion
// Removes old service and creates new VPV & service with updated vnet profile
func (vs *VoltService) updateVnetProfile(cntx context.Context, deviceID string) {
	logger.Infow(ctx, "Update Vnet Profile Triggering", log.Fields{"Service": vs.Name, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied})

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
	nvs.DeactivateInProgress = vs.DeactivateInProgress
	nvs.ForceDelete = vs.ForceDelete
	nvs.BwAvailInfo = vs.BwAvailInfo
	nvs.UpdateInProgress = vs.UpdateInProgress

	if nvs.DeleteInProgress {
		logger.Warnw(ctx, "Skipping Service Migration. Service Delete in Progress", log.Fields{"Device": deviceID, "Service": vs.Name, "Vnet": vs.VnetID})
		return
	}

	metadata := vs.Metadata.(*MigrateServiceMetadata)
	oldVnetID := vs.VnetID
	oldSrvName := vs.Name

	if metadata == nil || metadata.NewVnetID == "" {
		logger.Warnw(ctx, "Migrate Service Metadata not found. Dropping vnet profile update request", log.Fields{"Service": vs.Name, "Vnet": vs.VnetID})
		return
	}

	nvs.VnetID = metadata.NewVnetID
	id := metadata.RequestID

	// First add the new service and then only delete the old service
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

	// TODO:Nav Pass a copy, not the pointer
	logger.Debugw(ctx, "Add New Service Triggering", log.Fields{"Service": nvs.Name, "US": nvs.UsHSIAFlowsApplied, "DS": nvs.DsHSIAFlowsApplied, "DelFlag": nvs.DeleteInProgress})
	if err := va.AddService(cntx, nvs.VoltServiceCfg, &nvs.VoltServiceOper); err != nil {
		logger.Warnw(ctx, "Add New Service Failed", log.Fields{"Service": nvs.Name, "Error": err})
	}
	logger.Infow(ctx, "Add New Service Triggered", log.Fields{"Service": nvs.Name, "US": nvs.UsHSIAFlowsApplied, "DS": nvs.DsHSIAFlowsApplied, "DelFlag": nvs.DeleteInProgress})

	msr.ServicesList[oldSrvName] = true
	va.updateMigrateServicesRequest(deviceID, oldVnetID, id, msr)
	msr.WriteToDB(cntx)

	logger.Debugw(ctx, "Del Old Service Triggering", log.Fields{"Service": oldSrvName, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied, "DelFlag": vs.DeleteInProgress})
	va.DelService(cntx, oldSrvName, true, nil, true)
	logger.Debugw(ctx, "Del Old Service Triggered", log.Fields{"Service": oldSrvName, "US": vs.UsHSIAFlowsApplied, "DS": vs.DsHSIAFlowsApplied, "DelFlag": vs.DeleteInProgress})
	msr.serviceMigrated(cntx, oldSrvName)
}

// serviceMigrated - called on successful service updation
// Removes the service entry from servicelist and deletes the request on process completion
func (msr *MigrateServicesRequest) serviceMigrated(cntx context.Context, serviceName string) {
	logger.Infow(ctx, "Service Migrated", log.Fields{"ServiceName": serviceName})
	msr.MigrateServicesLock.Lock()
	defer msr.MigrateServicesLock.Unlock()

	delete(msr.ServicesList, serviceName)

	if len(msr.ServicesList) == 0 {
		_ = db.DelMigrateServicesReq(cntx, msr.DeviceID, msr.GetMsrKey())
		return
	}
	msr.WriteToDB(cntx)
	// TODO:Nav - Need for any Response to SubMgr?
}

// TriggerPendingMigrateServicesReq - trigger pending service request
func (va *VoltApplication) TriggerPendingMigrateServicesReq(cntx context.Context, device string) {
	va.FetchAndProcessAllMigrateServicesReq(cntx, device, storeAndProcessMigrateSrvRequest)
}

// FetchAndProcessAllMigrateServicesReq - fetch all pending migrate services req from DB and process based on provided func
func (va *VoltApplication) FetchAndProcessAllMigrateServicesReq(cntx context.Context, device string, msrAction func(context.Context, *MigrateServicesRequest)) {
	logger.Infow(ctx, "Fetch all pending migrate services req from DB and process based on provided func", log.Fields{"Device": device})
	msrList, _ := db.GetAllMigrateServicesReq(cntx, device)
	for _, msr := range msrList {
		b, ok := msr.Value.([]byte)
		if !ok {
			logger.Warn(ctx, "The value type is not []byte")
			continue
		}
		msr := va.createMigrateServicesFromString(b)
		msrAction(cntx, msr)
		logger.Debugw(ctx, "Triggering Pending Migrate Services Req", log.Fields{"OldVnet": msr.OldVnetID, "NewVnet": msr.NewVnetID, "Device": device, "PendingProfiles": len(msr.ServicesList)})
	}
}

// createMigrateServicesFromString to create Service from string
func (va *VoltApplication) createMigrateServicesFromString(b []byte) *MigrateServicesRequest {
	logger.Info(ctx, "Create Migrate Services From String")
	var msr MigrateServicesRequest
	if err := json.Unmarshal(b, &msr); err == nil {
		logger.Debugw(ctx, "Adding Migrate Services Request From Db", log.Fields{"Vlan": msr.OldVnetID})
	} else {
		logger.Warn(ctx, "Unmarshal failed")
	}
	return &msr
}

// storeAndProcessMigrateSrvRequest - stores the msr info in device obj and triggers req
func storeAndProcessMigrateSrvRequest(cntx context.Context, msr *MigrateServicesRequest) {
	logger.Infow(ctx, "Store And Process Migrate Srv Request", log.Fields{"MsrID": msr.DeviceID})
	d := GetApplication().GetDevice(msr.DeviceID)
	d.AddMigratingServices(msr)
	msr.ProcessMigrateServicesProfRequest(cntx)
}

// forceUpdateAllServices - force udpate services with new vnet profile
func forceUpdateAllServices(cntx context.Context, msr *MigrateServicesRequest) {
	logger.Infow(ctx, "Force udpate services with new vnet profile", log.Fields{"MsrID": msr.NewVnetID})
	for srv := range msr.ServicesList {
		if vsIntf, ok := GetApplication().ServiceByName.Load(srv); ok {
			vsIntf.(*VoltService).updateVnetProfile(cntx, msr.DeviceID)
		}
	}
	_ = db.DelMigrateServicesReq(cntx, msr.DeviceID, msr.GetMsrKey())
}

// nolint: gocyclo
// DeepEqualServicecfg - checks if the given service cfgs are same
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
	if nvs.IsOption82Enabled != evs.IsOption82Enabled {
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

// TriggerAssociatedFlowDelete - re-trigger service flow delete for pending delete flows
func (vs *VoltService) TriggerAssociatedFlowDelete(cntx context.Context) bool {
	// Clear the Flows flag if already set
	// This case happens only in case of some race condition
	logger.Infow(ctx, "Trigger Associated Flow Delete", log.Fields{"Device": vs.Device, "Service": vs.Name})
	if vs.UsHSIAFlowsApplied {
		if err := vs.DelUsHsiaFlows(cntx, false); err != nil {
			logger.Warnw(ctx, "DelUsHsiaFlows Failed", log.Fields{"Device": vs.Device, "Service": vs.Name, "Error": err})
		}
	}

	if vs.DsHSIAFlowsApplied {
		if err := vs.DelDsHsiaFlows(cntx, false); err != nil {
			logger.Warnw(ctx, "DelDsHsiaFlows Failed", log.Fields{"Device": vs.Device, "Service": vs.Name, "Error": err})
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

	// Trigger Flow Delete
	for _, cookie := range cookieList {
		if vd := GetApplication().GetDevice(vs.Device); vd != nil {
			flow := &of.VoltFlow{}
			flow.SubFlows = make(map[uint64]*of.VoltSubFlow)
			subFlow := of.NewVoltSubFlow()
			subFlow.Cookie = cookie
			flow.SubFlows[cookie] = subFlow
			logger.Infow(ctx, "Retriggering Service Delete Flow", log.Fields{"Device": vs.Device, "Service": vs.Name, "Cookie": cookie})
			if err := vs.DelFlows(cntx, vd, flow, false); err != nil {
				logger.Warnw(ctx, "DelFlows Failed", log.Fields{"Device": vs.Device, "Service": vs.Name, "Cookie": cookie, "Error": err})
			}
		}
	}
	return true
}

// triggerServiceInProgressInd - Indication is generated when Service is not provisioned after add serviec req from NB
func (vs *VoltService) triggerServiceInProgressInd() {
}

// JSONMarshal wrapper function for json Marshal VoltService
func (vs *VoltService) JSONMarshal() ([]byte, error) {
	return json.Marshal(VoltService{
		VoltServiceCfg: vs.VoltServiceCfg,
		VoltServiceOper: VoltServiceOper{
			Device:               vs.VoltServiceOper.Device,
			Ipv4Addr:             vs.VoltServiceOper.Ipv4Addr,
			Ipv6Addr:             vs.VoltServiceOper.Ipv6Addr,
			UsMeterID:            vs.VoltServiceOper.UsMeterID,
			DsMeterID:            vs.VoltServiceOper.DsMeterID,
			AggDsMeterID:         vs.VoltServiceOper.AggDsMeterID,
			UsHSIAFlowsApplied:   vs.VoltServiceOper.UsHSIAFlowsApplied,
			DsHSIAFlowsApplied:   vs.VoltServiceOper.DsHSIAFlowsApplied,
			UsDhcpFlowsApplied:   vs.VoltServiceOper.UsDhcpFlowsApplied,
			DsDhcpFlowsApplied:   vs.VoltServiceOper.DsDhcpFlowsApplied,
			IgmpFlowsApplied:     vs.VoltServiceOper.IgmpFlowsApplied,
			Icmpv6FlowsApplied:   vs.VoltServiceOper.Icmpv6FlowsApplied,
			PendingFlows:         vs.VoltServiceOper.PendingFlows,
			AssociatedFlows:      vs.VoltServiceOper.AssociatedFlows,
			DeleteInProgress:     vs.VoltServiceOper.DeleteInProgress,
			DeactivateInProgress: vs.VoltServiceOper.DeactivateInProgress,
			ForceDelete:          vs.VoltServiceOper.ForceDelete,
			BwAvailInfo:          vs.VoltServiceOper.BwAvailInfo,
			UpdateInProgress:     vs.VoltServiceOper.UpdateInProgress,
			Metadata:             vs.VoltServiceOper.Metadata,
		},
	})
}

// GetProgrammedSubscribers to get list of programmed subscribers
func (va *VoltApplication) GetProgrammedSubscribers(cntx context.Context, deviceID, portNo string) ([]*VoltService, error) {
	var svcList []*VoltService
	logger.Infow(ctx, "GetProgrammedSubscribers Request ", log.Fields{"Device": deviceID, "Port": portNo})
	va.ServiceByName.Range(func(key, value interface{}) bool {
		vs := value.(*VoltService)
		if len(deviceID) > 0 {
			if len(portNo) > 0 {
				if deviceID == vs.Device && portNo == vs.Port {
					svcList = append(svcList, vs)
				}
			} else {
				if deviceID == vs.Device {
					svcList = append(svcList, vs)
				}
			}
		} else {
			svcList = append(svcList, vs)
		}
		return true
	})
	return svcList, nil
}

type FlowProvisionStatus struct {
	FlowProvisionStatus string
}

// GetFlowProvisionStatus to get status of the subscriber and flow provisioned in controller
func (va *VoltApplication) GetFlowProvisionStatus(portNo string) FlowProvisionStatus {
	logger.Infow(ctx, "GetFlowProvisionStatus Request ", log.Fields{"Port": portNo})
	flowProvisionStatus := FlowProvisionStatus{}
	flowProvisionStatus.FlowProvisionStatus = SUBSCRIBER_NOT_IN_CONTROLLER
	va.ServiceByName.Range(func(key, value interface{}) bool {
		vs := value.(*VoltService)
		logger.Debugw(ctx, "Volt Service ", log.Fields{"VS": vs})
		if portNo == vs.Port {
			if vs.DsHSIAFlowsApplied && vs.UsHSIAFlowsApplied && vs.LenOfPendingFlows() == 0 {
				flowProvisionStatus.FlowProvisionStatus = ALL_FLOWS_PROVISIONED
				return false
			} else if !vs.IsActivated {
				flowProvisionStatus.FlowProvisionStatus = SUBSCRIBER_DISABLED_IN_CONTROLLER
				return false
			} else if !vs.DsHSIAFlowsApplied && !vs.UsHSIAFlowsApplied {
				flowProvisionStatus.FlowProvisionStatus = NO_FLOWS_PROVISIONED
				return false
			} else if vs.DsHSIAFlowsApplied && vs.UsHSIAFlowsApplied && vs.LenOfPendingFlows() > 0 {
				flowProvisionStatus.FlowProvisionStatus = FLOWS_PROVISIONED_PARTIALLY
				return false
			}
		}
		return true
	})
	return flowProvisionStatus
}

func (vs *VoltService) LenOfPendingFlows() int {
	vs.ServiceLock.RLock()
	lth := len(vs.PendingFlows)
	vs.ServiceLock.RUnlock()
	return lth
}

// ActivateService to activate pre-provisioned service
func (va *VoltApplication) ActivateService(cntx context.Context, deviceID, portNo string, sVlan, cVlan of.VlanType, tpID uint16) error {
	logger.Infow(ctx, "Service Activate Request ", log.Fields{"Device": deviceID, "Port": portNo, "Svaln": sVlan, "Cvlan": cVlan, "TpID": tpID})
	device, err := va.GetDeviceFromPort(portNo)
	if err != nil {
		// Lets activate the service even though port was not found. We will push the flows once the port is added by voltha
		logger.Warnw(ctx, "Couldn't get device for port, continuing with service activation", log.Fields{"Reason": err.Error(), "Port": portNo})
	}
	// If device id is not provided check only port number
	if device != nil {
		if deviceID == DeviceAny {
			deviceID = device.Name
		} else if deviceID != device.Name {
			err := errorCodes.ErrDeviceNotFound
			return fmt.Errorf("wrong device id %s : %w", deviceID, err)
		}
	}
	va.ServiceByName.Range(func(key, value interface{}) bool {
		vs := value.(*VoltService)
		// If svlan if provided, then the tags and tpID of service has to be matching
		if sVlan != of.VlanNone && (sVlan != vs.SVlan || cVlan != vs.CVlan || tpID != vs.TechProfileID) {
			logger.Warnw(ctx, "Service Activate Request Does not match", log.Fields{"Device": deviceID, "voltService": vs})
			return true
		}
		if portNo == vs.Port && !vs.IsActivated {
			// Mark the service as activated, so that we can push the flows later when the port is added by voltha
			logger.Debugw(ctx, "Service Activate", log.Fields{"Name": vs.Name})
			vs.IsActivated = true
			va.ServiceByName.Store(vs.Name, vs)
			vs.WriteToDb(cntx)

			// Push the flows only if the port is already added and we have a valid device
			if device != nil {
				p := device.GetPort(vs.Port)
				if p == nil {
					logger.Warnw(ctx, "Wrong device or port", log.Fields{"Device": deviceID, "Port": portNo})
					return true
				}
				// If port is already up send indication to vpv
				if p.State == PortStateUp {
					if vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan); vpv != nil {
						// PortUp call initiates flow addition
						vpv.PortUpInd(cntx, device, portNo)
					} else {
						logger.Warnw(ctx, "VPV does not exists!!!", log.Fields{"Device": deviceID, "port": portNo, "SvcName": vs.Name})
					}
				}
			}
		}
		return true
	})
	return nil
}

func (vs *VoltService) SetSvcDeactivationFlags(deactivateRsn SvcDeactivateReason) {
	vs.DeactivateInProgress = true
	vs.IsActivated = false
	vs.ServiceDeactivateReason = deactivateRsn
}

// DeactivateService to activate pre-provisioned service
func (va *VoltApplication) DeactivateService(cntx context.Context, deviceID, portNo string, sVlan, cVlan of.VlanType, tpID uint16) error {
	logger.Debugw(ctx, "Service Deactivate Request ", log.Fields{"Device": deviceID, "Port": portNo, "Svaln": sVlan, "Cvlan": cVlan, "TpID": tpID})

	va.ServiceByName.Range(func(key, value interface{}) bool {
		vs := value.(*VoltService)
		// If svlan if provided, then the tags and tpID of service has to be matching
		if sVlan != of.VlanNone && (sVlan != vs.SVlan || cVlan != vs.CVlan || tpID != vs.TechProfileID) {
			logger.Warnw(ctx, "condition not matched", log.Fields{"Device": deviceID, "Port": portNo, "sVlan": sVlan, "cVlan": cVlan, "tpID": tpID})
			return true
		}
		if portNo == vs.Port && vs.IsActivated {
			vs.SetSvcDeactivationFlags(SvcDeacRsn_NB)
			va.ServiceByName.Store(vs.Name, vs)
			vs.WriteToDb(cntx)
			device, err := va.GetDeviceFromPort(portNo)
			if err != nil {
				// Even if the port/device does not exists at this point in time, the deactivate request is succss.
				// So no error is returned
				logger.Warnw(ctx, "Error Getting Device", log.Fields{"Reason": err.Error(), "Port": portNo})
				return true
			}
			p := device.GetPort(vs.Port)
			if p != nil && (p.State == PortStateUp || !va.OltFlowServiceConfig.RemoveFlowsOnDisable) {
				if vpv := va.GetVnetByPort(vs.Port, vs.SVlan, vs.CVlan, vs.UniVlan); vpv != nil {
					// Port down call internally deletes all the flows
					vpv.PortDownInd(cntx, deviceID, portNo, true, false)
					if vpv.IgmpEnabled {
						va.ReceiverDownInd(cntx, deviceID, portNo)
					}
				} else {
					logger.Warnw(ctx, "VPV does not exists!!!", log.Fields{"Device": deviceID, "port": portNo, "SvcName": vs.Name})
				}
			}
			vs.DeactivateInProgress = false
			va.ServiceByName.Store(vs.Name, vs)
			vs.WriteToDb(cntx)
		}
		return true
	})
	return nil
}

// GetServicePbit to get first set bit in the pbit map
// returns -1 : If configured to match on all pbits
// returns 8  : If no pbits are configured
// returns first pbit if specific pbit is configured
func (vs *VoltService) GetServicePbit() int {
	if vs.IsPbitExist(of.PbitMatchAll) {
		return -1
	}
	for pbit := 0; pbit < int(of.PbitMatchNone); pbit++ {
		if vs.IsPbitExist(of.PbitType(pbit)) {
			return pbit
		}
	}
	return int(of.PbitMatchNone)
}
