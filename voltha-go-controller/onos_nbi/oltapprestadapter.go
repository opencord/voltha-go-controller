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

package onosnbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	app "voltha-go-controller/internal/pkg/application"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

const (
	PORTNAME  string = "portName"
	DEVICE    string = "device"
	OLTSERIAL string = "oltSerial"
	DPUSERIAL string = "dpuSerial"
	STAG      string = "sTag"
	CTAG      string = "cTag"
	TPID      string = "tpId"
)

// FlowHandle struct to handle flow related REST calls
type SubscriberInfo struct {
	Location string            `json:"location"`
	TagInfo  UniTagInformation `json:"tagInfo"`
}

// UniTagInformation - Service information
type UniTagInformation struct {
	UpstreamBandwidthProfile      string `json:"upstreamBandwidthProfile"`
	DownstreamBandwidthProfile    string `json:"downstreamBandwidthProfile"`
	UpstreamOltBandwidthProfile   string `json:"upstreamOltBandwidthProfile"`
	DownstreamOltBandwidthProfile string `json:"downstreamOltBandwidthProfile"`
	ServiceName                   string `json:"serviceName"`
	ConfiguredMacAddress          string `json:"configuredMacAddress"`
	UniTagMatch                   int    `json:"uniTagMatch"`
	PonCTag                       int    `json:"ponCTag"`
	PonSTag                       int    `json:"ponSTag"`
	UsPonCTagPriority             int    `json:"usPonCTagPriority"`
	UsPonSTagPriority             int    `json:"usPonSTagPriority"`
	DsPonCTagPriority             int    `json:"dsPonCTagPriority"`
	DsPonSTagPriority             int    `json:"dsPonSTagPriority"`
	TechnologyProfileID           int    `json:"technologyProfileId"`
	IsDhcpRequired                bool   `json:"isDhcpRequired"`
	IsIgmpRequired                bool   `json:"isIgmpRequired"`
	IsPppoeRequired               bool   `json:"isPppoeRequired"`
	EnableMacLearning             bool   `json:"enableMacLearning"`
}

type ServiceConfigInfo struct {
	OnuSerial     string `json:"onuSerial"`
	OltSerial     string `json:"oltSerial"`
	SubType       string `json:"subType"`
	State         string `json:"state"`
	SubSTag       string `json:"subSTag"`
	SubCTag       string `json:"subCTag"`
	IngressPBit   string `json:"ingressPBit"`
	EgressPBit    string `json:"egressPBit"`
	OltUplinkPort string `json:"oltUplinkPort"`
}

type ServiceAdapter struct {
}

func (sa *ServiceConfigInfo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		sa.GetServiceConfiguration(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (sa *ServiceAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		sa.ActivateService(context.Background(), w, r)
	case cDelete:
		sa.DeactivateService(context.Background(), w, r)
	case cGet:
		sa.GetProgrammedSubscribers(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (sa *ServiceAdapter) ServeHTTPWithPortName(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		sa.ActivateServiceWithPortName(context.Background(), w, r)
	case cDelete:
		sa.DeactivateServiceWithPortName(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// ActivateService godoc
// @Summary      Activate a service
// @Description  Activate the service(s) on the given device and port.
// @Tags         Services
// @Produce      json
// @Param        device  path  string  true  "Device identifier"
// @Param        port    path  string  true  "Port identifier"
// @Success      200  "Service activated"
// @Router       /services/{device}/{port} [post]
func (sa *ServiceAdapter) ActivateService(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars[DEVICE]
	portNo := vars["port"]

	logger.Infow(ctx, "Received ActivateService request specific for portNo and deviceID", log.Fields{"portNo": portNo, "deviceID": deviceID})

	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"portNo": portNo, "deviceID": deviceID, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	var devIntr app.VoltDevInterface

	if len(deviceID) > 0 && len(portNo) > 0 {
		port, err := strconv.Atoi(portNo)
		if err != nil {
			logger.Errorw(ctx, "Wrong port number value", log.Fields{"portNo": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		device := voltAppIntr.GetDevice(deviceID)
		if device == nil {
			logger.Errorw(ctx, "Device does not exists", log.Fields{"deviceID": deviceID})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		devIntr = device
		portName := devIntr.GetPortNameFromPortID(uint32(port))
		if len(portName) == 0 {
			logger.Errorw(ctx, "Port does not exists", log.Fields{"portNo": portNo})
			err := errorCodes.ErrPortNotFound
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := voltAppIntr.ActivateService(cntx, deviceID, portName, of.VlanNone, of.VlanNone, 0); err != nil {
			logger.Errorw(ctx, "ActivateService Failed", log.Fields{"deviceID": deviceID, "Port": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

// DeactivateService godoc
// @Summary      Deactivate a service
// @Description  Deactivate the service(s) on the given device and port.
// @Tags         Services
// @Produce      json
// @Param        device  path  string  true  "Device identifier"
// @Param        port    path  string  true  "Port identifier"
// @Success      200  "Service deactivated"
// @Router       /services/{device}/{port} [delete]
func (sa *ServiceAdapter) DeactivateService(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars[DEVICE]
	portNo := vars["port"]
	logger.Infow(ctx, "Received DeactivateService request specific for portNo and deviceID", log.Fields{"portNo": portNo, "deviceID": deviceID})

	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"portNo": portNo, "deviceID": deviceID, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	var devIntr app.VoltDevInterface
	if len(deviceID) > 0 && len(portNo) > 0 {
		port, err := strconv.Atoi(portNo)
		if err != nil {
			logger.Errorw(ctx, "Wrong port number value", log.Fields{"portNo": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		device := voltAppIntr.GetDevice(deviceID)
		if device == nil {
			logger.Errorw(ctx, "Device does not exists", log.Fields{"deviceID": deviceID})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		devIntr = device
		portName := devIntr.GetPortNameFromPortID(uint32(port))
		if len(portName) == 0 {
			logger.Errorw(ctx, "Port does not exists", log.Fields{"portNo": portNo})
			err := errorCodes.ErrPortNotFound
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := voltAppIntr.DeactivateService(cntx, deviceID, portName, of.VlanNone, of.VlanNone, 0); err != nil {
			logger.Errorw(ctx, "DeactivateService Failed", log.Fields{"deviceID": deviceID, "Port": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

// ActivateServiceWithPortName godoc
// @Summary      Activate a service by port name
// @Description  Activate the service on the given access port, optionally scoped by S-Tag, C-Tag and technology profile id.
// @Tags         Services
// @Produce      json
// @Param        portName  path  string  true   "Access port name"
// @Param        sTag      path  string  true  "Service VLAN (S-Tag)"
// @Param        cTag      path  string  true  "Customer VLAN (C-Tag)"
// @Param        tpId      path  string  true  "Technology profile id"
// @Success      200  "Service activated"
// @Router       /services/{portName} [post]
// @Router       /services/{portName}/{sTag}/{cTag}/{tpId} [post]
func (sa *ServiceAdapter) ActivateServiceWithPortName(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	portNo := vars[PORTNAME]
	sTag := vars[STAG]
	cTag := vars[CTAG]
	tpID := vars[TPID]
	sVlan := of.VlanNone
	cVlan := of.VlanNone
	techProfile := uint16(0)
	logger.Infow(ctx, "Received ActivateService request specific for portNo, sTag, cTag and tpID", log.Fields{"Port": portNo, "STag": sTag, "CTag": cTag, "TPID": tpID})

	if len(sTag) > 0 {
		sv, err := strconv.Atoi(sTag)
		if err != nil {
			logger.Errorw(ctx, "Wrong vlan value", log.Fields{"sTag": sTag, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		sVlan = of.VlanType(sv)
	}
	if len(cTag) > 0 {
		cv, err := strconv.Atoi(cTag)
		if err != nil {
			logger.Errorw(ctx, "Wrong vlan value", log.Fields{"cTag": cTag, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		cVlan = of.VlanType(cv)
	}
	if len(tpID) > 0 {
		tp, err := strconv.Atoi(tpID)
		if err != nil {
			logger.Errorw(ctx, "Wrong tech profile value", log.Fields{"tpID": tpID, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		techProfile = uint16(tp)
	}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	if len(portNo) > 0 {
		if err := voltAppIntr.ActivateService(cntx, app.DeviceAny, portNo, sVlan, cVlan, techProfile); err != nil {
			logger.Errorw(ctx, "ActivateService Failed", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	logger.Debugw(ctx, "ActivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile})
}

// DeactivateServiceWithPortName godoc
// @Summary      Deactivate a service by port name
// @Description  Deactivate the service on the given access port, optionally scoped by S-Tag, C-Tag and technology profile id.
// @Tags         Services
// @Produce      json
// @Param        portName  path  string  true   "Access port name"
// @Param        sTag      path  string  false  "Service VLAN (S-Tag)"
// @Param        cTag      path  string  false  "Customer VLAN (C-Tag)"
// @Param        tpId      path  string  false  "Technology profile id"
// @Success      200  "Service deactivated"
// @Router       /services/{portName} [delete]
// @Router       /services/{portName}/{sTag}/{cTag}/{tpId} [delete]
func (sa *ServiceAdapter) DeactivateServiceWithPortName(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	portNo := vars[PORTNAME]
	sTag := vars[STAG]
	cTag := vars[CTAG]
	tpID := vars[TPID]
	sVlan := of.VlanNone
	cVlan := of.VlanNone
	techProfile := uint16(0)
	logger.Infow(ctx, "Received DeactivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sTag, "CVlan": cTag, "techProfile": tpID})

	if len(sTag) > 0 {
		sv, err := strconv.Atoi(sTag)
		if err != nil {
			logger.Errorw(ctx, "Wrong vlan value", log.Fields{"sTag": sTag, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		sVlan = of.VlanType(sv)
	}
	if len(cTag) > 0 {
		cv, err := strconv.Atoi(cTag)
		if err != nil {
			logger.Errorw(ctx, "Wrong vlan value", log.Fields{"cTag": cTag, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		cVlan = of.VlanType(cv)
	}
	if len(tpID) > 0 {
		tp, err := strconv.Atoi(tpID)
		if err != nil {
			logger.Errorw(ctx, "Wrong tech profile value", log.Fields{"tpID": tpID, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		techProfile = uint16(tp)
	}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	if len(portNo) > 0 {
		if err := voltAppIntr.DeactivateService(cntx, app.DeviceAny, portNo, sVlan, cVlan, techProfile); err != nil {
			logger.Errorw(ctx, "DeactivateService Failed", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	logger.Debugw(ctx, "DeactivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sTag, "CVlan": cTag, "techProfile": tpID})
}

// GetProgrammedSubscribers godoc
// @Summary      Get programmed subscribers
// @Description  Retrieve programmed subscribers, optionally filtered by device and port.
// @Tags         Subscribers
// @Produce      json
// @Param        device  path  string  true  "Device identifier"
// @Param        port    path  string  true  "Port identifier"
// @Success      200  {object}  onosnbi.SubscribersList
// @Failure      404  {string}  string  "Subscribers not found"
// @Router       /programmed-subscribers [get]
// @Router       /programmed-subscribers/{device}/{port} [get]
// @Router       /services/{device}/{port} [get]
func (sa *ServiceAdapter) GetProgrammedSubscribers(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars[DEVICE]
	portNo := vars["port"]
	logger.Infow(ctx, "Received Programmed Subscribers request specific for portNo and deviceID", log.Fields{"portNo": portNo, "deviceID": deviceID})

	subsbr := SubscribersList{}
	subsbr.Subscribers = []SubscriberInfo{}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	svcs, err := voltAppIntr.GetProgrammedSubscribers(cntx, deviceID, portNo)
	if err != nil {
		logger.Errorw(ctx, "Failed to get subscribers", log.Fields{"portNo": portNo, "deviceID": deviceID, "Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		return
	}
	subs := convertServiceToSubscriberInfo(svcs)
	subsbr.Subscribers = subs
	subsJSON, err := json.Marshal(subsbr)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling subscriber response", log.Fields{"Subsbr": subsbr, "portNo": portNo, "deviceID": deviceID, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(subsJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending subscriber response", log.Fields{"Subsbr": subsbr, "portNo": portNo, "deviceID": deviceID, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Programmed Subscribers request specific for portNo and deviceID", log.Fields{"Subsbr": subsbr, "portNo": portNo, "deviceID": deviceID})
}

func (sa *ServiceConfigInfo) GetServiceConfiguration(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	oltSerial := vars[OLTSERIAL]
	dpuSerial := vars[DPUSERIAL]
	logger.Infow(ctx, "Received Get Service Configuration request specific for OLT", log.Fields{"olt-serial": oltSerial})

	subsbr := ServiceConfigList{}
	subsbr.Subscribers = []ServiceConfigInfo{}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	svcs := voltAppIntr.GetAllSubscribersInfo(cntx, oltSerial, dpuSerial)
	if len(svcs) == 0 {
		logger.Errorw(ctx, "No subscribers found", log.Fields{"olt-serial": oltSerial})
		w.WriteHeader(http.StatusNotFound)
		return
	}
	subs := convertServiceToDeviceConfig(svcs, oltSerial)
	subsbr.Subscribers = subs
	subsJSON, err := json.Marshal(subsbr)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling subscriber response", log.Fields{"Subsbr": subsbr, "olt-serial": oltSerial, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(subsJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending subscriber response", log.Fields{"Subsbr": subsbr, "olt-serial": oltSerial, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Get Service Configuration request specific for OLT", log.Fields{"Subsbr": subsbr, "olt-serial": oltSerial})
}
