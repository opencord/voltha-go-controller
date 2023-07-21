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
	PORTNAME string = "portName"
	DEVICE   string = "device"
	STAG     string = "sTag"
	CTAG     string = "cTag"
	TPID     string = "tpId"
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

type ServiceAdapter struct {
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

	if len(deviceID) > 0 && len(portNo) > 0 {
		va := app.GetApplication()
		port, err := strconv.Atoi(portNo)
		if err != nil {
			logger.Errorw(ctx, "Wrong port number value", log.Fields{"portNo": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		device := va.GetDevice(deviceID)
		if device == nil {
			logger.Errorw(ctx, "Device does not exists", log.Fields{"deviceID": deviceID})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		portName := device.GetPortNameFromPortID(uint32(port))
		if len(portName) == 0 {
			logger.Errorw(ctx, "Port does not exists", log.Fields{"portNo": portNo})
			err := errorCodes.ErrPortNotFound
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := va.ActivateService(cntx, deviceID, portName, of.VlanNone, of.VlanNone, 0); err != nil {
			logger.Errorw(ctx, "ActivateService Failed", log.Fields{"deviceID": deviceID, "Port": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

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

	if len(deviceID) > 0 && len(portNo) > 0 {
		va := app.GetApplication()
		port, err := strconv.Atoi(portNo)
		if err != nil {
			logger.Errorw(ctx, "Wrong port number value", log.Fields{"portNo": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		device := va.GetDevice(deviceID)
		if device == nil {
			logger.Errorw(ctx, "Device does not exists", log.Fields{"deviceID": deviceID})
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		portName := device.GetPortNameFromPortID(uint32(port))
		if len(portName) == 0 {
			logger.Errorw(ctx, "Port does not exists", log.Fields{"portNo": portNo})
			err := errorCodes.ErrPortNotFound
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := va.DeactivateService(cntx, deviceID, portName, of.VlanNone, of.VlanNone, 0); err != nil {
			logger.Errorw(ctx, "DeactivateService Failed", log.Fields{"deviceID": deviceID, "Port": portNo, "Error": err})
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

func (sa *ServiceAdapter) ActivateServiceWithPortName(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	portNo := vars[PORTNAME]
	sTag := vars[STAG]
	cTag := vars[CTAG]
	tpID := vars[TPID]
	sVlan := of.VlanNone
	cVlan := of.VlanNone
	techProfile := uint16(0)
	logger.Infow(ctx, "Received ActivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile})

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

	if len(portNo) > 0 {
		if err := app.GetApplication().ActivateService(cntx, app.DeviceAny, portNo, sVlan, cVlan, techProfile); err != nil {
			logger.Errorw(ctx, "ActivateService Failed", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	logger.Debugw(ctx, "ActivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile})
}

func (sa *ServiceAdapter) DeactivateServiceWithPortName(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	portNo := vars[PORTNAME]
	sTag := vars[STAG]
	cTag := vars[CTAG]
	tpID := vars[TPID]
	sVlan := of.VlanNone
	cVlan := of.VlanNone
	techProfile := uint16(0)
	logger.Infow(ctx, "Received DeactivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile})

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

	if len(portNo) > 0 {
		if err := app.GetApplication().DeactivateService(cntx, app.DeviceAny, portNo, sVlan, cVlan, techProfile); err != nil {
			logger.Errorw(ctx, "DeactivateService Failed", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile, "Reason": err.Error()})
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	logger.Debugw(ctx, "DeactivateService request specific for portNo, sVlan, cVlan and techProfile", log.Fields{"Port": portNo, "SVlan": sVlan, "CVlan": cVlan, "techProfile": techProfile})
}

func (sa *ServiceAdapter) GetProgrammedSubscribers(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars[DEVICE]
	portNo := vars["port"]
	logger.Infow(ctx, "Received Programmed Subscribers request specific for portNo and deviceID", log.Fields{"portNo": portNo, "deviceID": deviceID})

	subsbr := SubscribersList{}
	subsbr.Subscribers = []SubscriberInfo{}
	svcs, err := app.GetApplication().GetProgrammedSubscribers(cntx, deviceID, portNo)
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
