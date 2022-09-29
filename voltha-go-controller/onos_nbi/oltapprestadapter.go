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

package onos_nbi

import (
        "bytes"
        "context"
        "encoding/json"
        "net/http"
	"strconv"

	"github.com/gorilla/mux"
	"voltha-go-controller/internal/pkg/of"
        app "voltha-go-controller/internal/pkg/application"
        "voltha-go-controller/log"
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
	Location string             `json:"location"`
	TagInfo  UniTagInformation  `json:"tagInfo"`
}

//UniTagInformation - Service information
type UniTagInformation struct {
        UniTagMatch                   int    `json:"uniTagMatch"`
        PonCTag                       int    `json:"ponCTag"`
        PonSTag                       int    `json:"ponSTag"`
        UsPonCTagPriority             int    `json:"usPonCTagPriority"`
        UsPonSTagPriority             int    `json:"usPonSTagPriority"`
        DsPonCTagPriority             int    `json:"dsPonCTagPriority"`
        DsPonSTagPriority             int    `json:"dsPonSTagPriority"`
        TechnologyProfileID           int    `json:"technologyProfileId"`
        UpstreamBandwidthProfile      string `json:"upstreamBandwidthProfile"`
        DownstreamBandwidthProfile    string `json:"downstreamBandwidthProfile"`
        UpstreamOltBandwidthProfile   string `json:"upstreamOltBandwidthProfile"`
        DownstreamOltBandwidthProfile string `json:"downstreamOltBandwidthProfile"`
        ServiceName                   string `json:"serviceName"`
        EnableMacLearning             bool   `json:"enableMacLearning"`
        ConfiguredMacAddress          string `json:"configuredMacAddress"`
        IsDhcpRequired                bool   `json:"isDhcpRequired"`
        IsIgmpRequired                bool   `json:"isIgmpRequired"`
        IsPppoeRequired               bool   `json:"isPppoeRequired"`
}

type ServiceAdapter struct {
}

func (sa *ServiceAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
	case "POST":
		sa.ActivateService(context.Background(), w, r)
	case "DELETE":
		sa.DeactivateService(context.Background(), w, r)
        case "GET":
		sa.GetProgrammedSubscribers(context.Background(), w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

func (sa *ServiceAdapter) ServeHTTPWithPortName(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
	case "POST":
		sa.ActivateServiceWithPortName(context.Background(), w, r)
	case "DELETE":
		sa.DeactivateServiceWithPortName(context.Background(), w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

func (sa *ServiceAdapter) ActivateService(cntx context.Context, w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        deviceID := vars[DEVICE]
        portNo := vars["port"]

        // Get the payload to process the request
        d := new(bytes.Buffer)
        if _, err := d.ReadFrom(r.Body);  err != nil {
                logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
                return
        }

	if len(deviceID) > 0 && len(portNo) > 0 {
		app.GetApplication().ActivateService(cntx, deviceID, portNo, of.VlanNone, of.VlanNone, 0)
	}
}

func (sa *ServiceAdapter) DeactivateService(cntx context.Context, w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        deviceID := vars[DEVICE]
        portNo := vars["port"]

        // Get the payload to process the request
        d := new(bytes.Buffer)
        if _, err := d.ReadFrom(r.Body);  err != nil {
                logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
                return
        }

	if len(deviceID) > 0 && len(portNo) > 0 {
		app.GetApplication().DeactivateService(cntx, deviceID, portNo, of.VlanNone, of.VlanNone, 0)
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

	if len(sTag) > 0 {
		sv, err := strconv.Atoi(sTag)
		if err != nil {
			logger.Warnw(ctx, "Wrong vlan value", log.Fields{"sTag": sTag})
			return
		}
		sVlan = of.VlanType(sv)
	}
	if len(cTag) > 0 {
		cv, err := strconv.Atoi(cTag)
		if err != nil {
			logger.Warnw(ctx, "Wrong vlan value", log.Fields{"cTag": cTag})
			return
		}
		cVlan = of.VlanType(cv)
	}
	if len(tpID) > 0 {
		tp, err := strconv.Atoi(tpID)
		if err != nil {
			logger.Warnw(ctx, "Wrong tech profile value", log.Fields{"tpID": tpID})
			return
		}
		techProfile = uint16(tp)
	}

	if len(portNo) > 0 {
		app.GetApplication().ActivateService(cntx, app.DeviceAny, portNo, sVlan, cVlan, techProfile)
	}
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

	if len(sTag) > 0 {
		sv, err := strconv.Atoi(sTag)
		if err != nil {
			logger.Warnw(ctx, "Wrong vlan value", log.Fields{"sTag": sTag})
			return
		}
		sVlan = of.VlanType(sv)
	}
	if len(cTag) > 0 {
		cv, err := strconv.Atoi(cTag)
		if err != nil {
			logger.Warnw(ctx, "Wrong vlan value", log.Fields{"cTag": cTag})
			return
		}
		cVlan = of.VlanType(cv)
	}
	if len(tpID) > 0 {
		tp, err := strconv.Atoi(tpID)
		if err != nil {
			logger.Warnw(ctx, "Wrong tech profile value", log.Fields{"tpID": tpID})
			return
		}
		techProfile = uint16(tp)
	}

        // Get the payload to process the request
        d := new(bytes.Buffer)
        if _, err := d.ReadFrom(r.Body);  err != nil {
                logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
                return
        }

	if len(portNo) > 0 {
		app.GetApplication().DeactivateService(cntx, app.DeviceAny, portNo, sVlan, cVlan, techProfile)
	}
}

func (sa *ServiceAdapter) GetProgrammedSubscribers(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
        deviceID := vars[DEVICE]
        portNo := vars["port"]

	svcs, err := app.GetApplication().GetProgrammedSubscribers(cntx, deviceID, portNo)
	if err != nil {
		logger.Errorw(ctx, "Failed to get subscribers", log.Fields{"Reason": err.Error()})
	}
	subs := convertServiceToSubscriberInfo(svcs)
	subsJSON, err := json.Marshal(subs)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling subscriber response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(subsJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending subscriber response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}
