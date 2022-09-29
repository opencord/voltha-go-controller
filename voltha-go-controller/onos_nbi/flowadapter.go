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
        "context"
	"encoding/json"
        "net/http"
	"strconv"

	"github.com/gorilla/mux"
        "voltha-go-controller/internal/pkg/of"
        "voltha-go-controller/log"
	cntlr "voltha-go-controller/internal/pkg/controller"
)

// FlowHandle struct to handle flow related REST calls
type FlowHandle struct {
}

// FlowHandle struct to handle flow related REST calls
type PendingFlowHandle struct {
}

type TrafficSelector struct {

}

type TrafficTreatment struct {

}

/*
type FlowEntry struct {
	TrafficSelector
	TrafficTreatment
	FlowID int
	AppID  int
	GroupID int
	Priority int
	DeviceID string
	TimeOut int
	TableID int
}*/

func (fh *FlowHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
        case "GET":
                fh.GetFlows(context.Background(), w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

func (pfh *PendingFlowHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
        case "GET":
                pfh.GetPendingFlows(context.Background(), w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

func (pfh *PendingFlowHandle) GetPendingFlows(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	flows, err := cntlr.GetController().GetAllPendingFlows()
	if err != nil {
		logger.Errorw(ctx, "Failed to get Pending flows", log.Fields{"Error": err})
		return
	}
	flowResp := ConvertFlowsToFlowEntry(flows)
	FlowRespJSON, err := json.Marshal(flowResp)
	if err != nil {
		logger.Errorw(ctx, "Failed to marshal pending flow response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(FlowRespJSON)
	if err != nil {
		logger.Errorw(ctx, "Failed to write Pending Flow response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}

func (fh *FlowHandle) GetFlows(cntx context.Context, w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        deviceID := vars["deviceId"]
        flowIDStr := vars["flowId"]
	flowID, _ := strconv.ParseUint(flowIDStr, 10, 64)
	var flowResp FlowEntry
	if len(deviceID) > 0 && len(flowIDStr) > 0 {
		flow, err := fh.getFlow(deviceID, flowID)
		if err != nil {
			logger.Errorw(ctx, "Failed to Fetch flow", log.Fields{"Error": err})
			return
		}
		flowResp = ConvertFlowToFlowEntry(flow)
		//flowResp = append(flowResp, flow)
	} else {
		flows, err := fh.getAllFlows(deviceID)
		if err != nil {
			logger.Errorw(ctx, "Failed to Fetch flows", log.Fields{"Error": err})
			return
		}
		flowResp = ConvertFlowsToFlowEntry(flows)
		//..flowResp = append(flowResp, flows...)
	}
	FlowRespJSON, err := json.Marshal(flowResp)
	if err != nil {
		logger.Errorw(ctx, "Failed to marshal flow response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(FlowRespJSON)
	if err != nil {
		logger.Errorw(ctx, "Failed to write flow response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (fh *FlowHandle) getAllFlows(deviceID string) ([]*of.VoltSubFlow, error) {
	if len(deviceID) == 0 {
		return cntlr.GetController().GetAllFlows()
	}
	return cntlr.GetController().GetFlows(deviceID)
}

func (fh *FlowHandle) getFlow(deviceID string, flowID uint64) (*of.VoltSubFlow, error) {
	return cntlr.GetController().GetFlow(deviceID, flowID)
}
