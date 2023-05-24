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

package nbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"
)

// IgmpProxy - configurations
type IgmpProxy struct {
	FastLeave               string `json:"fastleave"`
	EnableIgmpProvisioning  string `json:"enableigmpprovisioning"`
	GlobalConnectPointMode  string `json:"globalconnectpointmode"`
	GlobalConnectPoint      string `json:"globalconnectpoint"`
	SourceDeviceAndPort     string `json:"sourcedeviceandport"`
	OutgoingIgmpWithV3      string `json:"outgoingigmpwithv3"`
	PeriodicQuery           string `json:"periodicquery"`
	LastQueryInterval       int    `json:"lastqueryinterval"`
	MaxResp                 int    `json:"maxresp"`
	OutgoingIgmpVlanID      int    `json:"outgoingigmpvlanid"`
	OutgoingIgmpInnerVlanID int    `json:"outgoingigmpinnervlanid"`
	IgmpCos                 int    `json:"igmpcos"`
	IgmpUniCos              int    `json:"igmpunicos"`
	KeepAliveInterval       int    `json:"keepaliveinterval"`
	KeepAliveCount          int    `json:"keepalivecount"`
	RequestDsIgmpPackets    bool   `json:"requestdsigmppackets"`
}

// IgmpProxyHandle struct
type IgmpProxyHandle struct {
}

// ServeHTTP to serve http request
func (iph *IgmpProxyHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		iph.AddIgmpProxyInfo(context.Background(), w, r)
	case cDelete:
		iph.DelIgmpProxyInfo(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// AddIgmpProxyInfo to add igmp proxy info
func (iph *IgmpProxyHandle) AddIgmpProxyInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Unmarshal the request into service configuration structure
	req := &IgmpProxy{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Failed to Unmarshal Adding Igmp Proxy Info", log.Fields{"req": req, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Infow(ctx, "Received-northbound-add-igmpProxyInfo-request", log.Fields{"req": req})

	go iph.addIgmpProxy(cntx, w, req)
}

// DelIgmpProxyInfo to delete igmp proxy info
func (iph *IgmpProxyHandle) DelIgmpProxyInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {
}

func (iph *IgmpProxyHandle) addIgmpProxy(cntx context.Context, w http.ResponseWriter, req *IgmpProxy) {
	var config McastConfig

	if mvp := app.GetApplication().GetMvlanProfileByTag(of.VlanType(req.OutgoingIgmpVlanID)); mvp == nil {
		logger.Errorw(ctx, "MVLAN ID not configured", log.Fields{"mvlan": req.OutgoingIgmpVlanID})
		http.Error(w, "MVLAN profile does not exists", http.StatusConflict)
		return
	}
	config.OltSerialNum = req.SourceDeviceAndPort
	var splits = strings.Split(req.SourceDeviceAndPort, "/")
	config.OltSerialNum = splits[0]
	config.MvlanProfileID = "mvlan" + strconv.Itoa(req.OutgoingIgmpVlanID)

	logger.Infow(ctx, "northbound-add-igmpProxy-request", log.Fields{"config": config})

	if err := app.GetApplication().AddMcastConfig(cntx, config.MvlanProfileID, config.IgmpProfileID,
		config.IgmpProxyIP, config.OltSerialNum); err != nil {
		logger.Errorw(ctx, "northbound-add-mcast-config-failed", log.Fields{"config": config, "Error": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
}
