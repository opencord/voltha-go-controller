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
        "encoding/json"
        "net/http"
	"strings"
	"strconv"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/of"
        "github.com/opencord/voltha-lib-go/v7/pkg/log"
)

// IgmpProxy - configurations
type IgmpProxy struct {
        FastLeave string `"fastleave"`
        LastQueryInterval int `"lastqueryinterval"`
        MaxResp int `"maxresp"`
        EnableIgmpProvisioning string `"enableigmpprovisioning"`
        GlobalConnectPointMode string `"globalconnectpointmode"`
        GlobalConnectPoint string `"globalconnectpoint"`
        SourceDeviceAndPort string `"sourcedeviceandport"`
        OutgoingIgmpVlanID int `"outgoingigmpvlanid"`
        OutgoingIgmpInnerVlanID int `"outgoingigmpinnervlanid"`
        OutgoingIgmpWithV3 string `"outgoingigmpwithv3"`
        IgmpCos int `"igmpcos"`
        IgmpUniCos int `"igmpunicos"`
        PeriodicQuery string `"periodicquery"`
        KeepAliveInterval int `"keepaliveinterval"`
        KeepAliveCount int `"keepalivecount"`
        RequestDsIgmpPackets bool `"requestdsigmppackets"`
}

// IgmpProxyHandle struct
type IgmpProxyHandle struct {
}

// ServeHTTP to serve http request
func (iph *IgmpProxyHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
        case "POST":
                iph.AddIgmpProxyInfo(w, r)
        case "DELETE":
                iph.DelIgmpProxyInfo(w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

// AddIgmpProxyInfo to add igmp proxy info
func (iph *IgmpProxyHandle) AddIgmpProxyInfo(w http.ResponseWriter, r *http.Request) {

        // Get the payload to process the request
        d := new(bytes.Buffer)
        d.ReadFrom(r.Body)

        // Unmarshal the request into service configuration structure
        req := &IgmpProxy{}
        if err := json.Unmarshal(d.Bytes(), req); err != nil {
                logger.Warnw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
                http.Error(w, err.Error(), http.StatusConflict)
                return
        }
        if mvp := app.GetApplication().GetMvlanProfileByTag(of.VlanType(req.OutgoingIgmpVlanID)); mvp == nil {
                logger.Errorw(ctx, "MVLAN ID not configured", log.Fields{"mvlan": req.OutgoingIgmpVlanID})
                http.Error(w, "MVLAN profile does not exists", http.StatusConflict)
                return
        }
        logger.Debugw(ctx, "Received-northbound-add-service-request", log.Fields{"req": req})

        go iph.addIgmpProxy(w, req)
}

// DelIgmpProxyInfo to delete igmp proxy info
func (iph *IgmpProxyHandle) DelIgmpProxyInfo(w http.ResponseWriter, r *http.Request) {

}

func (iph *IgmpProxyHandle) addIgmpProxy(w http.ResponseWriter, req *IgmpProxy) {
	var config McastConfig

	config.OltSerialNum = req.SourceDeviceAndPort
	//config.MvlanProfileID = mvp.Name
	//config.IgmpProfileID = 
	//config.IgmpProxyIP = 
	var splits = strings.Split(req.SourceDeviceAndPort, "/")
	config.OltSerialNum = splits[0]
	config.MvlanProfileID = "mvlan" + strconv.Itoa(req.OutgoingIgmpVlanID)

	logger.Errorw(ctx, "IgmpProxy", log.Fields{"config":config})

        if err := app.GetApplication().AddMcastConfig(config.MvlanProfileID, config.IgmpProfileID,
                config.IgmpProxyIP, config.OltSerialNum); err != nil {
                logger.Errorw(ctx, "northbound-add-mcast-config-failed", log.Fields{"config": config, "Error": err})
                http.Error(w, err.Error(), http.StatusConflict)
                return
        }

}

