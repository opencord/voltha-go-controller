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

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/of"
	common "voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

// McastConfig structure
type McastConfig struct {
	MvlanProfileID string `json:"mvlanProfile"`
	IgmpProfileID  string `json:"igmpProfile"`
	IgmpProxyIP    string `json:"igmpProxyIp"`
	OltSerialNum   string `json:"oltSerialNum"`
}

// MvlanProfileCfg structure
type MvlanProfileCfg struct {
	*MvlanProfile `json:"mvlanProfile"`
}

// Mvlan - configurations
type Mvlan struct {
	IngressVlan     int `json:"ingressvlan"`
	EgressVlan      int `json:"egressvlan"`
	EgressInnerVlan int `json:"egressinnervlan"`
}

// MvlanProfile structure
type MvlanProfile struct {
	Name                 string                                `json:"name"`
	Groups               map[string][]string                   `json:"groups"`
	Proxy                map[string]common.MulticastGroupProxy `json:"proxy"`
	OLTSerialNum         []string                              `json:"oltserialnum"`
	ActiveChannelsPerSub int                                   `json:"ActiveChannelsPerSub"`
	Mvlan                of.VlanType                           `json:"mvlan"`
	PonVlan              of.VlanType                           `json:"ponVlan"`
	IsChannelBasedGroup  bool                                  `json:"isChannelBasedGroup"`
}

// IGMPCfg structure
type IGMPCfg struct {
	AppID struct {
		IgmpApp struct {
			Parameters common.IGMPConfig `json:"igmpproxy"`
		} `json:"org.opencord.igmpproxy"`
	} `json:"apps"`
}

// MulticastHandle struct
type MulticastHandle struct {
}

// ServeHTTP to serve http request
func (iph *MulticastHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		iph.AddMvlanInfo(context.Background(), w, r)
	case cDelete:
		iph.DelMvlanInfo(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// AddMvlanInfo to add igmp proxy info
func (iph *MulticastHandle) AddMvlanInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Unmarshal the request into service configuration structure
	req := &Mvlan{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Failed to Unmarshal Adding Mvlan Info", log.Fields{"req": req, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Infow(ctx, "Received-northbound-add-mvlanInfo-request", log.Fields{"req": req})

	go iph.addMvlan(cntx, w, req)
}

// DelMvlanInfo to delete igmp proxy info
func (iph *MulticastHandle) DelMvlanInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	egressvlan := vars["egressvlan"]

	name := "mvlan" + egressvlan
	// HTTP response with 202 accepted for service delete request
	w.WriteHeader(http.StatusAccepted)

	logger.Infow(ctx, "Request for DelMvlanInfo for mvlan", log.Fields{"name": name})
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	err := voltAppIntr.DelMvlanProfile(cntx, name)
	if err != nil {
		logger.Errorw(cntx, "Failed to delete Mvlan profile", log.Fields{"name": name, "Error": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

func (iph *MulticastHandle) addMvlan(cntx context.Context, w http.ResponseWriter, req *Mvlan) {
	var config MvlanProfile
	var groups []string

	groups = append(groups, "225.0.0.0-239.255.255.255")
	config.Name = "mvlan" + strconv.Itoa(req.EgressVlan)
	config.Mvlan = of.VlanType(req.EgressVlan)
	config.PonVlan = of.VlanType(req.EgressInnerVlan)
	config.Groups = make(map[string][]string)
	config.Groups["default"] = groups

	logger.Infow(ctx, "northbound-add-mvlan-received", log.Fields{"Config": config})
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	if err := voltAppIntr.AddMvlanProfile(cntx, config.Name, config.Mvlan, config.PonVlan, config.Groups,
		config.IsChannelBasedGroup, config.OLTSerialNum,
		255, config.Proxy); err != nil {
		logger.Errorw(ctx, "northbound-add-mvlan-failed", log.Fields{"mvlan": config.Name, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "northbound-add-mvlan-successful", log.Fields{"mvlan": config.Name})
}
