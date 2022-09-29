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
	"net"
	"net/http"
	"strconv"

	"github.com/google/gopacket/layers"
	"github.com/gorilla/mux"
	"voltha-go-controller/internal/pkg/application"
	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/log"
)

//SubscriberDeviceInfo - Subcriber Device Info
type SubscriberDeviceInfo struct {
	ID                 string              `json:"id"`
	NasPortID          string              `json:"nasPortId"`
	UplinkPort         int                 `json:"uplinkPort"`
	Slot               int                 `json:"slot"`
	HardwareIdentifier string              `json:"hardwareIdentifier"`
	IPAddress          net.IP              `json:"ipAddress"`
	NasID              string              `json:"nasId"`
	CircuitID          string              `json:"circuitId"`
	RemoteID           string              `json:"remoteId"`
	UniTagList         []UniTagInformation `json:"uniTagList"`
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


func init() {
        // Setup this package so that it's log level can be modified at run time
        var err error
        logger, err = log.AddPackageWithDefaultParam()
        if err != nil {
                panic(err)
        }
}

// SubscriberHandle handle SubscriberInfo Requests
type SubscriberHandle struct {
}

// ServeHTTP to serve http request
func (sh *SubscriberHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "POST":
		sh.AddSubscriberInfo(context.Background(), w, r)
	case "DELETE":
		sh.DelSubscriberInfo(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// AddSubscriberInfo to add service
func (sh *SubscriberHandle) AddSubscriberInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {

	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body);  err != nil {
		logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		return
	}

	// Unmarshal the request into service configuration structure
	req := &SubscriberDeviceInfo{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Warnw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "Received-northbound-add-service-request", log.Fields{"req": req})

	//vsCfgList := getVoltServiceFromSrvInfo(req)

	go addAllService(cntx, req)
}

func addAllService(cntx context.Context, srvInfo *SubscriberDeviceInfo) {

	//vsCfgList := getVoltServiceFromSrvInfo(srvInfo)

	for _, uniTagInfo := range srvInfo.UniTagList {
		var vs application.VoltServiceCfg

		svcname := srvInfo.ID + "_"
		svcname = svcname + srvInfo.NasPortID + "-"
		svcname = svcname + strconv.Itoa(uniTagInfo.UniTagMatch) + "-"
		svcname = svcname + strconv.Itoa(uniTagInfo.PonSTag) + "-"
		svcname = svcname + strconv.Itoa(uniTagInfo.PonCTag) + "-"
		vs.Name = svcname + strconv.Itoa(uniTagInfo.TechnologyProfileID)

		vs.Port = srvInfo.NasPortID
		vs.SVlan = of.VlanType(uniTagInfo.PonSTag)
		vs.CVlan = of.VlanType(uniTagInfo.PonCTag)
		vs.UniVlan = of.VlanType(uniTagInfo.UniTagMatch)
		vs.TechProfileID = uint16(uniTagInfo.TechnologyProfileID)
		vs.UsMeterProfile = uniTagInfo.UpstreamBandwidthProfile
		vs.DsMeterProfile = uniTagInfo.DownstreamBandwidthProfile
		vs.IgmpEnabled = uniTagInfo.IsIgmpRequired
		//vs.McastService = uniTagInfo.IsIgmpRequired
		if vs.IgmpEnabled {
			vs.MvlanProfileName = "mvlan" + strconv.Itoa(uniTagInfo.PonSTag)
		}
		if uniTagInfo.UsPonSTagPriority == -1 {
			vs.Pbits = append(vs.Pbits, of.PbitMatchAll)
		// Process the p-bits received in the request
		} else {
			if uniTagInfo.UsPonSTagPriority < 8 {
				vs.Pbits = append(vs.Pbits, of.PbitType(uniTagInfo.UsPonCTagPriority))
			}

			if uniTagInfo.UsPonSTagPriority < 8 && uniTagInfo.UsPonSTagPriority != uniTagInfo.DsPonSTagPriority {
				vs.Pbits = append(vs.Pbits, of.PbitType(uniTagInfo.DsPonCTagPriority))
			}
		}

		/*
		var err error
		if vs.MacAddr, err = net.ParseMAC(srvInfo.HardwareIdentifier); err != nil {
			vs.MacAddr, _ = net.ParseMAC("00:00:00:00:00:00")
		}*/

		vs.MacAddr, _ = net.ParseMAC("00:00:00:00:00:00")
		if len(vs.Pbits) == 0 {
			vs.Pbits = append(vs.Pbits, of.PbitMatchNone)
		}

		vnetName := strconv.FormatUint(uint64(vs.SVlan), 10) + "-"
		vnetName = vnetName + strconv.FormatUint(uint64(vs.CVlan), 10) + "-"
		vnetName = vnetName + strconv.FormatUint(uint64(vs.UniVlan), 10)

		vnetcfg := app.VnetConfig{
			Name:       vnetName,
			SVlan:      vs.SVlan,
			CVlan:      vs.CVlan,
			UniVlan:    vs.UniVlan,
			SVlanTpid:  layers.EthernetTypeDot1Q,
			DhcpRelay:  uniTagInfo.IsDhcpRequired,
			//MacLearning:                req.MacLearning,
			//ONTEtherTypeClassification: req.ONTEtherTypeClassification,
			//VlanControl:                app.VlanControl(req.VlanControl), //TODO
		}
		if uniTagInfo.UsPonSTagPriority < 8 {
			vnetcfg.UsDhcpPbit = append(vnetcfg.UsDhcpPbit, of.PbitType(uniTagInfo.UsPonSTagPriority))
		}

		if vs.CVlan != of.VlanAny && vs.SVlan != of.VlanAny {
			vnetcfg.VlanControl = app.ONUCVlanOLTSVlan
		} else if vs.CVlan == of.VlanAny && vs.UniVlan == of.VlanAny {
			vnetcfg.VlanControl = app.OLTSVlan
		}

		if err := app.GetApplication().AddVnet(cntx, vnetcfg, nil); err != nil {
			logger.Errorw(ctx, "AddVnet Failed", log.Fields{"VnetName": vnetName, "Error": err})
		}
		if err := app.GetApplication().AddService(cntx, vs, nil); err != nil {
			logger.Errorw(ctx, "AddService Failed", log.Fields{"Service": vs.Name, "Error": err})
		}

	}
}

// DelSubscriberInfo to delete service
func (sh *SubscriberHandle) DelSubscriberInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	id := vars["id"]

	logger.Debugw(ctx, "Received-northbound-del-service-request", log.Fields{"req": id})

	// HTTP response with 202 accepted for service delete request
	w.WriteHeader(http.StatusAccepted)

	logger.Warnw(ctx, "northbound-del-service-req", log.Fields{"ServiceName": id})
	go app.GetApplication().DelServiceWithPrefix(cntx, id)
}
