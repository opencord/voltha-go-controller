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
	"context"
	"net/http"

	"voltha-go-controller/voltha-go-controller/onos_nbi"

	"github.com/gorilla/mux"

	"voltha-go-controller/log"
)

var logger log.CLogger
var ctx = context.TODO()

const (
	SubscribersPath                   string = "/vgc/v1/subscribers/{id}"
	ProfilesPath                      string = "/vgc/v1/profiles/{id}"
	IgmpProxyPath                     string = "/vgc/v1/igmp-proxy"
	IgmpProxyDeletePath               string = "/vgc/v1/igmp-proxy/{outgoingigmpvlanid}"
	MulticastPath                     string = "/vgc/v1/multicast/"
	MulticastDeletePath               string = "/vgc/v1/multicast/{egressvlan}"
	FlowsPath                         string = "/vgc/v1/flows"
	DevicesPath                       string = "/vgc/v1/devices"
	PortsPath                         string = "/vgc/v1/devices/ports"
	PortsPerDeviceIDPath              string = "/vgc/v1/devices/{olt_of_id}/ports"
	FlowsPerDeviceIDPath              string = "/vgc/v1/flows/{deviceId}"
	FlowPerDeviceIDFlowIDPath         string = "/vgc/v1/flows/{deviceId}/{flowId}"
	PendingFlowsPath                  string = "/vgc/v1/flows/pending"
	ProgrammedSubscribersPath         string = "/vgc/v1/programmed-subscribers"
	ServiceDevicePortPath             string = "/vgc/v1/services/{device}/{port}"
	ServicePortNamePath               string = "/vgc/v1/services/{portName}"
	ServicePortStagCtagTpIDPath       string = "/vgc/v1/services/{portName}/{sTag}/{cTag}/{tpId}"
	AllocationsPath                   string = "/vgc/v1/allocations"
	AllocationsDeviceIDPath           string = "/vgc/v1/allocations/{deviceId}"
	MecLearnerPath                    string = "/vgc/v1/mapping/all"
	MecLearnerDeviceIdAndPortNoPath   string = "/vgc/v1/mapping/{deviceId}/{portNumber}"
	MecLearnerDevicePortAndVlanIdPath string = "/vgc/v1/mapping/{deviceId}/{portNumber}/{vlanId}"
	PortIgnoredPath                   string = "/vgc/v1/ports/ignored"
	MetersParh                        string = "/vgc/v1/meters"
	MetersByIdPath                    string = "/vgc/v1/meters/{id}"
	GroupsPath                        string = "/vgc/v1/groups"
	GroupsByIdPath                    string = "/vgc/v1/groups/{id}"
	OltFlowServicePath                string = "/vgc/v1/oltflowservice"
	NetConfigPath                     string = "/vgc/v1/network/configurations"
	OltInfoPath                       string = "/vgc/v1/olt/{serialNumber}"
)

// RestStart to execute for API
func RestStart() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	mu.HandleFunc(SubscribersPath, (&SubscriberHandle{}).ServeHTTP)
	mu.HandleFunc(ProfilesPath, (&ProfileHandle{}).ServeHTTP)
	mu.HandleFunc(IgmpProxyPath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(IgmpProxyDeletePath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(MulticastPath, (&MulticastHandle{}).ServeHTTP)
	mu.HandleFunc(MulticastDeletePath, (&MulticastHandle{}).ServeHTTP)
	mu.HandleFunc(FlowsPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(FlowsPerDeviceIDPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(FlowPerDeviceIDFlowIDPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(PendingFlowsPath, (&onos_nbi.PendingFlowHandle{}).ServeHTTP)
	mu.HandleFunc(ProgrammedSubscribersPath, (&onos_nbi.ServiceAdapter{}).ServeHTTP)
	mu.HandleFunc(ServiceDevicePortPath, (&onos_nbi.ServiceAdapter{}).ServeHTTP)
	mu.HandleFunc(ServicePortNamePath, (&onos_nbi.ServiceAdapter{}).ServeHTTPWithPortName)
	mu.HandleFunc(ServicePortStagCtagTpIDPath, (&onos_nbi.ServiceAdapter{}).ServeHTTPWithPortName)
	mu.HandleFunc(AllocationsPath, (&onos_nbi.DhcpRelayHandle{}).ServeHTTP)
	mu.HandleFunc(AllocationsDeviceIDPath, (&onos_nbi.DhcpRelayHandle{}).ServeHTTP)
	mu.HandleFunc(DevicesPath, (&onos_nbi.DeviceHandle{}).ServeHTTP)
	mu.HandleFunc(PortsPath, (&onos_nbi.DevicePortHandle{}).ServeHTTP)
	mu.HandleFunc(PortsPerDeviceIDPath, (&onos_nbi.DevicePortHandle{}).ServeHTTPWithDeviceID)
	mu.HandleFunc(MecLearnerPath, (&onos_nbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(MecLearnerDeviceIdAndPortNoPath, (&onos_nbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(MecLearnerDevicePortAndVlanIdPath, (&onos_nbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(PortIgnoredPath, (&onos_nbi.PortIgnoredHandle{}).PortsIgnoredServeHTTP)
	mu.HandleFunc(MetersParh, (&onos_nbi.MetersHandle{}).MeterServeHTTP)
	mu.HandleFunc(MetersByIdPath, (&onos_nbi.MetersHandle{}).MeterServeHTTP)
	mu.HandleFunc(GroupsPath, (&onos_nbi.GroupsHandle{}).GroupServeHTTP)
	mu.HandleFunc(GroupsByIdPath, (&onos_nbi.GroupsHandle{}).GroupServeHTTP)
	mu.HandleFunc(OltFlowServicePath, (&onos_nbi.OltFlowServiceHandle{}).ServeHTTP)
	mu.HandleFunc(NetConfigPath, (&NetConfigHandle{}).NetConfigServeHTTP)
	mu.HandleFunc(OltInfoPath, (&onos_nbi.OltInfoHandle{}).ServeHTTP)

	err := http.ListenAndServe(":8181", mu)
	logger.Infow(ctx, "Rest Server Started", log.Fields{"Error": err})
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}
