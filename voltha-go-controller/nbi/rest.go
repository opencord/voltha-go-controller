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
	SubscribersPath                   string = "/subscribers/{id}"
	ProfilesPath                      string = "/profiles/{id}"
	IgmpProxyPath                     string = "/igmp-proxy"
	MulticastPath                     string = "/multicast"
	FlowsPath                         string = "/flows"
	DevicesPath                       string = "/devices"
	PortsPath                         string = "/devices/ports"
	PortsPerDeviceIDPath              string = "/devices/{olt_of_id}/ports"
	FlowsPerDeviceIDPath              string = "/flows/{deviceId}"
	FlowPerDeviceIDFlowIDPath         string = "/flows/{deviceId}/{flowId}"
	PendingFlowsPath                  string = "/flows/pending"
	ProgrammedSubscribersPath         string = "/programmed-subscribers"
	ServiceDevicePortPath             string = "/services/{device}/{port}"
	ServicePortNamePath               string = "/services/{portName}"
	ServicePortStagCtagTpIDPath       string = "/services/{portName}/{sTag}/{cTag}/{tpId}"
	AllocationsPath                   string = "/allocations"
	AllocationsDeviceIDPath           string = "/allocations/{deviceId}"
	MecLearnerPath                    string = "/mapping/all"
	MecLearnerDeviceIdAndPortNoPath   string = "/mapping/{deviceId}/{portNumber}"
	MecLearnerDevicePortAndVlanIdPath string = "/mapping/{deviceId}/{portNumber}/{vlanId}"
	PortIgnoredPath                   string = "/ports/ignored"
	MetersParh                        string = "/meters"
	MetersByIdPath                    string = "/meters/{id}"
	GroupsPath                        string = "/groups"
	GroupsByIdPath                    string = "/groups/{id}"
	OltFlowServicePath                string = "/oltflowservice"
)

// RestStart to execute for API
func RestStart() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	mu.HandleFunc(SubscribersPath, (&SubscriberHandle{}).ServeHTTP)
	mu.HandleFunc(ProfilesPath, (&ProfileHandle{}).ServeHTTP)
	mu.HandleFunc(IgmpProxyPath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(MulticastPath, (&MulticastHandle{}).ServeHTTP)
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
