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
	BasePath                          string = "/vgc/v1"
	SubscribersPath                   string = "/subscribers/{id}"
	ProfilesPath                      string = "/profiles/{id}"
	IgmpProxyPath                     string = "/igmp-proxy"
	IgmpProxyDeletePath               string = "/igmp-proxy/{outgoingigmpvlanid}"
	MulticastPath                     string = "/multicast/"
	MulticastDeletePath               string = "/multicast/{egressvlan}"
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
	NetConfigPath                     string = "/network/configurations"
	DeviceConfigPath                  string = "/olt/{serialNumber}"
)

// RestStart to execute for API
func RestStart() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	mu.HandleFunc(BasePath+SubscribersPath, (&SubscriberHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+ProfilesPath, (&ProfileHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+IgmpProxyPath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+IgmpProxyDeletePath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MulticastPath, (&MulticastHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MulticastDeletePath, (&MulticastHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+FlowsPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+FlowsPerDeviceIDPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+FlowPerDeviceIDFlowIDPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PendingFlowsPath, (&onos_nbi.PendingFlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+ProgrammedSubscribersPath, (&onos_nbi.ServiceAdapter{}).ServeHTTP)
	mu.HandleFunc(BasePath+ServiceDevicePortPath, (&onos_nbi.ServiceAdapter{}).ServeHTTP)
	mu.HandleFunc(BasePath+ServicePortNamePath, (&onos_nbi.ServiceAdapter{}).ServeHTTPWithPortName)
	mu.HandleFunc(BasePath+ServicePortStagCtagTpIDPath, (&onos_nbi.ServiceAdapter{}).ServeHTTPWithPortName)
	mu.HandleFunc(BasePath+AllocationsPath, (&onos_nbi.DhcpRelayHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+AllocationsDeviceIDPath, (&onos_nbi.DhcpRelayHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+DevicesPath, (&onos_nbi.DeviceHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PortsPath, (&onos_nbi.DevicePortHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PortsPerDeviceIDPath, (&onos_nbi.DevicePortHandle{}).ServeHTTPWithDeviceID)
	mu.HandleFunc(BasePath+MecLearnerPath, (&onos_nbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MecLearnerDeviceIdAndPortNoPath, (&onos_nbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MecLearnerDevicePortAndVlanIdPath, (&onos_nbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PortIgnoredPath, (&onos_nbi.PortIgnoredHandle{}).PortsIgnoredServeHTTP)
	mu.HandleFunc(BasePath+MetersParh, (&onos_nbi.MetersHandle{}).MeterServeHTTP)
	mu.HandleFunc(BasePath+MetersByIdPath, (&onos_nbi.MetersHandle{}).MeterServeHTTP)
	mu.HandleFunc(BasePath+GroupsPath, (&onos_nbi.GroupsHandle{}).GroupServeHTTP)
	mu.HandleFunc(BasePath+GroupsByIdPath, (&onos_nbi.GroupsHandle{}).GroupServeHTTP)
	mu.HandleFunc(BasePath+OltFlowServicePath, (&onos_nbi.OltFlowServiceHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+NetConfigPath, (&NetConfigHandle{}).NetConfigServeHTTP)
	mu.HandleFunc(BasePath+DeviceConfigPath, (&onos_nbi.DeviceConfigHandle{}).ServeHTTP)

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
