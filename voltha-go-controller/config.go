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

package main

import (
	"strconv"
	"strings"

	"voltha-go-controller/internal/pkg/util/envutils"
)

// RW Core service default constants
const (
	defaultLogLevel                  = "DEBUG"
	defaultVolthaHost                = "127.0.0.1"
	defaultVolthaPort                = 50057
	defaultProbeHost                 = ""
	defaultProbePort                 = 8090
	defaultBanner                    = true
	defaultDisplayVersion            = false
	defaultCPUProfile                = ""
	defaultMemProfile                = ""
	defaultDeviceListRefreshInterval = 10
	defaultDeviceSyncDuration        = 5
	/*
		FIXME(At RWCORE) Problem: VGC comes up fast by that time RWCORE may not be up and will retry after 10 sec
		but rwcore could come up before the 10 second expiry and post indications to VGC which can't be consumed by
		VGC. Proper workaround is heml to sping VGC only when RWCORE reports via prope when the grpc server is up
		OR maintain a event/indiction queue similar to that in openolt-agent(which too is a GRPC SERVER)
		WorkAround: Reduce retry interval to 1 second from existing 10 seconds to that chances of indications getting missed is rare
	*/
	defaultConnectionRetryDelay = 1
	defaultConnectionMaxRetries = 120
	defaultKVStoreType          = "etcd"
	defaultKVStoreHost          = "127.0.0.1"
	defaultKVStorePort          = 2379
	defaultKVStoreTimeout       = 5000000000
	defaultKafkaAdapterHost     = "127.0.0.1"
	defaultKafkaAdapterPort     = 9092
	defaultInstanceID           = "VGC-01"
	defaultVendorID             = ""
)

func newVGCFlags() *VGCFlags {
	var vgcConfig = VGCFlags{
		LogLevel:                  defaultLogLevel,
		VolthaHost:                defaultVolthaHost,
		VolthaPort:                defaultVolthaPort,
		KVStoreType:               defaultKVStoreType,
		KVStoreHost:               defaultKVStoreHost,
		KVStorePort:               defaultKVStorePort,
		KVStoreTimeout:            defaultKVStoreTimeout,
		KafkaAdapterHost:          defaultKafkaAdapterHost,
		KafkaAdapterPort:          defaultKafkaAdapterPort,
		ProbeHost:                 defaultProbeHost,
		ProbePort:                 defaultProbePort,
		Banner:                    defaultBanner,
		DisplayVersion:            defaultDisplayVersion,
		CPUProfile:                defaultCPUProfile,
		MemProfile:                defaultMemProfile,
		DeviceListRefreshInterval: defaultDeviceListRefreshInterval,
		ConnectionRetryDelay:      defaultConnectionRetryDelay,
		ConnectionMaxRetries:      defaultConnectionMaxRetries,
		InstanceID:                defaultInstanceID,
		VendorID:                  defaultVendorID,
		DeviceSyncDuration:        defaultDeviceSyncDuration,
	}

	return &vgcConfig
}

// VGCFlags represents the set of configurations used by the VGC service
type VGCFlags struct {
	LogLevel                  string
	VolthaHost                string
	InstanceID                string
	KVStoreEndPoint           string
	MsgBusEndPoint            string
	ProbeEndPoint             string
	VolthaAPIEndPoint         string
	VendorID                  string
	KVStoreType               string
	KVStoreHost               string
	KafkaAdapterHost          string
	ProbeHost                 string
	CPUProfile                string
	MemProfile                string
	OFControllerEndPoints     multiFlag
	KafkaAdapterPort          int
	KVStoreTimeout            int // in seconds
	KVStorePort               int
	VolthaPort                int
	ProbePort                 int
	DeviceListRefreshInterval int // in seconds
	ConnectionRetryDelay      int // in seconds
	ConnectionMaxRetries      int
	DeviceSyncDuration        int
	Banner                    bool
	DisplayVersion            bool
}

// parseEnvironmentVariables parses the arguments when running read-write VGC service
func (cf *VGCFlags) parseEnvironmentVariables() {
	cf.LogLevel = envutils.ParseStringEnvVariable(envutils.LogLevel, defaultLogLevel)
	cf.VolthaHost = envutils.ParseStringEnvVariable(envutils.VolthaHost, defaultVolthaHost)
	cf.VolthaPort = int(envutils.ParseIntEnvVariable(envutils.VolthaPort, defaultVolthaPort))
	cf.KVStoreType = envutils.ParseStringEnvVariable(envutils.KvStoreType, defaultKVStoreType)
	cf.KVStoreTimeout = int(envutils.ParseIntEnvVariable(envutils.KvStoreTimeout, defaultKVStoreTimeout))
	cf.KVStoreHost = envutils.ParseStringEnvVariable(envutils.KvStoreHost, defaultKVStoreHost)
	cf.KVStorePort = int(envutils.ParseIntEnvVariable(envutils.KvStorePort, defaultKVStorePort))
	cf.KafkaAdapterHost = envutils.ParseStringEnvVariable(envutils.KafkaAdapterHost, defaultKafkaAdapterHost)
	cf.KafkaAdapterPort = int(envutils.ParseIntEnvVariable(envutils.KafkaAdapterPort, defaultKafkaAdapterPort))
	cf.ProbeHost = envutils.ParseStringEnvVariable(envutils.ProbeHost, defaultProbeHost)
	cf.ProbePort = int(envutils.ParseIntEnvVariable(envutils.ProbePort, defaultProbePort))
	cf.Banner = envutils.ParseBoolEnvVariable(envutils.Banner, defaultBanner)
	cf.DisplayVersion = envutils.ParseBoolEnvVariable(envutils.DisplayVersionOnly, defaultDisplayVersion)
	cf.CPUProfile = envutils.ParseStringEnvVariable(envutils.CPUProfile, defaultCPUProfile)
	cf.MemProfile = envutils.ParseStringEnvVariable(envutils.MemProfile, defaultMemProfile)
	cf.DeviceListRefreshInterval = int(envutils.ParseIntEnvVariable(envutils.DeviceListRefreshInterval, defaultDeviceListRefreshInterval))
	cf.ConnectionRetryDelay = int(envutils.ParseIntEnvVariable(envutils.ConnectionRetryInterval, defaultConnectionRetryDelay))
	cf.ConnectionMaxRetries = int(envutils.ParseIntEnvVariable(envutils.MaxConnectionRetries, defaultConnectionMaxRetries))
	cf.InstanceID = envutils.ParseStringEnvVariable(envutils.HostName, defaultInstanceID)
	cf.VendorID = envutils.ParseStringEnvVariable(envutils.VendorID, defaultVendorID)

	cf.KVStoreEndPoint = cf.KVStoreHost + ":" + strconv.Itoa(cf.KVStorePort)
	cf.MsgBusEndPoint = cf.KafkaAdapterHost + ":" + strconv.Itoa(cf.KafkaAdapterPort)
	cf.ProbeEndPoint = cf.ProbeHost + ":" + strconv.Itoa(cf.ProbePort)
	cf.VolthaAPIEndPoint = cf.VolthaHost + ":" + strconv.Itoa(cf.VolthaPort)

	cf.DeviceSyncDuration = int(envutils.ParseIntEnvVariable(envutils.DeviceSyncDuration, defaultDeviceSyncDuration))
}

type multiFlag []string

func (m *multiFlag) String() string {
	return "[" + strings.Join(*m, ", ") + "]"
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

/*
func parseCommandLineArguments() (*VGCFlags, error) {
	config := VGCFlags{}

	flag.BoolVar(&(config.Banner),
		"banner",
		true,
		"display application banner on startup")
	flag.BoolVar(&(config.DisplayVersion),
		"version",
		false,
		"display application version and exit")
	flag.StringVar(&(config.VolthaAPIEndPoint),
		"voltha",
		"127.0.0.1:50057",
		"connection to the VOLTHA API server specified as host:port")
	flag.StringVar(&(config.VolthaAPIEndPoint),
		"A",
		"127.0.0.1:50057",
		"(short) connection to the VOLTHA API server specified as host:port")
	flag.StringVar(&(config.ProbeEndPoint),
		"probe",
		":50080",
		"address and port on which to listen for k8s live and ready probe requests")
	flag.StringVar(&(config.ProbeEndPoint),
		"P",
		":50080",
		"(short) address and port on which to listen for k8s live and ready probe requests")
	flag.StringVar(&(config.CPUProfile),
		"cpuprofile",
		"",
		"write cpu profile to 'file' if specified")
	flag.StringVar(&(config.MemProfile),
		"memprofile",
		"",
		"write memory profile to 'file' if specified")
	flag.IntVar(&(config.ConnectionRetryDelay),
		"cd",
		3,
		"(short) delay to wait before connection establishment retries")
	flag.IntVar(&(config.ConnectionRetryDelay),
		"connnection-delay",
		3,
		"delay to wait before connection establishment retries")
	flag.IntVar(&(config.ConnectionMaxRetries),
		"mr",
		0,
		"(short) number of retries when attempting to estblish a connection, 0 is unlimted")
	flag.IntVar(&(config.ConnectionMaxRetries),
		"connnection-retries",
		0,
		"number of retries when attempting to estblish a connection, 0 is unlimted")
	flag.IntVar(&(config.DeviceListRefreshInterval),
		"dri",
		10,
		"(short) interval between attempts to synchronize devices from voltha to vpagent")
	flag.IntVar(&(config.DeviceListRefreshInterval),
		"device-refresh-interval",
		10,
		"interval between attempts to synchronize devices from voltha to vpagent")
	flag.StringVar(&(config.KVStoreType), "kv_store_type", "etcd", "KV store type")

	flag.IntVar(&(config.KVStoreTimeout), "kv_store_request_timeout", 5, "The default timeout when making a kv store request")

	flag.StringVar(&(config.KVStoreHost), "kv_store_host", "127.0.0.1", "KV store host")

	flag.IntVar(&(config.KVStorePort), "kv_store_port", 2379, "KV store port")

	flag.StringVar(&(config.MsgBusEndPoint), "msgbus_addr", "127.0.0.1:9092", "msgbus address")

	flag.StringVar(&(config.LogLevel), "log_level", "DEBUG", "Log level")

	containerName := getContainerInfo()
	if len(containerName) > 0 {
		config.InstanceID = containerName
	} else {
		config.InstanceID = "VGC-01"
	}

	return &config, nil
}

func getContainerInfo() string {
	return os.Getenv("HOSTNAME")
}*/
# [EOF] - delta:force
