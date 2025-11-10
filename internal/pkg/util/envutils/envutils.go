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

// Package envutils provides the env parsing utility functions
package envutils

import (
	"fmt"
	"os"
	"strconv"
)

// common constants
const (
	// common environment variables

	KafkaAdapterHost     = "KAFKA_ADAPTER_HOST"
	KafkaAdapterPort     = "KAFKA_ADAPTER_PORT"
	KafkaClusterHost     = "KAFKA_CLUSTER_HOST"
	KafkaClusterPort     = "KAFKA_CLUSTER_PORT"
	KvStoreType          = "KV_STORE_TYPE"
	KvStoreTimeout       = "KV_STORE_TIMEOUT"
	KvStoreHost          = "KV_STORE_HOST"
	KvStorePort          = "KV_STORE_PORT"
	AdapterTopic         = "ADAPTER_TOPIC"
	CoreTopic            = "CORE_TOPIC"
	EventTopic           = "EVENT_TOPIC"
	LogLevel             = "LOG_LEVEL"
	OnuNumber            = "ONU_NUMBER"
	Banner               = "BANNER"
	DisplayVersionOnly   = "DISPLAY_VERSION_ONLY"
	ProbeHost            = "PROBE_HOST"
	ProbePort            = "PROBE_PORT"
	LiveProbeInterval    = "LIVE_PROBE_INTERVAL"
	NotLiveProbeInterval = "NOT_LIVE_PROBE_INTERVAL"
	VolthaHost           = "VOLTHA_HOST"
	VolthaPort           = "VOLTHA_PORT"
	HostName             = "HOST_NAME"

	// openolt adapter environment variables

	HeartbeatCheckInterval      = "HEARTBEAT_CHECK_INTERVAL"
	HeartbeatFailReportInterval = "HEARTBEAT_FAIL_REPORT_INTERVAL"
	GrpcTimeoutInterval         = "GRPC_TIMEOUT_INTERVAL"

	// rwcore environment variables

	RWCoreEndpoint            = "RW_CORE_ENDPOINT"
	GrpcHost                  = "GRPC_HOST"
	GrpcPort                  = "GRPC_PORT"
	AffinityRouterTopic       = "AFFINITY_ROUTER_TOPIC"
	InCompetingMode           = "IN_COMPETING_MODE"
	KVTxnKeyDelTime           = "KV_TXN_KEY_DEL_TIME"
	KVStoreDataPrefix         = "KV_STORE_DATA_PREFIX"
	LongRunningRequestTimeout = "LONG_RUNNING_REQ_TIMEOUT"
	DefaultRequestTimeout     = "DEFAULT_REQ_TIMEOUT"
	DefaultCoreTimeout        = "DEFAULT_CORE_TIMEOUT"
	CoreBindingKey            = "CORE_BINDING_KEY"
	CorePairTopic             = "CORE_PAIR_TOPIC"
	MaxConnectionRetries      = "MAX_CONNECTION_RETRIES"
	ConnectionRetryInterval   = "CONNECTION_RETRY_INTERVAL"

	// vgc environment variables

	DeviceListRefreshInterval = "DEVICE_LIST_REFRESH_INTERVAL" // in seconds
	CPUProfile                = "CPU_PROFILE"
	MemProfile                = "MEM_PROFILE"
	VendorID                  = "VENDOR_ID"
	DeviceSyncDuration        = "DEVICE_SYNC_DURATION"
	MaxFlowRetryDuration      = "MAX_FLOW_RETRY_DURATION"
	// openonu environment variables

	OmciPacketCapture   = "SAVE_OMCI_PACKET_CAPTURE"
	Undefined           = " undefined"
	EnvironmentVariable = "Environment variable "
)

// ParseStringEnvVariable reads the environment variable and returns env as string
func ParseStringEnvVariable(envVarName string, defaultVal string) string {
	envValue := os.Getenv(envVarName)
	if envValue == "" {
		fmt.Println(EnvironmentVariable + envVarName + Undefined)
		return defaultVal
	}
	return envValue
}

// ParseIntEnvVariable reads the environment variable and returns env as int64
func ParseIntEnvVariable(envVarName string, defaultVal int64) int64 {
	envValue := os.Getenv(envVarName)
	if envValue == "" {
		fmt.Println(EnvironmentVariable+envVarName+Undefined, envVarName)
		return defaultVal
	}
	returnVal, err := strconv.Atoi(envValue)
	if err != nil {
		fmt.Println("Unable to convert string to integer environment variable")
		return defaultVal
	}
	return int64(returnVal)
}

// ParseBoolEnvVariable reads the environment variable and returns env as boolean
func ParseBoolEnvVariable(envVarName string, defaultVal bool) bool {
	envValue := os.Getenv(envVarName)
	if envValue == "" {
		fmt.Println(EnvironmentVariable + envVarName + Undefined)
		return defaultVal
	}
	if envValue == "true" || envValue == "True" {
		return true
	}
	return false
}
