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

package database

import (
	"fmt"

	"voltha-go-controller/voltha-go-controller/cli/config"
)

// KVPath type
type KVPath string

const (
	// basePath constant
	basePath KVPath = "service/vgc/"
	// version1 constant
	version1 KVPath = "v1/"
	// APIBasePath constant
	APIBasePath string = "http://localhost:8181/"
	// DeviceCommandPath constant
	DeviceCommandPath string = APIBasePath + "device-info/"
	// IcmpCachePath constant
	IcmpCachePath string = APIBasePath + "icmp-cache/"
	// MvlanCachePath constant
	MvlanCachePath string = APIBasePath + "mvlan-cache/"
	// PortCachePath constant
	PortCachePath string = APIBasePath + "port-cache/"
	// TaskListPath constant
	TaskListPath string = APIBasePath + "task-list/"
	// PonPortsPath constant
	PonPortsPath string = APIBasePath + "pon-port/"
	// DHCPSessionPath constant
	DHCPSessionPath string = APIBasePath + "dhcp-session/"
	// FlowHashPath constant
	FlowHashPath string = APIBasePath + "devices/%s/flowhash/"
	// GetFlowHashPath constant
	GetFlowHashPath KVPath = basePath + version1 + "devices/%s/flowhash"
)

// Data contains key and value
type Data struct {
	Key   string
	Value []byte
}

// GetRedisClient create a new redis client for vgc ctl.
func GetRedisClient() (*RedisClient, error) {
	cfg := config.NewConfig()
	cfg.ParseEnvironmentVariables()

	rc, err := NewRedisClient(
		fmt.Sprintf("%s:%d", cfg.KVStoreHost, cfg.KVStorePort),
		cfg.KVStoreTimeout)
	if err != nil {
		return nil, fmt.Errorf("Failed to establish connection to Redis Client: %v ", err)
	}
	return rc, nil
}
