/*
* Copyright 2022-2024present Open Networking Foundation
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

package config

import "voltha-go-controller/internal/pkg/util/envutils"

// Default values
const (
	defaultKVStoreHost    = "127.0.0.1"
	defaultKVStorePort    = 6379
	defaultKVStoreTimeout = 5
	defaultKVStoreType    = "redis"
)

// Config represents the set of configurations used by the VGC-cli
type Config struct {
	KVStoreHost    string
	KVStoreType    string
	KVStorePort    int
	KVStoreTimeout int
}

// ParseEnvironmentVariables parses the environment variables passed to VGC-cli
func (cf *Config) ParseEnvironmentVariables() {
	cf.KVStoreHost = envutils.ParseStringEnvVariable(envutils.KvStoreHost, defaultKVStoreHost)
	cf.KVStorePort = int(envutils.ParseIntEnvVariable(envutils.KvStorePort, defaultKVStorePort))
	cf.KVStoreType = envutils.ParseStringEnvVariable(envutils.KvStoreType, defaultKVStoreType)
	cf.KVStoreTimeout = int(envutils.ParseIntEnvVariable(envutils.KvStoreTimeout, defaultKVStoreTimeout))
}

// NewConfig initializes the configuration with default values
func NewConfig() *Config {
	return &Config{
		KVStoreHost:    defaultKVStoreHost,
		KVStorePort:    defaultKVStorePort,
		KVStoreTimeout: defaultKVStoreTimeout,
	}
}
