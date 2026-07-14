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

package common

import (
	"errors"
)

// AdminState represents Status of an VLAN:ENABLE/DISABLE
type AdminState string

var (
	// ErrEntryNotFound is the error when the key doesn't exist in the KVStore
	ErrEntryNotFound = errors.New("Entry not found")
)

// Device Status
type SubscriberStatus_Types int32

const (
	SubscriberStatus_UNDEFINED SubscriberStatus_Types = 0
	SubscriberStatus_UP        SubscriberStatus_Types = 1
	SubscriberStatus_DOWN      SubscriberStatus_Types = 2
)

func (d SubscriberStatus_Types) String() string {
	switch d {
	case SubscriberStatus_UP:
		return "UP"
	case SubscriberStatus_DOWN:
		return "DOWN"
	default:
		return "UNDEFINED"
	}
}

// DeviceState refers to the state of device
type DeviceState string

// Device State constants
const (
	DeviceStateDOWN DeviceState = "DOWN"
	DeviceStateUP   DeviceState = "UP"
)

// Status represents the status of the request sent to the device manager.
type Status string

// LogLevel  represents the type of the OLT's LOG
type LogLevel int

const (
	// CRITICAL represents log level type of the OLT.
	CRITICAL LogLevel = iota
	// ERROR represents log level type of the OLT.
	ERROR
	// WARNING represents log level type of the OLT.
	WARNING
	// INFO represents log level type of the OLT.
	INFO
	// DEBUG represents log level type of the OLT.
	DEBUG
)
