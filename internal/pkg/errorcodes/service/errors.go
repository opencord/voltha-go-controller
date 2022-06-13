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

// Package service provides constants.
package service

const (
	errorCodeStartRange = 1000
)

const (
	// VolthaErrorMessageFormat represents the format in which the Voltha accepts the errors.
	VolthaErrorMessageFormat = "code = %d, desc = %s"
)

// ErrorCode is Enum of error type
type ErrorCode int

//ErrorAction is Enum for error action
type ErrorAction int

const (
	//ErrOk is returned when request is successful
	ErrOk ErrorCode = 0
	//ErrInProgress is returned when operation is in progress
	ErrInProgress ErrorCode = iota + errorCodeStartRange
	//ErrInvalidParm is returned when parameter is wrong
	ErrInvalidParm
	//ErrResourceUnavailable is returned when no free resources are available
	ErrResourceUnavailable
	//ErrAlreadyExists is returned when entry already exists
	ErrAlreadyExists
	//ErrNotExists is returned when entry does not exists
	ErrNotExists
	//ErrInvalidOperation is returned when invalid operation is performed
	ErrInvalidOperation
	//ErrDeviceNotConnected is returned when there is no connection with the target system
	ErrDeviceNotConnected
	//ErrTimeout is returned when operation times out
	ErrTimeout
	//ErrResourceBusy is returned when resource is busy
	ErrResourceBusy
	//ErrInternal is returned when Errors happened internally
	ErrInternal
	//ErrIo is returned when there is I/O error
	ErrIo
	//ErrMandatoryParmIsMissing is returned when mandatory parameter is missing
	ErrMandatoryParmIsMissing
	//ErrBadState is returned when object is in bad state
	ErrBadState
	//ErrOnuInternal is returned when ONT internal failure occurs
	ErrOnuInternal
	//ErrElanNotCreated is returned when ELAN is not created
	ErrElanNotCreated
	//ErrOltInternal is returned when OLT internal failure occurs
	ErrOltInternal
)

//ErrorCodeMap converts error code to error description string
var ErrorCodeMap = map[ErrorCode]string{
	ErrOk:                     "Success",
	ErrInProgress:             "Operation is in progress",
	ErrInvalidParm:            "Invalid parameter",
	ErrResourceUnavailable:    "No free resource available",
	ErrAlreadyExists:          "Entry already exists",
	ErrNotExists:              "Entry does not exists",
	ErrInvalidOperation:       "Invalid Operation",
	ErrDeviceNotConnected:     "No connection with the target system",
	ErrTimeout:                "Operation timed out",
	ErrResourceBusy:           "Resource Busy",
	ErrInternal:               "Internal Error",
	ErrIo:                     "I/O Error",
	ErrMandatoryParmIsMissing: "Mandatory parameter is missing",
	ErrBadState:               "Object is in bad state",
	ErrOnuInternal:            "ONT internal error",
	ErrElanNotCreated:         "ELAN not created",
	ErrOltInternal:            "OLT internal error",
}

const (
	//Retry is returned if subservice reactivation is required
	Retry ErrorAction = iota
	//Quiet is returned if no action has to be taken
	Quiet
	//Deactivate is returned if subservice has to be deactivated
	Deactivate
	//Invalid is returned when invalid error is received from vgc
	Invalid
)

//RetryErrorCodeMap consists of errors that requires service activation retry
var RetryErrorCodeMap = map[ErrorCode]ErrorAction{
	ErrOk:                     Quiet,
	ErrInProgress:             Deactivate,
	ErrInvalidParm:            Deactivate,
	ErrResourceUnavailable:    Deactivate,
	ErrAlreadyExists:          Quiet,
	ErrNotExists:              Quiet,
	ErrInvalidOperation:       Deactivate,
	ErrDeviceNotConnected:     Quiet,
	ErrTimeout:                Retry,
	ErrResourceBusy:           Retry,
	ErrInternal:               Deactivate,
	ErrIo:                     Retry,
	ErrMandatoryParmIsMissing: Deactivate,
	ErrBadState:               Deactivate,
	ErrOnuInternal:            Retry,
	ErrElanNotCreated:         Retry,
	ErrOltInternal:            Deactivate,
}
