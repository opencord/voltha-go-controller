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

// Package errorcodes provides constants that are commonly used by RWcore and adapters.
package errorcodes

import (
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NBErrorCode represents the error code for the error.
type NBErrorCode int

const (
	// VolthaErrorMessageFormat represents the format in which the Voltha accepts the errors.
	VolthaErrorMessageFormat = "code = %d, desc = %s"
)

// List of error messages returned to Voltha.
var (
	// ErrUnimplementedRPC is returned when the RPC is not implemented
	ErrUnimplementedRPC = status.Errorf(codes.Unimplemented, VolthaErrorMessageFormat, UnsupportedOperation, "Operation not implemented")
	// ErrOperationNotSupported is returned when the operation is not supported
	ErrOperationNotSupported = status.Errorf(codes.Unimplemented, VolthaErrorMessageFormat, UnsupportedOperation, "Operation not supported")

	// ErrFailedRequest is returned when the component fails to send any request to other component
	ErrFailedRequest = status.Errorf(codes.Internal, VolthaErrorMessageFormat, UnsuccessfulOperation, "Failed to send request")

	// ErrFailedToEncodeConfig is returned when the data json marshal fails
	ErrFailedToEncodeConfig = status.Errorf(codes.Internal, VolthaErrorMessageFormat, MessageEncodeFailed, "Failed to encode data")
	// ErrFailedToDecodeConfig is returned when the data json unmarshal fails
	ErrFailedToDecodeConfig = status.Errorf(codes.Internal, VolthaErrorMessageFormat, MessageDecodeFailed, "Failed to decode data")

	// ErrFailedToUpdateDB is returned when update of data in KV store fails
	ErrFailedToUpdateDB = status.Errorf(codes.Internal, VolthaErrorMessageFormat, DBOperationFailed, "Failed to update DB")
	// ErrFailedToGetFromDB is returned when get data from KV store fails
	ErrFailedToGetFromDB = status.Errorf(codes.Internal, VolthaErrorMessageFormat, DBOperationFailed, "Failed to fetch from DB")
	// ErrFailedToDeleteFromDB is returned when delete data from KV store fails
	ErrFailedToDeleteFromDB = status.Errorf(codes.Internal, VolthaErrorMessageFormat, DBOperationFailed, "Failed to delete from DB")

	// ErrDeviceNotFound is returned when the handler for the device is not present in VOLTHA
	ErrDeviceNotFound = status.Errorf(codes.NotFound, VolthaErrorMessageFormat, ResourceNotFound, "Device not found")
	// ErrDeviceNotReachable is returned when the connection between adapter and agent is broken
	ErrDeviceNotReachable = status.Errorf(codes.Unavailable, VolthaErrorMessageFormat, DeviceUnreachable, "Device is not reachable")
	// ErrWrongDevice is returned when the received request has wrong device (parent/child)
	ErrWrongDevice = status.Errorf(codes.FailedPrecondition, VolthaErrorMessageFormat, PrerequisiteNotMet, "Wrong device in request")
	// ErrDeviceNotEnabledAndUp is returned when the state of the device is neither enabled nor active
	ErrDeviceNotEnabledAndUp = status.Errorf(codes.FailedPrecondition, VolthaErrorMessageFormat, ResourceInImproperState, "Device is not enabled and up")
	// ErrDeviceDeleted is returned when the state of the device is DELETED
	ErrDeviceDeleted = status.Errorf(codes.FailedPrecondition, VolthaErrorMessageFormat, ResourceInImproperState, "Device is deleted")

	// ErrPortNotFound is returned when the port is not present in VOLTHA
	ErrPortNotFound = status.Errorf(codes.NotFound, VolthaErrorMessageFormat, ResourceNotFound, "Port not found")
	// ErrPortIsInInvalidState is returned when the port is in an invalid state
	ErrPortIsInInvalidState = status.Errorf(codes.Internal, VolthaErrorMessageFormat, ResourceInImproperState, "Port is in an invalid state")

	// ErrInvalidParamInRequest is returned when the request contains invalid configuration
	ErrInvalidParamInRequest = status.Errorf(codes.InvalidArgument, VolthaErrorMessageFormat, InvalidArgument, "Received invalid configuration in request")

	// ErrImageNotRegistered is returned when the image is not registered
	ErrImageNotRegistered = status.Errorf(codes.FailedPrecondition, VolthaErrorMessageFormat, PrerequisiteNotMet, "Image is not registered")
	// ErrImageDownloadInProgress is returned when the image download is in progress
	ErrImageDownloadInProgress = status.Errorf(codes.FailedPrecondition, VolthaErrorMessageFormat, MethodNotAllowed, "Image download is in progress")

	// ErrServiceNotFound is returned when the Service is not present in VOLTHA
	ErrServiceNotFound = status.Errorf(codes.NotFound, VolthaErrorMessageFormat, ResourceNotFound, "Service not found")
)

// ConvertToVolthaErrorFormat converts the error to Voltha error format
func ConvertToVolthaErrorFormat(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	return status.Errorf(st.Code(), VolthaErrorMessageFormat, GrpcToVolthaErrorCodeMap[st.Code()], st.Message())
}

const (
	//Success is returned when there is no error - 0
	Success NBErrorCode = iota
	//InvalidURL is returned when the URL specified for the request is invalid - 1
	InvalidURL
	//MissingArgument is returned when the mandatory/conditionally mandatory argument is missing - 2
	MissingArgument
	//RequestTimeout is returned when the request timed out. - 3
	RequestTimeout
	//ResourceAlreadyExists is returned when the resource already exists and create for the same is not allowed - 4
	ResourceAlreadyExists
	//ResourceInImproperState is returned when the resource is in improper state to process the request. - 5
	ResourceInImproperState
	//DeviceUnreachable is returned when the device is not reachable - 6
	DeviceUnreachable
	//OperationAlreadyInProgress is returned when the requested operation is already in progress - 7
	OperationAlreadyInProgress
	//InvalidConfig is returned when the configuration provided is invalid - 8
	InvalidConfig
	//ResourceNotFound is returned when the resource is not found - 9
	ResourceNotFound
	//MethodNotAllowed is returned when the requested method is not allowed - 10
	MethodNotAllowed
	//ResourceInUse is returned when the resource is in use, the delete of the resource is not allowed when in use - 11
	ResourceInUse
	//JobIDNotFound is returned when the Job ID not found - 12
	JobIDNotFound
	//JobIDAlreadyInUse is returned when the Job ID already in use - 13
	JobIDAlreadyInUse
	//PeerUnreachable is returned when the peer is unreachable -14
	PeerUnreachable
	//InvalidPatchOperation is returned when the parameter(s) mentioned in the patch operation are invalid - 15
	InvalidPatchOperation
	//OLTUnreachable is returned when the OLT is not reachable - 16
	OLTUnreachable
	//PrerequisiteNotMet is returned when the required prerequisite is not met to execute the requested procedure - 17
	PrerequisiteNotMet
	//MessageEncodeFailed is returned when Message encoding failed - 18
	MessageEncodeFailed
	//MessageDecodeFailed is returned when Message decoding failed - 19
	MessageDecodeFailed
	//ONTInternalError is returned when Internal error is reported by the ONT - 20
	ONTInternalError
	//OLTInternalError is returned when Internal error is reported by the OLT - 21
	OLTInternalError
	//VolthaInternalError is returned when Internal error occurred at Voltha - 22
	VolthaInternalError
	//ConfigMismatch is returned when the configuration does not match - 23
	ConfigMismatch
	//DBOperationFailed is returned when the database operation failed for the key - 24
	DBOperationFailed
	//ResourceLimitExceeded is returned when the resource limit exceeded the allowed limit - 25
	ResourceLimitExceeded
	//UndefinedEnv is returned when the required environment variable is not defined - 26
	UndefinedEnv
	//InvalidArgument is returned when the argument provided is invalid - 27
	InvalidArgument
	//InvalidPayload is returned when the configuration payload is invalid - 28
	InvalidPayload
	//DuplicateKey is returned when the duplicate entry for the key - 29
	DuplicateKey
	//DuplicateValue is returned when the duplicate entry for the value - 30
	DuplicateValue
	//UnsupportedOperation is returned when the request operation is not supported - 31
	UnsupportedOperation
	//UserUnauthorized is returned when the user is unauthorized to perform the requested operation - 32
	UserUnauthorized
	//LiveKPISubscriptionExists is returned when the live KPI subscription exists already for the requested resource - 33
	LiveKPISubscriptionExists
	//UnsuccessfulOperation is returned when the requested operation is unsuccessful - 34
	UnsuccessfulOperation
	//ResourceInDisabledStateAlready is returned when the resource is in disabled state already - 35
	ResourceInDisabledStateAlready
	//ResourceInEnabledStateAlready is returned when the resource is in enabled state already - 36
	ResourceInEnabledStateAlready
	//ResourceNotDiscoveredYet is returned when the resource is not discovered yet - 37
	ResourceNotDiscoveredYet
	//HighDiskUtilization is returned when the disk utilization is high, consider the disk cleanup. - 38
	HighDiskUtilization
	//KafkaError is returned when there is a kafka error - 39
	KafkaError
	//ResourceBusy is returned when the component/resource is busy. - 40
	ResourceBusy
	// UnsupportedParameter is returned when un supported field is provided in request. -41
	UnsupportedParameter
	//JobIDAlreadyExists is returned when the Job ID is already there in DB. -42
	JobIDAlreadyExists
	//LiveKPISubscriptionNotFound is returned when the live KPI subscription not found for the requested resource. -42
	LiveKPISubscriptionNotFound
	// HostUnreachable is returned when failed to establish the SFTP connection. -44
	HostUnreachable
	// DHCPServerUnreachable is returned when dhcp server is unreachable. -45
	DHCPServerUnreachable
	// SessionExpired is returned when user session is expired/timeout - 46
	SessionExpired
	// AccessDenied is returned when user operation is forbidden - 47
	AccessDenied
	// PasswordUpdateRequired is returned when password for the user is about to expire - 48
	PasswordUpdateRequired
	// InvalidMessageHeader is returned when token in security request is invalid/nil - 49
	InvalidMessageHeader
	// UserAccountBlocked is returned when user account gets blocked after multiple invalid attempts - 50
	UserAccountBlocked
	// UserAccountExpired is returned when user account gets expired - 51
	UserAccountExpired
	// UserAccountDormant is returned when user account gets dormant - 52
	UserAccountDormant
	// InvalidCredentials is returned when credentials are invalid in login request - 53
	InvalidCredentials
	// ConcurrentAccessFromMultipleIPs when multiple sessions gets established from same ip - 54
	ConcurrentAccessFromMultipleIPs
	// KPIThresholdCrossed when KPI threshold is crossed - 55
	KPIThresholdCrossed
	// ONTUnreachable is returned when the ONT is not reachable - 56
	ONTUnreachable
	// ResourceUnreachable is returned when the resource is not reachable -57
	ResourceUnreachable
	// ONTProcessingError is returned when onu returns processing error for omci message - 58
	ONTProcessingError
	// ONTResourceBusy is returned when onu returns device busy error for omci message - 59
	ONTResourceBusy
	// ONTMEInstanceExists is returned when onu returns OMCI ME instance exists error for omci message - 60
	ONTMEInstanceExists
	// ONTUnknownMEInstance is returned when onu returns OMCI ME Unknown Instance error for omci message - 61
	ONTUnknownMEInstance
	// JoinUnsuccessful is returned when an IGMP Join request is unsuccessful - 62
	JoinUnsuccessful
	// QueryExpired is returned when there is no response to IGMP Queries from the controller - 63
	QueryExpired
	// AvailableBwValidationErr is returned when requested bandwidth is not available on the pon port - 64
	AvailableBwValidationErr
)

// NBErrorCodeMap converts error code to error description string
var NBErrorCodeMap = map[NBErrorCode]string{
	Success:                         "Success",
	InvalidURL:                      "INVALID_URL",
	RequestTimeout:                  "REQUEST_TIMEOUT",
	MissingArgument:                 "MISSING_ARGUMENT",
	ResourceAlreadyExists:           "RESOURCE_ALREADY_EXISTS",
	ResourceInImproperState:         "RESOURCE_IN_IMPROPER_STATE",
	DeviceUnreachable:               "DEVICE_UNREACHABLE",
	OperationAlreadyInProgress:      "OPERATION_ALREADY_IN_PROGRESS",
	InvalidConfig:                   "INVALID_CONFIG",
	ResourceNotFound:                "RESOURCE_NOT_FOUND",
	MethodNotAllowed:                "METHOD_NOT_ALLOWED",
	ResourceInUse:                   "RESOURCE_IN_USE",
	JobIDNotFound:                   "JOB_ID_NOT_FOUND",
	JobIDAlreadyInUse:               "JOB_ID_ALREADY_IN_USE",
	PeerUnreachable:                 "PEER_UNREACHABLE",
	InvalidPatchOperation:           "INVALID_PATCH_OPERATION",
	OLTUnreachable:                  "OLT_UNREACHABLE",
	PrerequisiteNotMet:              "PREREQUISITE_NOT_MET",
	MessageEncodeFailed:             "MESSAGE_ENCODE_FAILED",
	MessageDecodeFailed:             "MESSAGE_DECODE_FAILED",
	ONTInternalError:                "ONT_INTERNAL_ERROR",
	OLTInternalError:                "OLT_INTERNAL_ERROR",
	VolthaInternalError:             "Voltha_INTERNAL_ERROR",
	ConfigMismatch:                  "CONFIG_MISMATCH",
	DBOperationFailed:               "DB_OPERATION_FAILED",
	ResourceLimitExceeded:           "RESOURCE_LIMIT_EXCEEDED",
	UndefinedEnv:                    "UNDEFINED_ENV",
	InvalidArgument:                 "INVALID_ARGUMENT",
	InvalidPayload:                  "INVALID_PAYLOAD",
	DuplicateKey:                    "DUPLICATE_KEY",
	DuplicateValue:                  "DUPLICATE_VALUE",
	UnsupportedOperation:            "UNSUPPORTED_OPERATION",
	UserUnauthorized:                "USER_UNAUTHORIZED",
	LiveKPISubscriptionExists:       "LIVE_KPI_SUBSCRIPTION_EXISTS",
	UnsuccessfulOperation:           "UNSUCCESSFUL_OPERATION",
	ResourceInDisabledStateAlready:  "RESOURCE_IN_DISABLED_STATE_ALREADY",
	ResourceInEnabledStateAlready:   "RESOURCE_IN_ENABLED_STATE_ALREADY",
	ResourceNotDiscoveredYet:        "RESOURCE_NOT_DISCOVERED_YET",
	HighDiskUtilization:             "HIGH_DISK_UTILIZATION",
	KafkaError:                      "KAFKA_ERROR",
	LiveKPISubscriptionNotFound:     "LIVE_KPI_SUBSCRIPTION_NOT_FOUND",
	ResourceBusy:                    "RESOURCE_BUSY",
	UnsupportedParameter:            "UNSUPPORTED_PARAMETER",
	JobIDAlreadyExists:              "JOB_ID_ALREADY_EXISTS",
	HostUnreachable:                 "HOST_UNREACHABLE",
	DHCPServerUnreachable:           "DHCP_SERVER_UNREACHABLE",
	InvalidMessageHeader:            "INVALID_MESSAGE_HEADER",
	SessionExpired:                  "SESSION_EXPIRED",
	AccessDenied:                    "ACCESS_DENIED",
	PasswordUpdateRequired:          "PASSWORD_UPDATE_REQUIRED",
	InvalidCredentials:              "INVALID_CREDENTIALS",
	UserAccountBlocked:              "USER_ACCOUNT_BLOCKED",
	UserAccountExpired:              "USER_ACCOUNT_EXPIRED",
	ConcurrentAccessFromMultipleIPs: "CONCURRENT_ACCESS_FROM_MULTIPLE_IPS",
	KPIThresholdCrossed:             "KPI_THRESHOLD_CROSSED",
	ONTUnreachable:                  "ONT_UNREACHABLE",
	ONTProcessingError:              "ONT_PROCESSING_ERROR",
	ONTResourceBusy:                 "ONT_RESOURCE_BUSY",
	ONTMEInstanceExists:             "ONT_ME_INSTANCE_ALREADY_EXISTS",
	ONTUnknownMEInstance:            "ONT_UNKNOWN_ME_INSTANCE",
	JoinUnsuccessful:                "JOIN_UNSUCCESSFUL",
	QueryExpired:                    "QUERY_EXPIRED",
}

// GrpcToVolthaErrorCodeMap contains mapping of grpc error code coming from OpenOLT-Agent to Voltha error codes.
var GrpcToVolthaErrorCodeMap = map[codes.Code]NBErrorCode{
	codes.OK:                 Success,
	codes.Canceled:           UnsuccessfulOperation,
	codes.Unknown:            OLTInternalError,
	codes.InvalidArgument:    InvalidArgument,
	codes.DeadlineExceeded:   RequestTimeout,
	codes.NotFound:           ResourceNotFound,
	codes.AlreadyExists:      ResourceAlreadyExists,
	codes.PermissionDenied:   UserUnauthorized,
	codes.ResourceExhausted:  ResourceLimitExceeded,
	codes.FailedPrecondition: PrerequisiteNotMet,
	codes.Aborted:            UnsuccessfulOperation,
	codes.OutOfRange:         InvalidArgument,
	codes.Unimplemented:      UnsupportedOperation,
	codes.Internal:           OLTInternalError,
	codes.Unavailable:        ResourceBusy,
	codes.DataLoss:           OLTInternalError,
	codes.Unauthenticated:    UserUnauthorized,
}

// HTTPStatusCodeToVolthaErrorCodeMap contains mapping of http status code coming from VGC to Voltha error codes.
var HTTPStatusCodeToVolthaErrorCodeMap = map[int]NBErrorCode{
	http.StatusOK:                  Success,
	http.StatusCreated:             Success,
	http.StatusAccepted:            Success,
	http.StatusBadRequest:          InvalidPayload,
	http.StatusConflict:            ResourceInImproperState,
	http.StatusInternalServerError: VolthaInternalError,
}

// GetErrorInfo - parses the error details from err structure response from voltha
// Return statusCode (uint32) - Error code [0 - Success]
// status Msg (string) - Error Msg
func GetErrorInfo(err error) (uint32, string) {
	var statusCode uint32
	var statusMsg string
	if status, _ := status.FromError(err); status != nil {
		statusCode = uint32(status.Code())
		statusMsg = status.Message()
	} else {
		statusCode = 0
	}
	return statusCode, statusMsg
}
