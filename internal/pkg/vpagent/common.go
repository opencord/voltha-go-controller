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

// Package vpagent Common Logger initialization
package vpagent

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsConnCanceled returns true, if error is from a closed gRPC connection.
// ref. https://github.com/grpc/grpc-go/pull/1854
func isConnCanceled(err error) bool {
	if err == nil {
		return false
	}

	s, ok := status.FromError(err)
	if ok {
		switch {
		case s.Code() == codes.Canceled || s.Message() == "transport is closing":
			// >= gRPC v1.23.x
			// connection is canceled or server has already closed the connection
			return true
		case s.Message() == "all SubConns are in TransientFailure":
			return true
		case s.Code() == codes.Unavailable || s.Message() == "error reading from server: EOF":
			// >= gRPC v1.76.x
			// connection is unavailable or server has already closed the connection
			return true
		case s.Code() == codes.Internal || s.Code() == codes.DeadlineExceeded:
			// connection is interrupted
			return true
		}
	}

	// >= gRPC v1.10.x
	if err == context.Canceled {
		return true
	}

	// <= gRPC v1.7.x returns 'errors.New("grpc: the client connection is closing")'
	return strings.Contains(err.Error(), "grpc: the client connection is closing")
}
