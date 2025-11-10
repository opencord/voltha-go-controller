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

package vpagent

import (
	"context"
	"errors"
	"time"

	"voltha-go-controller/log"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/opencord/voltha-protos/v5/go/voltha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GrpcMaxSize Max size of grpc message
const GrpcMaxSize int = 17455678

func (vpa *VPAgent) establishConnectionToVoltha(ctx context.Context) error {
	if vpa.volthaConnection != nil {
		_ = vpa.volthaConnection.Close()
	}

	vpa.volthaConnection = nil
	vpa.volthaClient.Clear()
	try := 1
	for vpa.ConnectionMaxRetries == 0 || try < vpa.ConnectionMaxRetries {
		conn, err := grpc.NewClient(vpa.VolthaAPIEndPoint, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(GrpcMaxSize)))
		if err == nil {
			svc := voltha.NewVolthaServiceClient(conn)
			if svc != nil {
				if _, err = svc.GetVoltha(context.Background(), &empty.Empty{}); err == nil {
					logger.Debugw(ctx, "Established connection to Voltha",
						log.Fields{
							"VolthaApiEndPoint": vpa.VolthaAPIEndPoint,
						})
					vpa.volthaConnection = conn
					vpa.volthaClient.Set(svc)
					vpa.events <- vpaEventVolthaConnected
					return nil
				}
			}
		}
		logger.Errorw(ctx, "Failed to connect to voltha",
			log.Fields{
				"VolthaApiEndPoint": vpa.VolthaAPIEndPoint,
				"error":             err.Error(),
			})
		if vpa.ConnectionMaxRetries == 0 || try < vpa.ConnectionMaxRetries {
			if vpa.ConnectionMaxRetries != 0 {
				try++
			}
			time.Sleep(vpa.ConnectionRetryDelay)
		}
	}
	return errors.New("failed-to-connect-to-voltha")
}

// CloseConnectionToVoltha closes the grpc connection to VOLTHA
func (vpa *VPAgent) CloseConnectionToVoltha() {
	// Close the grpc connection to voltha
	logger.Debug(ctx, "Closing voltha grpc connection")
	_ = vpa.volthaConnection.Close()
}
