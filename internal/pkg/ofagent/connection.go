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

package ofagent

import (
	"context"
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
	"github.com/opencord/voltha-lib-go/v7/pkg/probe"
	"github.com/opencord/voltha-protos/v5/go/voltha"
	"google.golang.org/grpc"
)

func (ofa *OFAgent) establishConnectionToVoltha(ctx context.Context, p *probe.Probe) error {
	if p != nil {
		p.UpdateStatus(ctx, "voltha", probe.ServiceStatusPreparing)
	}

	if ofa.volthaConnection != nil {
		ofa.volthaConnection.Close()
	}

	ofa.volthaConnection = nil
	ofa.volthaClient.Clear()
	try := 1
	for ofa.ConnectionMaxRetries == 0 || try < ofa.ConnectionMaxRetries {
		conn, err := grpc.Dial(ofa.VolthaAPIEndPoint, grpc.WithInsecure(), grpc.WithMaxMsgSize(17455678))
		if err == nil {
			svc := voltha.NewVolthaServiceClient(conn)
			if svc != nil {
				if _, err = svc.GetVoltha(context.Background(), &empty.Empty{}); err == nil {
					logger.Debugw(ctx, "Established connection to Voltha",
						log.Fields{
							"VolthaApiEndPoint": ofa.VolthaAPIEndPoint,
						})
					ofa.volthaConnection = conn
					ofa.volthaClient.Set(svc)
					if p != nil {
						p.UpdateStatus(ctx, "voltha", probe.ServiceStatusRunning)
					}
					ofa.events <- ofaEventVolthaConnected
					return nil
				}
			}
		}
		logger.Warnw(ctx, "Failed to connect to voltha",
			log.Fields{
				"VolthaApiEndPoint": ofa.VolthaAPIEndPoint,
				"error":             err.Error(),
			})
		if ofa.ConnectionMaxRetries == 0 || try < ofa.ConnectionMaxRetries {
			if ofa.ConnectionMaxRetries != 0 {
				try++
			}
			time.Sleep(ofa.ConnectionRetryDelay)
		}
	}
	if p != nil {
		p.UpdateStatus(ctx, "voltha", probe.ServiceStatusFailed)
	}
	return errors.New("failed-to-connect-to-voltha")
}

// CloseConnectionToVoltha closes the grpc connection to VOLTHA
func (ofa *OFAgent) CloseConnectionToVoltha() {
	//Close the grpc connection to voltha
	logger.Debug(ctx, "Closing voltha grpc connection")
	ofa.volthaConnection.Close()
}
