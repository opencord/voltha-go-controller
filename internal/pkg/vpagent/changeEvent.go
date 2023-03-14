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
	"io"

	"voltha-go-controller/log"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
)

func (vpa *VPAgent) receiveChangeEvents(ctx context.Context) {
	logger.Debug(ctx, "receive-change-events-started")
	// If we exit, assume disconnected
	defer func() {
		vpa.events <- vpaEventVolthaDisconnected
		logger.Debug(ctx, "receive-change-events-finished")
	}()
	if vpa.volthaClient == nil {
		logger.Error(ctx, "no-voltha-connection")
		return
	}
	opt := grpc.EmptyCallOption{}
	streamCtx, streamDone := context.WithCancel(context.Background())
	defer streamDone()
	vServiceClient := vpa.volthaClient.Get()
	if vServiceClient == nil {
		logger.Error(ctx, "Failed to get Voltha Service Client")
		return
	}

	stream, err := vServiceClient.ReceiveChangeEvents(streamCtx, &empty.Empty{}, opt)
	if err != nil {
		logger.Errorw(ctx, "Unable to establish Receive Change Event Stream",
			log.Fields{"error": err})
		return
	}

top:
	for {
		select {
		case <-ctx.Done():
			logger.Errorw(ctx, "Context Done", log.Fields{"Context": ctx})
			break top
		default:
			ce, err := stream.Recv()
			if err == io.EOF {
				//logger.Infow(ctx, "EOF for receiveChangeEvents stream, reconnecting", log.Fields{"err": err})
				stream, err = vServiceClient.ReceiveChangeEvents(streamCtx, &empty.Empty{}, opt)
				if err != nil {
					logger.Errorw(ctx, "Unable to establish Receive Change Event Stream",
						log.Fields{"error": err})
					return
				}
				continue
			}
			if isConnCanceled(err) {
				logger.Errorw(ctx, "error receiving change event",
					log.Fields{"error": err})
				break top
			} else if err != nil {
				logger.Infow(ctx, "Ignoring unhandled error", log.Fields{"err": err})
				continue
			}
			vpa.changeEventChannel <- ce
			logger.Debug(ctx, "receive-change-event-queued")
		}
	}
}

func (vpa *VPAgent) handleChangeEvents(ctx context.Context) {
	logger.Debug(ctx, "handle-change-event-started")

top:
	for {
		select {
		case <-ctx.Done():
			logger.Errorw(ctx, "Context Done", log.Fields{"Context": ctx})
			break top
		case changeEvent := <-vpa.changeEventChannel:
			logger.Debugw(ctx, "Change Event", log.Fields{"Device": changeEvent.Id})
			if vpc := vpa.getVPClient(changeEvent.Id); vpc != nil {
				if err := vpc.ChangeEvent(changeEvent); err != nil {
					logger.Errorw(ctx, "error handling Change Event", log.Fields{"Error": err, "Device": changeEvent.Id})
				}
			}
		}
	}

	logger.Debug(ctx, "handle-change-event-finsihed")
}
