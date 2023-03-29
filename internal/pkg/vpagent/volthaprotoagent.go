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
	"sync"
	"time"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/holder"
	"voltha-go-controller/internal/pkg/intf"

	"voltha-go-controller/log"

	"github.com/opencord/voltha-lib-go/v7/pkg/probe"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/opencord/voltha-protos/v5/go/voltha"
	"google.golang.org/grpc"
)

var logger log.CLogger
var ctx = context.TODO()

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}

type vpaEvent byte
type vpaState byte

var db database.DBIntf

const (
	vpaEventStart = vpaEvent(iota)
	vpaEventVolthaConnected
	vpaEventVolthaDisconnected
	vpaEventError

	vpaStateConnected = vpaState(iota)
	vpaStateConnecting
	vpaStateDisconnected
)

var vpAgent *VPAgent

// VPAgent structure
type VPAgent struct {
	VPClientAgent             intf.IVPClientAgent
	clientMap                 map[string]intf.IVPClient
	packetInChannel           chan *ofp.PacketIn
	packetOutChannel          chan *ofp.PacketOut
	changeEventChannel        chan *ofp.ChangeEvent
	volthaClient              *holder.VolthaServiceClientHolder
	volthaConnection          *grpc.ClientConn
	events                    chan vpaEvent
	VolthaAPIEndPoint         string
	mapLock                   sync.Mutex
	DeviceListRefreshInterval time.Duration
	ConnectionRetryDelay      time.Duration
	ConnectionMaxRetries      int
}

// NewVPAgent is constructor for VPAgent
func NewVPAgent(config *VPAgent) (*VPAgent, error) {
	vpa := VPAgent{
		VolthaAPIEndPoint:         config.VolthaAPIEndPoint,
		DeviceListRefreshInterval: config.DeviceListRefreshInterval,
		ConnectionMaxRetries:      config.ConnectionMaxRetries,
		ConnectionRetryDelay:      config.ConnectionRetryDelay,
		VPClientAgent:             config.VPClientAgent,
		volthaClient:              &holder.VolthaServiceClientHolder{},
		packetInChannel:           make(chan *ofp.PacketIn),
		// customPacketIndChannel:    make(chan *voltha.CustomPacketIn),
		packetOutChannel:   make(chan *ofp.PacketOut),
		changeEventChannel: make(chan *ofp.ChangeEvent),
		// ofpCommandNotiChannel:     make(chan *voltha.OfpCmdRespNotification),
		// oltRebootNotiChannel:      make(chan *voltha.OltRebootNotification),
		clientMap: make(map[string]intf.IVPClient),
		events:    make(chan vpaEvent, 100),
	}

	if vpa.DeviceListRefreshInterval <= 0 {
		logger.Warnw(ctx, "device list refresh internal not valid, setting to default",
			log.Fields{
				"value":   vpa.DeviceListRefreshInterval.String(),
				"default": (10 * time.Second).String()})
		vpa.DeviceListRefreshInterval = 1 * time.Minute
	}

	if vpa.ConnectionRetryDelay <= 0 {
		logger.Warnw(ctx, "connection retry delay not value, setting to default",
			log.Fields{
				"value":   vpa.ConnectionRetryDelay.String(),
				"default": (3 * time.Second).String()})
		vpa.ConnectionRetryDelay = 3 * time.Second
	}

	if db == nil {
		db = database.GetDatabase()
	}
	vpAgent = &vpa
	return &vpa, nil
}

// GetVPAgent - returns vpAgent object
func GetVPAgent() *VPAgent {
	return vpAgent
}

// VolthaSvcClient for Voltha Svc client
func (vpa *VPAgent) VolthaSvcClient() voltha.VolthaServiceClient {
	return vpa.volthaClient.Get()
}

// Run - make the initial connection to voltha and kicks off io streams
func (vpa *VPAgent) Run(ctx context.Context) {
	logger.Debugw(ctx, "Starting GRPC - VOLTHA client",
		log.Fields{
			"voltha-endpoint": vpa.VolthaAPIEndPoint})

	// If the context contains a k8s probe then register services
	p := probe.GetProbeFromContext(ctx)
	if p != nil {
		p.RegisterService(ctx, "voltha")
	}

	vpa.events <- vpaEventStart

	/*
	 * Two sub-contexts are created here for different purposes so we can
	 * control the lifecyle of processing loops differently.
	 *
	 * volthaCtx -  controls those processes that rely on the GRPC
	 *              GRPCconnection to voltha and will be restarted when the
	 *              GRPC connection is interrupted.
	 * hdlCtx    -  controls those processes that listen to channels and
	 *              process each message. these will likely never be
	 *              stopped until the vpagent is stopped.
	 */
	var volthaCtx, hdlCtx context.Context
	var volthaDone, hdlDone func()
	state := vpaStateDisconnected

	for {
		select {
		case <-ctx.Done():
			logger.Errorw(ctx, "Context Done", log.Fields{"Context": ctx})
			if volthaDone != nil {
				volthaDone()
			}
			if hdlDone != nil {
				hdlDone()
			}
			return
		case event := <-vpa.events:
			switch event {
			case vpaEventStart:
				logger.Debug(ctx, "vpagent-voltha-start-event")

				// Start the loops that process messages
				hdlCtx, hdlDone = context.WithCancel(context.Background())
				go vpa.handlePacketsIn(hdlCtx)
				go vpa.handleChangeEvents(hdlCtx)

				// Kick off process to attempt to establish
				// connection to voltha
				state = vpaStateConnecting
				go func() {
					if err := vpa.establishConnectionToVoltha(hdlCtx, p); err != nil {
						logger.Fatalw(ctx, "voltha-connection-failed", log.Fields{"error": err})
					}
				}()

			case vpaEventVolthaConnected:
				logger.Debug(ctx, "vpagent-voltha-connect-event")

				// Start the loops that poll from voltha
				if state != vpaStateConnected {
					state = vpaStateConnected
					volthaCtx, volthaDone = context.WithCancel(context.Background())
					go vpa.receiveChangeEvents(volthaCtx)
					go vpa.receivePacketsIn(volthaCtx)
					go vpa.streamPacketOut(volthaCtx)
					go vpa.synchronizeDeviceList(volthaCtx)
				}

			case vpaEventVolthaDisconnected:
				if p != nil {
					p.UpdateStatus(ctx, "voltha", probe.ServiceStatusNotReady)
				}
				logger.Debug(ctx, "vpagent-voltha-disconnect-event")
				if state == vpaStateConnected {
					state = vpaStateDisconnected
					vpa.volthaClient.Clear()
					volthaDone()
					volthaDone = nil
				}
				if state != vpaStateConnecting {
					state = vpaStateConnecting
					go func() {
						hdlCtx, hdlDone = context.WithCancel(context.Background())
						if err := vpa.establishConnectionToVoltha(hdlCtx, p); err != nil {
							logger.Fatalw(ctx, "voltha-connection-failed", log.Fields{"error": err})
						}
					}()
				}

			case vpaEventError:
				logger.Debug(ctx, "vpagent-error-event")
			default:
				logger.Fatalw(ctx, "vpagent-unknown-event",
					log.Fields{"event": event})
			}
		}
	}
}
