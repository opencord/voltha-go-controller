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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	pc "voltha-go-controller/infra/pprofcontroller"

	"voltha-go-controller/database"
	db "voltha-go-controller/database"
	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/vpagent"
	"voltha-go-controller/voltha-go-controller/nbi"

	"voltha-go-controller/log"

	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/opencord/voltha-lib-go/v7/pkg/probe"
)

// VgcInfo structure
type VgcInfo struct {
	kvClient kvstore.Client
	Name     string
	Version  string
}

var vgcInfo = VgcInfo{Name: "VGC"}
var dbHandler *database.Database

func printBanner() {
	fmt.Println("##     ##  ######    ######  ")
	fmt.Println("##     ## ##    ##  ##    ## ")
	fmt.Println("##     ## ##        ##       ")
	fmt.Println("##     ## ##   #### ##       ")
	fmt.Println(" ##   ##  ##    ##  ##       ")
	fmt.Println("  ## ##   ##    ##  ##    ## ")
	fmt.Println("   ###     ######    ######  ")
}

func stop(ctx context.Context, kvClient kvstore.Client, vpa *vpagent.VPAgent) {
	// Cleanup - applies only if we had a kvClient
	if kvClient != nil {
		// Release all reservations
		if err := kvClient.ReleaseAllReservations(ctx); err != nil {
			logger.Infow(ctx, "fail-to-release-all-reservations", log.Fields{"error": err})
		}
		// Close the DB connection
		kvClient.Close(ctx)
	}
	//Closet voltha connection
	vpa.CloseConnectionToVoltha()
}

func newKVClient(ctx context.Context, storeType, address string, timeout int) (kvstore.Client, error) {
	logger.Infow(ctx, "kv-store-type", log.Fields{"store": storeType})
	switch storeType {
	case "redis":
		return kvstore.NewRedisClient(address, time.Duration(timeout), false)
	case "etcd":
		return kvstore.NewEtcdClient(ctx, address, time.Duration(timeout), log.ErrorLevel)
	}
	return nil, errors.New("unsupported-kv-store")
}

// waitUntilKVStoreReachableOrMaxTries will wait until it can connect to a KV store or until maxtries has been reached
func waitUntilKVStoreReachableOrMaxTries(ctx context.Context, config *VGCFlags) error {
	count := 0
	for {
		if !vgcInfo.kvClient.IsConnectionUp(ctx) {
			logger.Infow(ctx, "KV-store-unreachable", log.Fields{"KVStoreType": config.KVStoreType, "Address": config.KVStoreEndPoint})
			if config.ConnectionMaxRetries != -1 {
				if count >= config.ConnectionMaxRetries {
					logger.Errorw(ctx, "kv store unreachable", log.Fields{})
					return errors.New("kv store unreachable")
				}
			}
			count++
			//	Take a nap before retrying
			time.Sleep(time.Duration(config.ConnectionRetryDelay) * time.Second)
			logger.Infow(ctx, "retry-KV-store-connectivity", log.Fields{"retryCount": count,
				"maxRetries": config.ConnectionMaxRetries, "retryInterval": config.ConnectionRetryDelay})
		} else {
			break
		}
	}
	return nil
}

func main() {
	// Environment variables processing
	config := newVGCFlags()
	config.parseEnvironmentVariables()

	if config.Banner {
		printBanner()
	}
	// Create a context adding the status update channel
	p := &probe.Probe{}
	ctx = context.WithValue(context.Background(), probe.ProbeContextKey, p)

	pc.Init()

	// Setup logging for the program
	// Read the loglevel configured first
	// Setup default logger - applies for packages that do not have specific logger set
	var logLevel log.LevelLog
	var err error
	var dblogLevel string
	if logLevel, err = log.StringToLogLevel(config.LogLevel); err != nil {
		logLevel = log.DebugLevel
	}
	if err = log.SetDefaultLogger(ctx, int(logLevel), log.Fields{"instanceId": config.InstanceID}); err != nil {
		logger.With(ctx, log.Fields{"error": err}, "Cannot setup logging")
	}

	// Update all loggers (provisionned via init) with a common field
	if err = log.UpdateAllLoggers(log.Fields{"instanceId": config.InstanceID}); err != nil {
		logger.With(ctx, log.Fields{"error": err}, "Cannot setup logging")
	}
	log.SetAllLogLevel(int(logLevel))

	if vgcInfo.kvClient, err = newKVClient(ctx, config.KVStoreType, config.KVStoreEndPoint, config.KVStoreTimeout); err != nil {
		logger.Errorw(ctx, "KVClient Establishment Failure", log.Fields{"Reason": err})
	}

	if dbHandler, err = db.Initialize(ctx, config.KVStoreType, config.KVStoreEndPoint, config.KVStoreTimeout); err != nil {
		logger.Errorw(ctx, "unable-to-connect-to-db", log.Fields{"error": err})
		return
	}

	db.SetDatabase(dbHandler)
	logger.Infow(ctx, "verifying-KV-store-connectivity", log.Fields{"host": config.KVStoreHost,
		"port": config.KVStorePort, "retries": config.ConnectionMaxRetries,
		"retryInterval": config.ConnectionRetryDelay})

	err = waitUntilKVStoreReachableOrMaxTries(ctx, config)
	if err != nil {
		logger.Fatalw(ctx, "Unable-to-connect-to-KV-store", log.Fields{"KVStoreType": config.KVStoreType, "Address": config.KVStoreEndPoint})
	}

	logger.Info(ctx, "KV-store-reachable")
	//Read if log-level is stored in DB
	if dblogLevel, err = dbHandler.Get(ctx, db.GetKeyPath(db.LogLevelPath)); err == nil {
		logger.Infow(ctx, "Read log-level from db", log.Fields{"logLevel": logLevel})
		storedLogLevel, _ := log.StringToLogLevel(dblogLevel)
		log.SetAllLogLevel(int(storedLogLevel))
		log.SetDefaultLogLevel(int(storedLogLevel))
	}

	// Check if Data Migration is required
	// Migration has to be done before Initialzing the Kafka
	if app.CheckIfMigrationRequired(ctx) {
		logger.Debug(ctx, "Migration Initiated")
		app.InitiateDataMigration(ctx)
	}

	defer func() {
		err = log.CleanUp()
		if err != nil {
			logger.Errorw(ctx, "unable-to-flush-any-buffered-log-entries", log.Fields{"error": err})
		}
	}()

	// TODO: Wrap it up properly and monitor the KV store to check for faults

	/*
	 * Create and start the liveness and readiness container management probes. This
	 * is done in the main function so just in case the main starts multiple other
	 * objects there can be a single probe end point for the process.
	 */
	go p.ListenAndServe(ctx, config.ProbeEndPoint)

	app.GetApplication().ReadAllFromDb(ctx)
	app.GetApplication().InitStaticConfig()
	app.GetApplication().SetVendorID(config.VendorID)
	ofca := controller.NewController(ctx, app.GetApplication())
	controller.GetController().SetDeviceTableSyncDuration(config.DeviceSyncDuration)
	vpa, err1 := vpagent.NewVPAgent(&vpagent.VPAgent{
		VolthaAPIEndPoint:         config.VolthaAPIEndPoint,
		DeviceListRefreshInterval: time.Duration(config.DeviceListRefreshInterval) * time.Second,
		ConnectionMaxRetries:      config.ConnectionMaxRetries,
		ConnectionRetryDelay:      time.Duration(config.ConnectionRetryDelay) * time.Second,
		VPClientAgent:             ofca,
	})
	if err1 != nil {
		logger.Fatalw(ctx, "failed-to-create-vpagent",
			log.Fields{
				"error": err})
	}
	// starts go routine which verifies dhcp server connectivity for requests
	app.StartDhcpServerHandler()
	logger.Error(ctx, "Trigger Rest Server...")
	go nbi.RestStart()
	go vpa.Run(ctx)
	//FIXME: Need to enhance CLI to use in docker environment
	//go ProcessCli()
	//go handler.MsgHandler()
	//go app.StartCollector()
	waitForExit()
	app.StopTimer()
	stop(ctx, vgcInfo.kvClient, vpa)
}

func waitForExit() int {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	exitChannel := make(chan int)

	go func() {
		s := <-signalChannel
		switch s {
		case syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT:
			logger.Infow(ctx, "closing-signal-received", log.Fields{"signal": s})
			exitChannel <- 0
		default:
			logger.Infow(ctx, "unexpected-signal-received", log.Fields{"signal": s})
			exitChannel <- 1
		}
	}()

	code := <-exitChannel
	return code
}
