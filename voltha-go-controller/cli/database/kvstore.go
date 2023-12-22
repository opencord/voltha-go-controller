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

package database

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// Background returns a non-nil, empty Context. It is never canceled, has no values
// and has no deadline. It is typically used by the main function initialization,
// tests and as the top-level Context for incoming requests.
var ctx = context.Background()

const redisSentinelPort int = 26379

// Database structure
type Database struct {
	kvc       Client
	storeType string
	address   string
	//timeout   int
}

// Client represents the set of APIs a KV Client must implement
type Client interface {
	GetAll(interface{}) (map[string]*Data, error)
	Get(interface{}, interface{}) (*Data, error)
}

// The singleton object that represents the database module
var db Database

// RedisClient represents the Redis KV store client
type RedisClient struct {
	redisClient *redis.Client /* Redis client object*/
}

// Init initialize the KV store.
func Init(storeType string, address string, timeout int) error {
	var err error
	db.address = address
	db.storeType = storeType
	switch storeType {
	case "redis":
		db.kvc, err = NewRedisClient(address, int(timeout))
		return err
	}
	return nil
}

// NewRedisClient create a new redis client for vgc ctl.
func NewRedisClient(address string, timeout int) (*RedisClient, error) {
	var redClient *redis.Client
	duration := time.Duration(timeout) * time.Second
	split := strings.Split(address, ":")
	port, err := strconv.Atoi(split[1])
	if err != nil {
		//fmt.Errorf("Wrong Address details were passed")
		return nil, err
	}

	/* We are initiating the redis HA client incase of redis sentinel port(26379) is configured*/
	if port == redisSentinelPort {
		redClient = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    "mymaster",
			SentinelAddrs: []string{address},
			Password:      "", // no password set
			DB:            0,  // use default DB
			DialTimeout:   duration,
			ReadTimeout:   duration,
			WriteTimeout:  duration,
			PoolTimeout:   duration,
			IdleTimeout:   duration,
			MaxRetries:    10,
			PoolSize:      10,
		})
	} else {
		/* We are initiating the single redis client incase of standard redis port is configured */
		redClient = redis.NewClient(&redis.Options{
			Addr:     address,
			Password: "", // no password set
			DB:       0,  // use default DB
		})
	}

	if redClient == nil {
		return nil, fmt.Errorf("Failed to create redis client")
	}
	return &RedisClient{redisClient: redClient}, nil
}

// GetAll to fetch all values
func (rc *RedisClient) GetAll(key interface{}) (map[string]*Data, error) {
	path := GetPath(key)
	resp, err := rc.redisClient.HGetAll(ctx, path).Result()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	kvPair := make(map[string]*Data)
	for k, v := range resp {
		key := string([]byte(k))
		value := []byte(v)
		kvPair[key] = &Data{Key: key, Value: value}
	}
	return kvPair, nil
}

// Get to fetch single value
func (rc *RedisClient) Get(basePath, key interface{}) (*Data, error) {
	var err error
	bPath := basePath.(string)
	argKey := key.(string)
	path := fmt.Sprintf(string(bPath), argKey)
	hash, keyStr := SplitHashKey(path)

	var resp string
	resp, err = rc.redisClient.HGet(ctx, hash, keyStr).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &Data{Value: []byte(resp)}, nil
}

// SplitHashKey splits the key path into hash and key for redis hash kv pair
func SplitHashKey(keyPath string) (string, string) {
	part := strings.Split(keyPath, "/")
	key := part[len(part)-1]
	hash := strings.TrimRight(keyPath, key)
	return hash, key
}

// GetPath to get path
func GetPath(path interface{}) string {
	switch reflect.ValueOf(path).Kind() {
	default:
		switch path := path.(type) {
		case string:
			return fmt.Sprint(path)
		default:
			return (string(path.(KVPath)))
		}
	}
}

// GetValue to fetch single value
func (rc *RedisClient) GetValue(basePath interface{}) (*Data, error) {
	var err error
	path := GetPath(basePath)
	hash, keyStr := SplitHashKey(path)

	var resp string
	resp, err = rc.redisClient.HGet(ctx, hash, keyStr).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &Data{Value: []byte(resp)}, nil
}
# [EOF] - delta:force
