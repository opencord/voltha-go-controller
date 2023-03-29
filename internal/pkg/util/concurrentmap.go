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

package util

import (
	"sync"

	"go.uber.org/atomic"
)

// ConcurrentMap implements a wrapper on top of SyncMap so that the count is also maintained
type ConcurrentMap struct {
	count   *atomic.Uint64
	syncMap sync.Map
	MapLock sync.RWMutex
}

// NewConcurrentMap - Initializes new ConcurentMap Object
func NewConcurrentMap() *ConcurrentMap {
	var cm ConcurrentMap
	cm.count = atomic.NewUint64(0)
	return &cm
}

// Get - Gets return the value store in the sync map
// If value is present, the result will be true else false
func (cm *ConcurrentMap) Get(key interface{}) (value interface{}, result bool) {
	return cm.syncMap.Load(key)
}

// Set - Store the value in sync map against the key provided
func (cm *ConcurrentMap) Set(key, value interface{}) {
	if cm.count == nil {
		cm.count = atomic.NewUint64(0)
	}
	_, exists := cm.syncMap.Load(key)
	cm.syncMap.Store(key, value)
	if !exists {
		cm.count.Inc()
	}
}

// Remove - Removes the key-value pair from the sync map
func (cm *ConcurrentMap) Remove(key interface{}) bool {
	if _, ok := cm.syncMap.Load(key); ok {
		cm.syncMap.Delete(key)
		cm.count.Dec()
		return true
	}
	return false
}

// Range calls f sequentially for each key and value present in the sync map.
// If f returns false, range stops the iteration.
//
// Range does not necessarily correspond to any consistent snapshot of the Sync Map's
// contents: no key will be visited more than once, but if the value for any key
// is stored or deleted concurrently, Range may reflect any mapping for that key
// from any point during the Range call.
//
// Range may be O(N) with the number of elements in the sync map even if f returns
// false after a constant number of calls.
func (cm *ConcurrentMap) Range(f func(key, value interface{}) bool) {
	cm.syncMap.Range(f)
}

// Length - return the no of entries present in the map
func (cm *ConcurrentMap) Length() uint64 {
	if cm.count == nil {
		return 0
	}
	return cm.count.Load()
}
