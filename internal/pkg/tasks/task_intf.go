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

package tasks

import (
	"context"
)

// Each task must support this interface to be exercised
// by the implementation to execute the tasks similarly
// across all tasks

// Task interface
type Task interface {
	TaskID() uint8
	Name() string
	Timestamp() string
	Start(context.Context, uint8) error
	Stop()
}
