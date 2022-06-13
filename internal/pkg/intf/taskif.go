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

package intf

import (
	"context"
	"voltha-go-controller/internal/pkg/tasks"
)

/*Tasks interface is responsible for creating the tasks
and executing them as well. For now, it is assumed that
one task run at a time though interface doesn't force it.*/
type Tasks interface {
	AddTask(tasks.Task)
	Initialize(cxt context.Context)
}
