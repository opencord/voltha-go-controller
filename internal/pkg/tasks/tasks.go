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
	"errors"
	"sync"
	"time"

	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

var logger log.CLogger

var (
	// ErrCxtCancelError error
	ErrCxtCancelError = errors.New("Context Cancelled")
	// ErrTaskCancelError error
	ErrTaskCancelError = errors.New("Task Cancelled")

	ctx = context.TODO()
)

// TaskSet implements a set of dependent tasks into a single unit. The
// tasks are added in the order they are expected to be executed. If any
// of the tasks fails, the remaining tasks are not executed.

// TaskSet structure
type TaskSet struct {
	name      string
	taskID    uint8
	timestamp string
	queued    []Task
}

// NewTaskSet is constructor for TaskSet
func NewTaskSet(name string) *TaskSet {
	var ts TaskSet
	ts.name = name
	tstamp := (time.Now()).Format(time.RFC3339Nano)
	ts.timestamp = tstamp
	return &ts
}

// Name to return name of the task
func (ts *TaskSet) Name() string {
	return ts.name
}

// TaskID to return task id of the task
func (ts *TaskSet) TaskID() uint8 {
	return ts.taskID
}

// Timestamp to return timestamp for the task
func (ts *TaskSet) Timestamp() string {
	return ts.timestamp
}

// AddTask to add task
func (ts *TaskSet) AddTask(task Task) {
	logger.Debugw(ctx, "Adding Task to TaskSet", log.Fields{"SetName": ts.name, "TaskName": task.Name()})
	ts.queued = append(ts.queued, task)
}

// Start to start the task
func (ts *TaskSet) Start(ctx context.Context, taskID uint8) error {
	logger.Debug(ctx, "Starting Execution TaskSet", log.Fields{"SetName": ts.name})
	ts.taskID = taskID
	for len(ts.queued) != 0 {
		task := ts.queued[0]
		logger.Infow(ctx, "Starting Execution of task", log.Fields{"TaskName": task.Name()})
		err := task.Start(ctx, ts.taskID)
		if err != nil {
			return err
		}
		task = ts.popTask()
		logger.Infow(ctx, "Execution of task completed", log.Fields{"TaskName": task.Name()})
	}
	logger.Debug(ctx, "Exiting Execution of TaskSet")
	return nil
}

// popTask is used internally to remove the task that is
// is just completed.
func (ts *TaskSet) popTask() Task {
	var task Task
	task, ts.queued = ts.queued[0], ts.queued[1:]
	return task
}

// Stop is used internally to remove the task that is
// is just completed.
func (ts *TaskSet) Stop() {
	var task Task
	// Stop all the tasks and clean up
	for size := len(ts.queued); size > 0; size = len(ts.queued) {
		// Pop out the first task and clean up resources
		task, ts.queued = ts.queued[0], ts.queued[1:]
		task.Stop()
	}
}

//***************************************************************************
// Task Execution Environment
// ------------------------------
// The section below helps create an execution environment for tasks
// of a single ONU. Addition and in sequence execution of tasks is
// the main goal.

// queued - holds tasks yet to be executed and the current in progress
// taskID - This variable is used to generate unique task id for each task
// currentTask - This holds the value of task being executed
// timout - This variable sets the timeout value for all of the messages
// stop - This provides a way of stopping the execution of next task

// Tasks structure
type Tasks struct {
	queued      []Task
	taskID      uint8
	stop        bool
	totalTasks  uint16
	failedTasks uint16
	lock        sync.RWMutex
	ctx         context.Context
}

// NewTasks is constructor for Tasks
func NewTasks(ctx context.Context) *Tasks {
	var ts Tasks
	ts.taskID = 0xff
	ts.stop = false
	ts.queued = []Task{}
	ts.totalTasks = 0
	ts.failedTasks = 0
	ts.ctx = ctx
	return &ts
}

// Initialize is used to initialize the embedded tasks structure within
// each ONU.
func (ts *Tasks) Initialize(ctx context.Context) {

	//Send signal to stop any task which are being executed
	ts.StopAll()
	ts.taskID = 0xff
	ts.ctx = ctx
}

// CheckAndInitialize is used to initialize the embedded tasks structure within
// NNI and resets taskID only when there are no pending tasks
func (ts *Tasks) CheckAndInitialize(ctx context.Context) {

	ts.lock.Lock()
	logger.Infow(ctx, "Queued Tasks", log.Fields{"Count": len(ts.queued)})
	if len(ts.queued) == 0 {
		ts.lock.Unlock()
		ts.Initialize(ctx)
		return
	}
	ts.ctx = ctx
	ts.lock.Unlock()
}

// getNewTaskId generates a unique task-id for each new task. The
// transaction-ids are generated for the task-ids.
func (ts *Tasks) getNewTaskID() uint8 {
	ts.taskID++
	return ts.taskID
}

// GetContext to get context of the task
func (ts *Tasks) GetContext() context.Context {
	return ts.ctx
}

// AddTask adds a task and executes it if there is no task
// pending execution. The execution happens on a seperate thread.
// The tasks are maintained per ONU. This structure is instantiated
// one per ONU
func (ts *Tasks) AddTask(task Task) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	// logger.Infow(ctx, "Adding Task", log.Fields{"TaskName": task.Name()})
	ts.queued = append(ts.queued, task)
	if ts.queued[0] == task {
		go ts.executeTasks()
	}
}

// TotalTasks returns the total number of tasks completed by the
// the execution of the tasks.
func (ts *Tasks) TotalTasks() uint16 {
	return ts.totalTasks
}

// StopAll stops the execution of the tasks and cleans up
// everything associated with the tasks
func (ts *Tasks) StopAll() {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	ts.stop = true
	logger.Infow(ctx, "Stopping all tasks in queue", log.Fields{"TaskCount": len(ts.queued)})

	if len(ts.queued) > 0 {
		ts.queued = ts.queued[:1]
		logger.Warnw(ctx, "Skipping Current Task", log.Fields{"Task": ts.queued[0].Name()})
	}
	ts.stop = false
	return
}

// popTask is used internally to remove the task that is
// is just completed.
func (ts *Tasks) popTask() (Task, int) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	var task Task
	queueLen := len(ts.queued)
	if queueLen > 0 {
		task = ts.queued[0]
		ts.queued = append(ts.queued[:0], ts.queued[0+1:]...)
	} else {
		logger.Errorw(ctx, "Trying to remove task from empty Task List", log.Fields{"#task ": queueLen})
	}

	return task, len(ts.queued)
}

// NumPendingTasks returns the count of tasks that are either in progress or
// yet to be executed. The first in the list is the in progress
// task.
func (ts *Tasks) NumPendingTasks() uint16 {
	return uint16(len(ts.queued))
}

// GetTaskList returns the list of tasks that are either in progress or
// yet to be executed. The first in the list is the in progress
// task.
func (ts *Tasks) GetTaskList() []Task {
	taskList := []Task{}
	return append(taskList, ts.queued...)
}

// CurrentTask returns the task that is currently running. This can be
// used for verifying upon unforseen failures for debugging from
// with the code
func (ts *Tasks) CurrentTask() Task {
	return ts.queued[0]
}

// executeTasks executes the pending tasks one by one. The tasks are attempted
// one after another to avoid two tasks simultaneously operating on the
// same ONU.
func (ts *Tasks) executeTasks() {
	// logger.Debug(ctx, "Starting Execution of tasks")
	for (len(ts.queued) != 0) && (!ts.stop) {
		task := ts.queued[0]
		taskID := ts.getNewTaskID()
		// logger.Infow(ctx, "Starting Execution of task", log.Fields{"TaskName": task.Name()})
		ts.totalTasks++

		err := task.Start(ts.ctx, taskID)
		if err == ErrTaskCancelError {
			logger.Warnw(ctx, "Previous task cancelled. Exiting current task queue execution thread", log.Fields{"TaskCount": len(ts.queued)})
			return
		}
		task, pending := ts.popTask()

		if err != nil {
			ts.failedTasks++
		}
		if err == ErrCxtCancelError {
			// TODO - This needs correction
			ts.StopAll()
			return
		}

		if pending == 0 {
			break
		}
	}
	// logger.Debug(ctx, "Exiting Execution of tasks")
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.RegisterPackage(log.JSON, log.ErrorLevel, log.Fields{})
	if err != nil {
		panic(err)
	}
}
