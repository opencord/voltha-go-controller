/* -----------------------------------------------------------------------
 * Copyright 2022-2024 Open Networking Foundation Contributors
 *
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
 * -----------------------------------------------------------------------
 * SPDX-FileCopyrightText: 2022-2024 Open Networking Foundation Contributors
 * SPDX-License-Identifier: Apache-2.0
 * -----------------------------------------------------------------------
 */

package mocks

import (
	"context"
	"reflect"

	common "voltha-go-controller/internal/pkg/types"

	gomock "go.uber.org/mock/gomock"
)

// MockEvIntf is a mock of EvIntf interface.
type MockEvIntf struct {
	ctrl     *gomock.Controller
	recorder *MockEvIntfMockRecorder
}

// MockEvIntfMockRecorder is the mock recorder for MockEvIntf.
type MockEvIntfMockRecorder struct {
	mock *MockEvIntf
}

// NewMockEventIntf creates a new mock instance.
func NewMockEventIntf(ctrl *gomock.Controller) *MockEvIntf {
	mock := &MockEvIntf{ctrl: ctrl}
	mock.recorder = &MockEvIntfMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEvIntf) EXPECT() *MockEvIntfMockRecorder {
	return m.recorder
}

// SendSubscriberStateEvent mocks base method.
func (m *MockEvIntf) SendSubscriberStateEvent(arg0 context.Context, arg1 string, arg2 common.SubscriberStatus_Types, arg3 string, arg4 string, arg5 string, arg6 int64) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SendSubscriberStateEvent", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// SendSubscriberStateEvent indicates an expected call of SendSubscriberStateEvent.
func (mr *MockEvIntfMockRecorder) SendSubscriberStateEvent(arg0, arg1, arg2, arg3, arg4, arg5, arg6 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendSubscriberStateEvent", reflect.TypeOf((*MockEvIntf)(nil).SendSubscriberStateEvent), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}
