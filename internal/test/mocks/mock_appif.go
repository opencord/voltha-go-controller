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

// Code generated by MockGen. DO NOT EDIT.
// Source: /home/vinod/go/src/gerrit.opencord.org/voltha-go-controller/internal/pkg/intf/appif.go

// Package mock_intf is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"
	intf "voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"

	gomock "github.com/golang/mock/gomock"
)

// MockApp is a mock of App interface.
type MockApp struct {
	ctrl     *gomock.Controller
	recorder *MockAppMockRecorder
}

// MockAppMockRecorder is the mock recorder for MockApp.
type MockAppMockRecorder struct {
	mock *MockApp
}

// NewMockApp creates a new mock instance.
func NewMockApp(ctrl *gomock.Controller) *MockApp {
	mock := &MockApp{ctrl: ctrl}
	mock.recorder = &MockAppMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockApp) EXPECT() *MockAppMockRecorder {
	return m.recorder
}

// AddDevice mocks base method.
func (m *MockApp) AddDevice(arg0 context.Context, arg1, arg2, arg3 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddDevice", arg0, arg1, arg2, arg3)
}

// AddDevice indicates an expected call of AddDevice.
func (mr *MockAppMockRecorder) AddDevice(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddDevice", reflect.TypeOf((*MockApp)(nil).AddDevice), arg0, arg1, arg2, arg3)
}

// DelDevice mocks base method.
func (m *MockApp) DelDevice(arg0 context.Context, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DelDevice", arg0, arg1)
}

// DelDevice indicates an expected call of DelDevice.
func (mr *MockAppMockRecorder) DelDevice(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DelDevice", reflect.TypeOf((*MockApp)(nil).DelDevice), arg0, arg1)
}

// DeviceDisableInd mocks base method.
func (m *MockApp) DeviceDisableInd(arg0 context.Context, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DeviceDisableInd", arg0, arg1)
}

// DeviceDisableInd indicates an expected call of DeviceDisableInd.
func (mr *MockAppMockRecorder) DeviceDisableInd(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeviceDisableInd", reflect.TypeOf((*MockApp)(nil).DeviceDisableInd), arg0, arg1)
}

// DeviceDownInd mocks base method.
func (m *MockApp) DeviceDownInd(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DeviceDownInd", arg0)
}

// DeviceDownInd indicates an expected call of DeviceDownInd.
func (mr *MockAppMockRecorder) DeviceDownInd(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeviceDownInd", reflect.TypeOf((*MockApp)(nil).DeviceDownInd), arg0)
}

// DeviceRebootInd mocks base method.
func (m *MockApp) DeviceRebootInd(arg0 context.Context, arg1, arg2, arg3 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DeviceRebootInd", arg0, arg1, arg2, arg3)
}

// DeviceRebootInd indicates an expected call of DeviceRebootInd.
func (mr *MockAppMockRecorder) DeviceRebootInd(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeviceRebootInd", reflect.TypeOf((*MockApp)(nil).DeviceRebootInd), arg0, arg1, arg2, arg3)
}

// DeviceUpInd mocks base method.
func (m *MockApp) DeviceUpInd(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DeviceUpInd", arg0)
}

// DeviceUpInd indicates an expected call of DeviceUpInd.
func (mr *MockAppMockRecorder) DeviceUpInd(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeviceUpInd", reflect.TypeOf((*MockApp)(nil).DeviceUpInd), arg0)
}

// PacketInInd mocks base method.
func (m *MockApp) PacketInInd(arg0 context.Context, arg1, arg2 string, arg3 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PacketInInd", arg0, arg1, arg2, arg3)
}

// PacketInInd indicates an expected call of PacketInInd.
func (mr *MockAppMockRecorder) PacketInInd(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PacketInInd", reflect.TypeOf((*MockApp)(nil).PacketInInd), arg0, arg1, arg2, arg3)
}

// PortAddInd mocks base method.
func (m *MockApp) PortAddInd(arg0 context.Context, arg1 string, arg2 uint32, arg3 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PortAddInd", arg0, arg1, arg2, arg3)
}

// PortAddInd indicates an expected call of PortAddInd.
func (mr *MockAppMockRecorder) PortAddInd(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortAddInd", reflect.TypeOf((*MockApp)(nil).PortAddInd), arg0, arg1, arg2, arg3)
}

// PortDelInd mocks base method.
func (m *MockApp) PortDelInd(arg0 context.Context, arg1, arg2 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PortDelInd", arg0, arg1, arg2)
}

// PortDelInd indicates an expected call of PortDelInd.
func (mr *MockAppMockRecorder) PortDelInd(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortDelInd", reflect.TypeOf((*MockApp)(nil).PortDelInd), arg0, arg1, arg2)
}

// PortDownInd mocks base method.
func (m *MockApp) PortDownInd(arg0 context.Context, arg1, arg2 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PortDownInd", arg0, arg1, arg2)
}

// PortDownInd indicates an expected call of PortDownInd.
func (mr *MockAppMockRecorder) PortDownInd(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortDownInd", reflect.TypeOf((*MockApp)(nil).PortDownInd), arg0, arg1, arg2)
}

// PortUpInd mocks base method.
func (m *MockApp) PortUpInd(arg0 context.Context, arg1, arg2 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PortUpInd", arg0, arg1, arg2)
}

// PortUpInd indicates an expected call of PortUpInd.
func (mr *MockAppMockRecorder) PortUpInd(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortUpInd", reflect.TypeOf((*MockApp)(nil).PortUpInd), arg0, arg1, arg2)
}

// PortUpdateInd mocks base method.
func (m *MockApp) PortUpdateInd(arg0, arg1 string, arg2 uint32) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PortUpdateInd", arg0, arg1, arg2)
}

// PortUpdateInd indicates an expected call of PortUpdateInd.
func (mr *MockAppMockRecorder) PortUpdateInd(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PortUpdateInd", reflect.TypeOf((*MockApp)(nil).PortUpdateInd), arg0, arg1, arg2)
}

// ProcessFlowModResultIndication mocks base method.
func (m *MockApp) ProcessFlowModResultIndication(arg0 context.Context, arg1 intf.FlowStatus) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ProcessFlowModResultIndication", arg0, arg1)
}

// ProcessFlowModResultIndication indicates an expected call of ProcessFlowModResultIndication.
func (mr *MockAppMockRecorder) ProcessFlowModResultIndication(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProcessFlowModResultIndication", reflect.TypeOf((*MockApp)(nil).ProcessFlowModResultIndication), arg0, arg1)
}

// IsFlowDelThresholdReached mocks base method.
func (m *MockApp) IsFlowDelThresholdReached(arg0 context.Context, arg1 string, arg2 string) bool {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "IsFlowDelThresholdReached", arg0, arg1, arg2)
	return false
}

	// CheckAndDeactivateService mocks base method.
	func (m *MockApp) CheckAndDeactivateService(arg0 context.Context, arg1 *of.VoltSubFlow, arg2 string, arg3 string) {
		 m.ctrl.T.Helper()
		m.ctrl.Call(m, "CheckAndDeactivateService", arg0, arg1, arg2, arg3)
	 }

// IsFlowDelThresholdReached indicates an expected call of IsFlowDelThresholdReached.
func (mr *MockAppMockRecorder) IsFlowDelThresholdReached(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsFlowDelThresholdReached", reflect.TypeOf((*MockApp)(nil).IsFlowDelThresholdReached), arg0, arg1, arg2)
}
	// CheckAndDeactivateService indicates an expected call of CheckAndDeactivateService.
	func (mr *MockAppMockRecorder) CheckAndDeactivateService(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
		 mr.mock.ctrl.T.Helper()
		return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckAndDeactivateService", reflect.TypeOf((*MockApp)(nil).CheckAndDeactivateService), arg0, arg1, arg2)
	 }
// SetRebootFlag mocks base method.
func (m *MockApp) SetRebootFlag(arg0 bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRebootFlag", arg0)
}

// SetRebootFlag indicates an expected call of SetRebootFlag.
func (mr *MockAppMockRecorder) SetRebootFlag(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRebootFlag", reflect.TypeOf((*MockApp)(nil).SetRebootFlag), arg0)
}

// TriggerPendingMigrateServicesReq mocks base method.
func (m *MockApp) TriggerPendingMigrateServicesReq(arg0 context.Context, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "TriggerPendingMigrateServicesReq", arg0, arg1)
}

// TriggerPendingMigrateServicesReq indicates an expected call of TriggerPendingMigrateServicesReq.
func (mr *MockAppMockRecorder) TriggerPendingMigrateServicesReq(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TriggerPendingMigrateServicesReq", reflect.TypeOf((*MockApp)(nil).TriggerPendingMigrateServicesReq), arg0, arg1)
}

// TriggerPendingProfileDeleteReq mocks base method.
func (m *MockApp) TriggerPendingProfileDeleteReq(arg0 context.Context, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "TriggerPendingProfileDeleteReq", arg0, arg1)
}

// TriggerPendingProfileDeleteReq indicates an expected call of TriggerPendingProfileDeleteReq.
func (mr *MockAppMockRecorder) TriggerPendingProfileDeleteReq(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TriggerPendingProfileDeleteReq", reflect.TypeOf((*MockApp)(nil).TriggerPendingProfileDeleteReq), arg0, arg1)
}

// UpdateMvlanProfilesForDevice mocks base method.
func (m *MockApp) UpdateMvlanProfilesForDevice(arg0 context.Context, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdateMvlanProfilesForDevice", arg0, arg1)
}

// UpdateMvlanProfilesForDevice indicates an expected call of UpdateMvlanProfilesForDevice.
func (mr *MockAppMockRecorder) UpdateMvlanProfilesForDevice(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateMvlanProfilesForDevice", reflect.TypeOf((*MockApp)(nil).UpdateMvlanProfilesForDevice), arg0, arg1)
}