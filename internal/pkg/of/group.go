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

package of

import (
	"voltha-go-controller/log"

	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	//	"github.com/opencord/voltha-protos/v5/go/voltha"
)

// The commands on groups available. Add is not expected to be used.
// The mod is used for both create and update. The delete is used to
// delete the group

// GroupCommand type
type GroupCommand ofp.OfpGroupModCommand

const (
	// GroupCommandAdd constant
	GroupCommandAdd GroupCommand = 0
	// GroupCommandMod constant
	GroupCommandMod GroupCommand = 1
	// GroupCommandDel constant
	GroupCommandDel GroupCommand = 2
)

const (
	// GroupOperSuccess constant
	GroupOperSuccess = 0
	// GroupOperFailure constant
	GroupOperFailure = 1
	// GroupOperPending constant
	GroupOperPending = 2
)

// The group modification record to be used by the controller
// to create a group. This is prepared by application and passed
// on to the controller

// Group structure
type Group struct {
	Device           string
	ErrorReason      string
	Buckets          []uint32
	GroupID          uint32
	SetVlan          VlanType
	Command          GroupCommand `json:"-"`
	State            uint8
	IsPonVlanPresent bool
	ForceAction      bool
}

// CreateGroupTableUpdate creates the logical group flow table update
// This is used by controller for building the final outgoing
// structure towards the VOLTHA
func CreateGroupTableUpdate(g *Group) *ofp.FlowGroupTableUpdate {
	logger.Debugw(ctx, "Group Construction", log.Fields{"Group": g})
	groupUpdate := &ofp.FlowGroupTableUpdate{
		Id: g.Device,
		GroupMod: &ofp.OfpGroupMod{
			Command: ofp.OfpGroupModCommand(g.Command),
			Type:    ofp.OfpGroupType_OFPGT_ALL,
			GroupId: g.GroupID,
		},
	}
	logger.Debugw(ctx, "Adding Receivers", log.Fields{"Num": len(g.Buckets)})

	// Since OLT doesnt support setvlan action during update, adding setVlan action
	// during group creation itself even when bucketlist is empty
	if len(g.Buckets) == 0 && g.IsPonVlanPresent {
		bucket := &ofp.OfpBucket{}
		bucket.Weight = 0
		bucket.Actions = []*ofp.OfpAction{
			{
				Type: ofp.OfpActionType_OFPAT_SET_FIELD,
				Action: &ofp.OfpAction_SetField{
					SetField: &ofp.OfpActionSetField{
						Field: &ofp.OfpOxmField{
							Field: &ofp.OfpOxmField_OfbField{
								OfbField: &ofp.OfpOxmOfbField{
									Type: ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID,
									Value: &ofp.OfpOxmOfbField_VlanVid{
										VlanVid: uint32(g.SetVlan),
									},
								},
							},
						},
					},
				},
			},
		}
		groupUpdate.GroupMod.Buckets = append(groupUpdate.GroupMod.Buckets, bucket)
	}

	for _, pon := range g.Buckets {
		bucket := &ofp.OfpBucket{}
		bucket.Weight = 0
		bucket.Actions = []*ofp.OfpAction{
			{
				Type: ofp.OfpActionType_OFPAT_OUTPUT,
				Action: &ofp.OfpAction_Output{
					Output: &ofp.OfpActionOutput{
						Port:   pon,
						MaxLen: 65535,
					},
				},
			},
		}
		if g.IsPonVlanPresent {
			setVlanAction := &ofp.OfpAction{

				Type: ofp.OfpActionType_OFPAT_SET_FIELD,
				Action: &ofp.OfpAction_SetField{
					SetField: &ofp.OfpActionSetField{
						Field: &ofp.OfpOxmField{
							Field: &ofp.OfpOxmField_OfbField{
								OfbField: &ofp.OfpOxmOfbField{
									Type: ofp.OxmOfbFieldTypes_OFPXMT_OFB_VLAN_VID,
									Value: &ofp.OfpOxmOfbField_VlanVid{
										VlanVid: uint32(g.SetVlan),
									},
								},
							},
						},
					},
				},
			}
			bucket.Actions = append(bucket.Actions, setVlanAction)
		}
		groupUpdate.GroupMod.Buckets = append(groupUpdate.GroupMod.Buckets, bucket)
	}

	logger.Debugw(ctx, "Group Constructed", log.Fields{"Group": groupUpdate})
	return groupUpdate
}
