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

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

// DeviceIDForGetAll to get list of device id for GetAll functionality.
func DeviceIDForGetAll() []string {
	// url to fetch device-id list
	baseURL := "http://localhost:8181/device-id-list/"
	vgcClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, baseURL, nil)
	if err != nil {
		//fmt.Errorf("Error sending device id list request : %s", err)
		return nil
	}

	resp, getErr := vgcClient.Do(req)
	if getErr != nil {
		//fmt.Errorf("Error fetching the device id list details: %s", getErr)
		return nil
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		//fmt.Errorf("Error while reading device id list details: %s", readErr)
		return nil
	}

	var deviceIDList []string
	marshErr := json.Unmarshal([]byte(body), &deviceIDList)
	if marshErr != nil {
		//fmt.Errorf("Error while unmarshalling device id list details: %s", marshErr)
		return nil
	}

	if len(deviceIDList) == 0 {
		//fmt.Errorf("No device id  found")
		return nil
	}

	return deviceIDList
}

// GetAPIData fetches data for api by url path.
func GetAPIData(path string) ([]byte, error) {
	vgcClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("Error sending api command request : %s", err)
	}

	resp, getErr := vgcClient.Do(req)
	if getErr != nil {
		return nil, fmt.Errorf("Error fetching the api command output details: %s", getErr)
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("Error while reading api command output details: %s", readErr)
	}

	return body, nil
}

// PutAPIData puts the data to the provided URL.
func PutAPIData(path string, data io.Reader) error {
	vgcClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}
	req, err := http.NewRequest(http.MethodPut, path, data)
	if err != nil {
		return fmt.Errorf("Error sending api command request : %s", err)
	}

	_, getErr := vgcClient.Do(req)
	if getErr != nil {
		return fmt.Errorf("Error in set http request: %s", getErr)
	}
	return nil
}
# [EOF] - delta:force
