// +build !linux appengine

/*
 *
 * Copyright 2022 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *
 */

package channelz

// GetSocketOption gets the socket option info of the conn.
func GetSocketOption(c interface{}) *SocketOptionData {
	return nil
}
