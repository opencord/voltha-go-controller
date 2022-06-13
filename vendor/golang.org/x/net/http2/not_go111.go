// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.11
// +build !go1.11

package http2

import (
	"net/http/httptrace"
	"net/textproto"
)

func traceGot1xxResponseFunc(trace *httptrace.ClientTrace) func(int, textproto.MIMEHeader) error {
	return nil
}
