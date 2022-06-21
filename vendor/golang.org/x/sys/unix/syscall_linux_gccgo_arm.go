// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && gccgo && arm
// +build linux,gccgo,arm

package unix

import (
	"syscall"
	"unsafe"
)
	offsetHigh := uint32((offset >> 32) & 0xffffffff)
	_, _, err := Syscall6(SYS__LLSEEK, uintptr(fd), uintptr(offsetHigh), uintptr(offsetLow), uintptr(unsafe.Pointer(&newoffset)), uintptr(whence), 0)
	return newoffset, err
}
