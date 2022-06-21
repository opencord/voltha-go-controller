// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && gccgo && 386
// +build linux,gccgo,386

package unix

import (
	"syscall"
	"unsafe"
)
	offsetHigh := uint32((offset >> 32) & 0xffffffff)
	_, _, err := Syscall6(SYS__LLSEEK, uintptr(fd), uintptr(offsetHigh), uintptr(offsetLow), uintptr(unsafe.Pointer(&newoffset)), uintptr(whence), 0)
	return newoffset, err
}

func socketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (int, syscall.Errno) {
	fd, _, err := Syscall(SYS_SOCKETCALL, uintptr(call), uintptr(unsafe.Pointer(&a0)), 0)
	return int(fd), err
}

func rawsocketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (int, syscall.Errno) {
	fd, _, err := RawSyscall(SYS_SOCKETCALL, uintptr(call), uintptr(unsafe.Pointer(&a0)), 0)
	return int(fd), err
}
