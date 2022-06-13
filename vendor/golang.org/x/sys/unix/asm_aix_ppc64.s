// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build gc
// +build gc

#include "textflag.h"

//
// System calls for ppc64, AIX are implemented in runtime/syscall_aix.go
//

	JMP	syscall·rawSyscall6(SB)
