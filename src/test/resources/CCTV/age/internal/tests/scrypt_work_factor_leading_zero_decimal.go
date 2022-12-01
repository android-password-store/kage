// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import "c2sp.org/CCTV/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.Scrypt("password", 10)
	body, args := f.UnreadLine(), f.UnreadArgsLine()
	f.ArgsLine(args[0], args[1], "010")
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Generate()
}
