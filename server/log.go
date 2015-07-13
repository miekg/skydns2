// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import "log"

// printf calls log.Printf with the parameters given.
func printf(format string, a ...interface{}) {
	log.Printf("skydns: "+format, a...)
}
