// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package msg

type Service struct {
	UUID        string
	Name        string
	Version     string
	Environment string
	Region      string
	Host        string
	Port        uint16
}
