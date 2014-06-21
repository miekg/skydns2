// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

// This file needs to go as soon as possible, the Cache in cache.go is generic
// enough for both use cases. For now, I'm too lazy, hence two duplicate implementations.

package main

import (
	"container/list"
	"crypto/sha1"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// response hold an answer and additional section that returned from the cache.
type responseElem struct {
	key        string
	expiration time.Time // time added + TTL, after this the elem is invalid
	answer     []dns.RR
	extra      []dns.RR
}

type cache1 struct {
	sync.RWMutex
	l        *list.List
	m        map[string]*list.Element
	capacity uint // number of RRs
	size     uint // current size
}

func newCache1(capacity uint) *cache1 {
	c := new(cache1)
	c.l = list.New()
	c.m = make(map[string]*list.Element)
	c.capacity = capacity
	return c
}

func (c *cache1) Remove(s string) {
	c.Lock()
	defer c.Unlock()
	e := c.m[s]
	if e == nil {
		return
	}
	c.size -= 1
	c.l.Remove(e)
	delete(c.m, s)
	c.shrink()
}

func (c *cache1) shrink() {
	for c.size > c.capacity {
		e := c.l.Back()
		if e == nil { // nothing left
			break
		}
		v := e.Value.(*responseElem)
		c.l.Remove(e)
		delete(c.m, v.key)
		c.size -= uint(len(v.answer) + len(v.extra))
	}
}

func (c *cache1) insert(s string, answer, extra []dns.RR) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.m[s]; !ok {
		e := c.l.PushFront(&responseElem{s, time.Now().UTC().Add(time.Second * time.Duration(answer[0].Header().Ttl)), answer, extra})
		c.m[s] = e
	}
	c.size += uint(len(answer) + len(extra))
	c.shrink()
}

func (c *cache1) search(s string) ([]dns.RR, []dns.RR) {
	c.RLock()
	defer c.RUnlock()
	if e, ok := c.m[s]; ok {
		// we want to return a copy here, because if we didn't the RRSIG
		// could be removed by another goroutine before the packet containing
		// this signature is send out.
		c.l.MoveToFront(e)
		e := e.Value.(*responseElem)
		answer := make([]dns.RR, len(e.answer))
		extra := make([]dns.RR, len(e.extra))
		for i, r := range e.answer {
			answer[i] = dns.Copy(r)
		}
		for i, r := range e.extra {
			extra[i] = dns.Copy(r)
		}
		return answer, extra
	}
	return nil, nil
}

func QuestionKey(q dns.Question) string {
	h := sha1.New()
	i := append([]byte(q.Name), packUint16(q.Qtype)...)
	return string(h.Sum(i))
}
