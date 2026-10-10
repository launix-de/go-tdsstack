/* Copyright (C) 2026 Carl-Philip Hänsch
SPDX-License-Identifier: GPL-3.0-or-later */

package tds

import (
	"context"
	"fmt"
	"math"
	"strings"
)

const preparedLimit = 128
const preparedBytesLimit = 1 << 20

func rpcParameters(r tdsRPC, start int) []Parameter {
	if len(r.arguments) != len(r.wireDescriptors) || start > len(r.arguments) {
		panic("invalid parameter carrier")
	}
	p := make([]Parameter, len(r.arguments)-start)
	for i, a := range r.arguments[start:] {
		p[i] = Parameter{a.name, a.flags, r.wireDescriptors[i+start], a.value}
	}
	return p
}
func rpcText(a tdsRPCParameter, nullable bool) string {
	if a.flags != 0 {
		panic("statement/declarations must be input text")
	}
	if a.value == nil && nullable {
		return ""
	}
	v, ok := a.value.(string)
	if !ok {
		panic("statement/declarations must be text")
	}
	return v
}
func rpcHandle(a tdsRPCParameter) int32 {
	n, ok := a.value.(int64)
	if a.flags != 0 || !ok || n <= 0 || n > math.MaxInt32 {
		panic("invalid prepared handle")
	}
	return int32(n)
}
func (c *connection) removePrepared(handle int32) {
	if p, ok := c.prepared[handle]; ok {
		c.preparedBytes -= p.bytes
		delete(c.prepared, handle)
	}
}
func (c *connection) prepareRPC(ctx context.Context, r tdsRPC, w *resultWriter) (q Request, handle int32, name string, execute bool, err error) {
	q.Database = c.database
	a := r.arguments
	execute = true
	switch r.procedure {
	case 10:
		if len(a) < 1 {
			return q, 0, "", false, fmt.Errorf("missing execution statement")
		}
		q.Text = rpcText(a[0], false)
		if len(a) > 1 {
			q.Declarations = rpcText(a[1], true)
			q.Parameters = rpcParameters(r, 2)
		}
	case 12, 15:
		if len(a) < 1 {
			return q, 0, "", false, fmt.Errorf("missing prepared handle")
		}
		id := rpcHandle(a[0])
		p, ok := c.prepared[id]
		if !ok {
			return q, 0, "", false, fmt.Errorf("unknown prepared handle")
		}
		if r.procedure == 15 {
			if len(a) != 1 {
				return q, 0, "", false, fmt.Errorf("unprepare requires one handle")
			}
			c.removePrepared(id)
			return q, 0, "", false, nil
		}
		q.Text, q.Declarations = p.text, p.declarations
		q.Parameters = rpcParameters(r, 1)
	case 11, 13:
		if len(a) < 3 || a[0].flags != 1 || a[0].value != nil && !isInt64(a[0].value) {
			return q, 0, "", false, fmt.Errorf("prepare requires output handle, declarations and statement")
		}
		q.Declarations, q.Text = rpcText(a[1], true), rpcText(a[2], false)
		size := len(q.Text) + len(q.Declarations)
		if len(c.prepared) >= preparedLimit || size > preparedBytesLimit-c.preparedBytes || c.nextPrepared == math.MaxInt32 {
			return q, 0, "", false, fmt.Errorf("prepared resource limit")
		}
		if strings.TrimSpace(q.Text) == "" {
			return q, 0, "", false, fmt.Errorf("empty prepared text")
		}
		// Pure describe is also the application's prepare validation boundary. No
		// declaration parser or SQL statement splitter is duplicated in this package.
		if c.server.Handler.Describe == nil {
			return q, 0, "", false, fmt.Errorf("pure describe handler required for prepare")
		}
		columns, e := c.server.Handler.Describe(ctx, c.session, q)
		if e != nil {
			return q, 0, "", false, e
		}
		if e = ctx.Err(); e != nil {
			return q, 0, "", false, e
		}
		if r.procedure == 11 {
			execute = false
			if len(a) > 4 {
				return q, 0, "", false, fmt.Errorf("too many prepare parameters")
			}
			if len(a) == 4 {
				option, ok := a[3].value.(int64)
				if a[3].flags != 0 || !ok || option != 0 && option != 1 {
					return q, 0, "", false, fmt.Errorf("invalid prepare option")
				}
				if option == 1 {
					if e = w.Fields(columns); e != nil {
						return q, 0, "", false, e
					}
				}
			}
		} else {
			q.Parameters = rpcParameters(r, 3)
		}
		c.nextPrepared++
		handle = c.nextPrepared
		name = a[0].name
		if c.prepared == nil {
			c.prepared = make(map[int32]prepared)
		}
		c.prepared[handle] = prepared{q.Text, q.Declarations, size}
		c.preparedBytes += size
	default:
		return q, 0, "", false, fmt.Errorf("unsupported prepared RPC")
	}
	for _, p := range q.Parameters {
		if p.Flags != 0 {
			return q, handle, name, false, fmt.Errorf("statement output parameters unsupported")
		}
	}
	return
}
