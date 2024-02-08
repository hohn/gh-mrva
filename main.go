/*
Copyright © 2023 Alvaro Munoz pwntester@github.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/GitHubSecurityLab/gh-mrva/cmd"

	"github.com/motemen/go-loghttp"
	"github.com/motemen/go-nuts/roundtime"
)

func main() {
	var transport = &loghttp.Transport{
		Transport:   http.DefaultTransport,
		LogRequest:  LogRequestDump,
		LogResponse: LogResponseDump,
	}

	http.DefaultTransport = transport

	cmd.Execute()
}

// Used if transport.LogRequest is not set.
func LogRequestDump(req *http.Request) {
	log.Printf(">> %s %s", req.Method, req.URL)
}

type contextKey struct {
	name string
}

var ContextKeyRequestStart = &contextKey{"RequestStart"}

// Used if transport.LogResponse is not set.
func LogResponseDump(resp *http.Response) {
	ctx := resp.Request.Context()
	if start, ok := ctx.Value(ContextKeyRequestStart).(time.Time); ok {
		log.Printf("<< %d %s (%s)", resp.StatusCode, resp.Request.URL,
			roundtime.Duration(time.Since(start), 2))
	} else {
		log.Printf("<< %d %s", resp.StatusCode, resp.Request.URL)
	}
}
