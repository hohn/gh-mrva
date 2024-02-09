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
	"bytes"
	"io"
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

func LogRequestDump(req *http.Request) {
	log.Printf(">> %s %s", req.Method, req.URL)

	// TODO: as function
	// TODO: show index for pk zip archives
	// TODO: show json ?toc? for
	//   2024/02/08 14:54:14 >> Request body: {"repositories":["google/flatbuffers"],
	//   "language":"cpp","query_pack":"H4sIAAAA...","action_repo_ref":"main"}
	if req.Body != nil {
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			var w http.ResponseWriter
			log.Printf("Error reading request body: %v", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf(">> Request body: %v", string(buf))

		reader := io.NopCloser(bytes.NewBuffer(buf))
		req.Body = reader
	}
}

type contextKey struct {
	name string
}

var ContextKeyRequestStart = &contextKey{"RequestStart"}

func LogResponseDump(resp *http.Response) {
	ctx := resp.Request.Context()
	if start, ok := ctx.Value(ContextKeyRequestStart).(time.Time); ok {
		log.Printf("<< %d %s (%s)", resp.StatusCode, resp.Request.URL,
			roundtime.Duration(time.Since(start), 2))
	} else {
		log.Printf("<< %d %s", resp.StatusCode, resp.Request.URL)
	}

	if resp.Body != nil {
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			var w http.ResponseWriter
			log.Printf("Error reading response body: %v", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf(">> Response body: %v", string(buf))

		reader := io.NopCloser(bytes.NewBuffer(buf))
		resp.Body = reader
	}
}
