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
	"archive/zip"
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
	req.Body = LogBody(req.Body, "request")
}

func LogBody(body io.ReadCloser, from string) io.ReadCloser {

	if body != nil {
		buf, err := io.ReadAll(body)
		if err != nil {
			var w http.ResponseWriter
			log.Fatalf("Error reading %s body: %v", from, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}

		IsZipFile := func() bool {
			if len(buf) >= 4 {
				// The header is []byte{ 0x50, 0x4b, 0x03, 0x04 }
				magic := []byte{0x50, 0x4b, 0x03, 0x04}
				if bytes.Equal(buf[0:4], magic) {
					return true
				} else {
					return false
				}
			} else {
				return false
			}
		}

		if IsZipFile() {
			// Show index for pk zip archives
			buf1 := make([]byte, len(buf))
			copy(buf1, buf)

			r, err := zip.NewReader(bytes.NewReader(buf1), int64(len(buf1)))
			if err != nil {
				log.Fatal(err)
			}
			// defer r.Close()

			// Print the archive index
			log.Printf(">> %s body:\n", from)
			log.Printf("zip file, contents:\n")

			for _, f := range r.File {
				log.Printf("\t%s\n", f.Name)
			}
		} else if false {
			// TODO: show json ?toc? for
			//   2024/02/08 14:54:14 >> Request body: {"repositories":["google/flatbuffers"],
			//   "language":"cpp","query_pack":"H4sIAAAA...","action_repo_ref":"main"}
			//  54:0:$ base64 -d < foo1 | gunzip | tar t|head -20
			// base64 has no magic number.
			// We have to decode enough to check the gzip magic number, 0x1f 0x8b
			// 4 chars in base64 yield 3 bytes.
		} else {
			log.Printf(">> %s body: %v", from, string(buf))
		}

		reader := io.NopCloser(bytes.NewBuffer(buf))
		return reader
	}
	return body
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

	resp.Body = LogBody(resp.Body, "response")
}
