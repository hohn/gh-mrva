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
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
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

func IsBase64Gzip(val []byte) bool {
	// Some important payloads can be listed via
	// base64 -d < foo1 | gunzip | tar t|head -20
	//
	// This function checks the request body up to the `gunzip` part.
	//
	if len(val) >= 4 {
		// Extract header
		hdr := make([]byte, base64.StdEncoding.DecodedLen(4))
		_, err := base64.StdEncoding.Decode(hdr, []byte(val[0:4]))
		if err != nil {
			log.Println("WARNING: IsBase64Gzip decode error:", err)
			return false
		}
		// Check for gzip heading
		magic := []byte{0x1f, 0x8b}
		if bytes.Equal(hdr[0:2], magic) {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

func LogRequestDump(req *http.Request) {
	log.Printf(">> %s %s", req.Method, req.URL)
	req.Body = LogBody(req.Body, "request")
}

func IsZipFile(buf []byte) bool {
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

func MaybeJSON(buf []byte) bool {
	if len(buf) >= 4 { // {""} is 4 characters
		if bytes.Equal(buf[0:2], []byte("{\"")) {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

type SubmitMsg struct {
	ActionRepoRef string   `json:"action_repo_ref"`
	Language      string   `json:"language"`
	QueryPack     string   `json:"query_pack"`
	Repositories  []string `json:"repositories"`
}

func PPJson(str string) (string, error) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(str), "", "    "); err != nil {
		return "", err
	}
	return pretty.String(), nil
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

		if IsZipFile(buf) {
			ShowZipIndex(buf, from)
		} else if MaybeJSON(buf) {
			// See if the json contains a known message
			m, err := TrySubmitMsg(buf)

			if err != nil {
				// Unknown message, try pretty-printing json
				pjson, err := PPJson(string(buf))
				if err != nil {
					log.Printf(">> %s body: %v", from, string(buf))
				} else {
					log.Printf(">> %s body: {\n%v\n}", from, pjson)
				}
				goto BodyDone
			}

			// Print index for encoded query packs in the json <value>:
			// {..."query_pack": <value>,...}
			log.Printf(">> %s body: {\n", from)
			log.Printf("    \"%s\": \"%s\"\n", "action_repo_ref", m.ActionRepoRef)
			log.Printf("    \"%s\": \"%s\"\n", "language", m.Language)
			pjson, err := json.MarshalIndent(m.Repositories, "", "    ")
			if err != nil {
				log.Printf("    \"%s\": \"%s\"\n", "repositories", m.Repositories[:])
			} else {
				log.Printf("    \"%s\": %s\n", "repositories", pjson)
			}

			// Provide custom logging for encoded, compressed tar file
			if IsBase64Gzip([]byte(m.QueryPack)) {
				LogBase64GzippedTar(m)
			} else {
				log.Printf("    \"%s\": \"%s\"\n", "query_pack", m.QueryPack)
			}

			log.Printf("\n}")

		} else {
			log.Printf(">> %s body: %v", from, string(buf))
		}

	BodyDone:
		reader := io.NopCloser(bytes.NewBuffer(buf))
		return reader
	}
	return body
}

func TrySubmitMsg(buf []byte) (SubmitMsg, error) {
	buf1 := make([]byte, len(buf))
	copy(buf1, buf)
	dec := json.NewDecoder(bytes.NewReader(buf1))
	dec.DisallowUnknownFields()
	var m SubmitMsg
	err := dec.Decode(&m)
	return m, err

}

func LogBase64GzippedTar(m SubmitMsg) {
	// These are decoded manually via
	//    base64 -d < foo1 | gunzip | tar t | head -20
	// but we need complete logs for inspection and testing.
	// base64 decode the body
	data, err := base64.StdEncoding.DecodeString(m.QueryPack)
	if err != nil {
		log.Fatalln("body decoding error:", err)
	}
	// gunzip the decoded body
	gzb := bytes.NewBuffer(data)
	gzr, err := gzip.NewReader(gzb)
	if err != nil {
		log.Fatal(err)
	}
	// tar t the gunzipped body
	log.Printf("    \"%s\": \n", "query_pack")
	log.Printf("        base64 encoded gzipped tar file, contents:\n")
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			log.Fatalln("Tar listing failure:", err)
		}
		// TODO: head / tail the listing
		log.Printf("        %s\n", hdr.Name)
	}
}

func ShowZipIndex(buf []byte, from string) {
	buf1 := make([]byte, len(buf))
	copy(buf1, buf)

	r, err := zip.NewReader(bytes.NewReader(buf1), int64(len(buf1)))
	if err != nil {
		log.Fatal(err)
	}

	// Print the archive index
	log.Printf(">> %s body:\n", from)
	log.Printf("zip file, contents:\n")

	for _, f := range r.File {
		log.Printf("\t%s\n", f.Name)
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

	resp.Body = LogBody(resp.Body, "response")
}
