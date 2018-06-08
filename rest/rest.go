/*
Copyright 2018 Caicloud Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/caicloud/nirvana/definition"
	"github.com/caicloud/nirvana/errors"
	"github.com/caicloud/nirvana/service/router"
)

// Client implements builder pattern for http client.
type Client struct {
	config *Config
}

// NewClient creates a client.
func NewClient(cfg *Config) (*Client, error) {
	return &Client{cfg}, nil
}

// Request creates an request.
func (c *Client) Request(method string, code int, path string) *Request {
	req, err := newRequest(method, code, c.config.Endpoint, path)
	if err != nil {
		panic(err)
	}
	return req
}

// Request describes a http request.
type Request struct {
	method          string
	code            int
	endpoint        string
	path            string
	segments        []segment
	paths           map[string]interface{}
	queries         map[string]interface{}
	headers         map[string]interface{}
	forms           map[string]interface{}
	files           map[string]interface{}
	body            interface{}
	bodyContentType string
	meta            map[string]string
	data            interface{}
}

func newRequest(method string, code int, endpoint string, path string) (*Request, error) {
	path = "/" + strings.TrimLeft(path, "/\\")
	segments, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	req := &Request{
		method:   http.MethodGet,
		code:     code,
		endpoint: strings.TrimRight(endpoint, "/\\"),
		path:     path,
		segments: segments,
		paths:    map[string]interface{}{},
		queries:  map[string]interface{}{},
		headers:  map[string]interface{}{},
		forms:    map[string]interface{}{},
		files:    map[string]interface{}{},
	}
	return req, nil
}

// Path sets path parameter.
func (r *Request) Path(name string, value interface{}) *Request {
	r.paths[name] = value
	return r
}

// Query sets query parameter.
func (r *Request) Query(name string, value interface{}) *Request {
	r.queries[name] = value
	return r
}

// Header sets header parameter.
func (r *Request) Header(name string, value interface{}) *Request {
	r.headers[name] = value
	return r
}

// Form sets form parameter.
func (r *Request) Form(name string, value interface{}) *Request {
	r.forms[name] = value
	return r
}

// File sets file parameter.
func (r *Request) File(name string, value interface{}) *Request {
	r.files[name] = value
	return r
}

// Body sets body parameter.
func (r *Request) Body(contentType string, value interface{}) *Request {
	r.body = value
	r.bodyContentType = contentType
	return r
}

// Meta sets header result.
func (r *Request) Meta(value map[string]string) *Request {
	r.meta = value
	return r
}

// Data sets body result.
func (r *Request) Data(value interface{}) *Request {
	r.data = value
	return r
}

// Do executes the request.
func (r *Request) Do(ctx context.Context) error {
	if r.body != nil && (len(r.files) > 0 || len(r.forms) != 0) {
		return fmt.Errorf("conflict body parameter in path %s", r.path)
	}
	path := r.endpoint
	for _, v := range r.segments {
		value := v.value
		if v.name != "" {
			p := r.paths[v.name]
			if p == nil {
				return fmt.Errorf("can't find path parameter %s in path %s", v.name, r.path)
			}
			value = fmt.Sprint(p)
		}
		path += value
	}
	urlVal := url.Values{}
	for k, v := range r.queries {
		urlVal.Add(k, fmt.Sprint(v))
	}
	if len(urlVal) > 0 {
		path += "?" + urlVal.Encode()
	}
	contentType := r.bodyContentType
	buf := bytes.NewBuffer(nil)
	reader := io.Reader(buf)
	if r.body != nil {
		if body, ok := r.body.(io.Reader); ok {
			reader = body
		} else {
			switch contentType {
			case definition.MIMEJSON:
				if err := json.NewEncoder(buf).Encode(r.body); err != nil {
					return err
				}
			case definition.MIMEXML:
				if err := xml.NewEncoder(buf).Encode(r.body); err != nil {
					return err
				}
			default:
				if _, err := buf.WriteString(fmt.Sprint()); err != nil {
					return err
				}
			}
		}
	} else {
		if len(r.files) > 0 {
			parts := multipart.NewWriter(buf)
			for k, v := range r.forms {
				w, err := parts.CreateFormField(k)
				if err != nil {
					return err
				}
				if _, err = fmt.Fprint(w, v); err != nil {
					return err
				}
			}
			for k, v := range r.files {
				w, err := parts.CreateFormFile(k, k)
				if err != nil {
					return err
				}
				if r, ok := v.(io.Reader); ok {
					if _, err := io.Copy(w, r); err != nil {
						return err
					}
				} else {
					switch data := v.(type) {
					case []byte:
						if _, err := w.Write(data); err != nil {
							return err
						}
					default:
						if _, err = fmt.Fprint(w, v); err != nil {
							return err
						}
					}
				}
			}
			contentType = parts.FormDataContentType()
		} else if len(r.forms) > 0 {
			contentType = definition.MIMEURLEncoded
			formVal := url.Values{}
			for k, v := range r.forms {
				formVal.Add(k, fmt.Sprint(v))
			}
			_, err := buf.WriteString(formVal.Encode())
			if err != nil {
				return err
			}
		}
	}
	req, err := http.NewRequest(r.method, path, reader)
	if err != nil {
		return err
	}
	for k, v := range r.headers {
		req.Header.Add(k, fmt.Sprint(v))
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if r.meta != nil {
		for k, v := range resp.Header {
			if len(v) > 0 {
				r.meta[k] = v[0]
			} else {
				r.meta[k] = ""
			}
		}
	}
	ct := resp.Header.Get("Content-Type")
	contentType, _, err = mime.ParseMediaType(ct)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 299 {
		if r.data != nil {
			switch target := r.data.(type) {
			case *io.ReadCloser:
				*target = resp.Body
			case *[]byte:
				data, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				if err := resp.Body.Close(); err != nil {
					return err
				}
				*target = data
			case *string:
				data, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				if err := resp.Body.Close(); err != nil {
					return err
				}
				*target = string(data)
			}
			switch contentType {
			case definition.MIMEJSON:
				if err := json.NewDecoder(resp.Body).Decode(r.data); err != nil {
					return err
				}
			case definition.MIMEXML:
				if err := xml.NewDecoder(resp.Body).Decode(r.data); err != nil {
					return err
				}
			default:
				return fmt.Errorf("can't parse data with type %s", contentType)
			}
		}
	} else {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		dt := errors.DataTypePlain
		switch contentType {
		case definition.MIMEJSON:
			dt = errors.DataTypeJSON
		case definition.MIMEXML:
			dt = errors.DataTypeXML
		}
		e, err := errors.ParseError(resp.StatusCode, dt, data)
		if err != nil {
			return err
		}
		return e
	}
	return nil
}

type segment struct {
	name  string
	value string
}

func parsePath(path string) ([]segment, error) {
	paths, err := router.Split(path)
	if err != nil {
		return nil, err
	}
	segments := make([]segment, len(paths))
	for i, p := range paths {
		if strings.HasPrefix(p, "{") {
			p = p[1 : len(p)-1]
			index := strings.Index(p, ":")
			if index > 0 {
				segments[i].name = p[:index]
			} else {
				segments[i].name = p
			}
		} else {
			segments[i].value = p
		}
	}
	return segments, nil
}
