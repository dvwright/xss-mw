// Copyright 2016 David Wright. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package xss

// XssMw provides an auto remove XSS from all submitted user input.
// It's applied on POST and PUT Requests only.
//
// We currently support three Request types:
// JSON requests - Content-Type application/json
// Form Encoded - Content-Type application/x-www-form-urlencoded
// Multipart Form Data - Content-Type multipart/form-data
//
// XSS filtering is performed by HTML sanitizer https://github.com/microcosm-cc/bluemonday
// The default uses the strictest policy - StrictPolicy()
//
//[TODO - how to expose bluemonday?]
//
// TODO
// add option to pass through XSS to the database and filter out only on the Response.
// - in other words - data would be stored in the database as it was submitted
// Pros: data integrity
// Cons: XSS exploits still present
//
// NOTE: This is Beta level code with minimal real world usage, use at your own risk - not production ready.
//

// NOTE: There is plenty of inefficient code which can and will be improved

import (
	"errors"
	"github.com/gin-gonic/gin"
	//"net/http/httputil" // debugging
	//"reflect" // debugging type
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	//"html"
	"io/ioutil"
	//"net/url"
	"github.com/microcosm-cc/bluemonday"
	"io"
	"mime/multipart"
	"strconv"
	"strings"
)

// TODO - add features/configuration
type XssMw struct {
	// List of tables to not filter any fields on
	TablesToSkip []string

	// List of fields to not filter . i.e. created_on, created_at, etc
	FieldsToSkip []string

	// Hash of table->field combinations to skip filtering on
	TableFieldRelationToSkip map[string]string

	// Config options - how much filtering? Regular | Lite | Custom

	//PayloadFunc func(userID string) map[string]interface{}
	// User can define own Unauthorized func.
	//Unauthorized func(*gin.Context, int, string)
}

type XssMwJson map[string]interface{}

// XssMw implements the Gin Middleware interface.
func (mw *XssMw) RemoveXss() gin.HandlerFunc {

	// TODO - should make this overwriteable in case user does not want any safe fields
	mw.FieldsToSkip = append(mw.FieldsToSkip, "password")

	return func(c *gin.Context) {
		mw.callRemoveXss(c)
		return
	}
}

// call to do removal and pass to next handler
// bails if really bad stuff happens
func (mw *XssMw) callRemoveXss(c *gin.Context) {
	err := mw.XssRemove(c)

	if err != nil {
		fmt.Printf("%v", err)
		c.Abort()
		return
	}

	// ok, pass to next handler
	c.Next()
}

// TODO refactor

// Receives an http request object, processes the body, removing html and returns the request.
// it passes through the headers (and other parts of the request) untouched.
//
// The Request must be Content-Type = application/json - TODO make work for other types.
// There must be a body. i.e. Content-Length > 1
//
// Request Method must be "POST" or "PUT"
//
func (mw *XssMw) XssRemove(c *gin.Context) error {
	//dump, derr := httputil.DumpRequest(c.Request, true)
	//fmt.Print(derr)
	//fmt.Printf("%q", dump)

	//ReqHeader := c.Request.Header
	//fmt.Printf("%v Header\n", ReqHeader)

	// https://golang.org/pkg/net/http/#Request

	ReqMethod := c.Request.Method
	//fmt.Printf("%v Method\n", ReqMethod)

	//ReqBody := c.Request.Body
	//fmt.Printf("%v URL\n", ReqBody)

	// [application/json] only supported
	ct_hdr := c.Request.Header.Get("Content-Type")
	//fmt.Printf("%v\n", ct_hdr)

	cts_len := c.Request.Header.Get("Content-Length")
	//fmt.Printf("%v\n", cts_len)
	ct_len, _ := strconv.Atoi(cts_len)

	// https://golang.org/src/net/http/request.go
	// check expected application type
	if ReqMethod == "POST" || ReqMethod == "PUT" {
		//ReqURL := c.Request.URL
		//fmt.Printf("%v URL\n", ReqURL)

		//// TODO URL's TO SKIP
		//// will have to be a regex or indexof in reality
		//// XXX we wont know id value (at end)
		//if ReqURL.String() == "/api/v1/end_point/1" {
		//	fmt.Printf("Skipping URL: %v\n", ReqURL)
		//	return nil
		//}
		//if ReqURL.String() == "/api/v1/end_point2/1" {
		//	fmt.Printf("Skipping URL: %v\n", ReqURL)
		//	return nil
		//}

		if ct_len > 1 && ct_hdr == "application/json" {
			err := mw.HandleJson(c)
			if err != nil {
				return err
			}
		} else if ct_hdr == "application/x-www-form-urlencoded" {
			err := mw.HandleXFormEncoded(c)
			if err != nil {
				return err
			}
		} else if strings.Contains(ct_hdr, "multipart/form-data") {
			err := mw.HandleMultiPartFormData(c, ct_hdr)
			if err != nil {
				return err
			}
		}

	}
	// if here, all should be well or nothing was actually done,
	// either way return happily
	return nil
}

// XXX file part uploads?
// just do basic fields - how to tell difference?

// Handles Content-Type "application/x-www-form-urlencoded"
// Has been tested only with basic param=value form fields
// i.e comment=<img src=x onerror=alert(0)>
//     &cre_at=1481017167
//     &email=testUser@example.com
//     &flt=2.345
//     &id=2
//     &password=TestPass
//     &user=TestUser
// has not been tested on file/data uploads
// NOTE: any form field - param key named 'password' is skipped (not sanitized)
func (mw *XssMw) HandleXFormEncoded(c *gin.Context) error {
	//fmt.Println("TODO handle application/x-www-form-urlencoded")
	//dump, _ := httputil.DumpRequest(c.Request, true)
	//fmt.Printf("%q", dump)

	// https://golang.org/src/net/http/httputil/dump.go
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(c.Request.Body); err != nil {
		return err
	}
	//comment=%3E%27%3E%5C%22%3E%3Cimg+src%3Dx+onerror%3Dalert%280%29%3E&cre_at=1481017167&email=testUser%40example.com&flt=2.345&id=2&password=%21%40%24%25%5EASDF&user=TestUser
	//fmt.Println("%v", buf.String())

	m, uerr := url.ParseQuery(buf.String())
	if uerr != nil {
		return uerr
	}

	p := bluemonday.StrictPolicy()

	var bq bytes.Buffer
	for k, v := range m {
		//fmt.Println(k, " => ", v)
		bq.WriteString(k)
		bq.WriteByte('=')
		if k == "password" { // dont saniitize password field
			bq.WriteString(url.QueryEscape(v[0]))
		} else {
			bq.WriteString(url.QueryEscape(p.Sanitize(v[0])))
		}
		bq.WriteByte('&')
	}
	bq.Truncate(bq.Len() - 1) // remove last '&'
	bodOut := bq.String()

	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bodOut)))

	return nil
}

// Handles Content-Type "multipart/form-data"
// skips sanitizing if file upload
// i.e. Content-Disposition: form-data; name="" filename=""
// tries to determine Content-type for form data file upload, defaults
// to application/octet-stream if unknown
// handles basic form field POST request
// i.e:
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//Content-Disposition: form-data; name="flt"
//
//2.345
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//Content-Disposition: form-data; name="user"
//
//TestUser
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//Content-Disposition: form-data; name="email"
//
//testUser@example.com
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//281         }
//Content-Disposition: form-data; name="password"
//
//!@$%^ASDF
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//Content-Disposition: form-data; name="comment"
//
//&gt;&#39;&gt;\&#34;&gt;
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//Content-Disposition: form-data; name="cre_at"
//
//1481017167
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//Content-Disposition: form-data; name="id"
//
//2
//--3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909--
//
// NOTE: form-data name 'password' is skipped (not sanitized)
func (mw *XssMw) HandleMultiPartFormData(c *gin.Context, ct_hdr string) error {
	var ioreader io.Reader = c.Request.Body

	boundary := ct_hdr[strings.Index(ct_hdr, "boundary=")+9 : len(ct_hdr)]

	reader := multipart.NewReader(ioreader, boundary)

	var multiPrtFrm bytes.Buffer
	// unknown, so make up some param limit - 100 max should be enough
	for i := 0; i < 100; i++ {
		part, err := reader.NextPart()
		if err != nil {
			//fmt.Println("didn't get a part")
			break
		}

		var buf bytes.Buffer
		n, err := io.Copy(&buf, part)
		if err != nil {
			//fmt.Println("error reading part: %v\nread so far: %q", err, buf.String())
			return err
		}
		// XXX needed?
		if n <= 0 {
			//fmt.Println("read %d bytes; expected >0", n)
			return errors.New("error recreating Multipart form Request")
		}
		// https://golang.org/src/mime/multipart/multipart_test.go line 230
		multiPrtFrm.WriteString(`--` + boundary + "\r\n")
		// dont sanitize file content
		if part.FileName() != "" {
			fn := part.FileName()
			mtype := part.Header.Get("Content-Type")
			multiPrtFrm.WriteString(`Content-Disposition: form-data; name="` + part.FormName() + "\"; ")
			multiPrtFrm.WriteString(`filename="` + fn + "\";\r\n")
			// default to application/octet-stream
			if mtype == "" {
				mtype = `application/octet-stream`
			}
			multiPrtFrm.WriteString(`Content-Type: ` + mtype + "\r\n\r\n")
			multiPrtFrm.WriteString(buf.String() + "\r\n")
		} else {
			multiPrtFrm.WriteString(`Content-Disposition: form-data; name="` + part.FormName() + "\";\r\n\r\n")
			p := bluemonday.StrictPolicy()
			if "password" == part.FormName() {
				multiPrtFrm.WriteString(buf.String() + "\r\n")
			} else {
				multiPrtFrm.WriteString(p.Sanitize(buf.String()) + "\r\n")
			}
		}
	}
	multiPrtFrm.WriteString("--" + boundary + "--\r\n")

	//fmt.Println("MultiPartForm Out %v", multiPrtFrm.String())

	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(multiPrtFrm.String())))

	return nil
}

// Handles request Content-Type = application/json
//
// The three types of data handled.
//
// 1st type filter - basic key:value - most common
//map[string]interface {}{"updated_by":"534", "updated_at":"1480831130", "id":"1", "name":"foo"}
//
// 2nd type an id with associated ids list
// map[string]interface {}{"project_id":"1", "talent_ids":[]interface {}{"1", "4", "8"}}
// NOTE changes from ["1", "4", "8"] to [1,4,8]
//
// 3rd type an "array of records"
// []interface {}{
//    map[string]interface {}{"name":"asd", "url":"/data/1/as",
//                            "user_id":"537", "username":"Test User ©", "created_by":"537", "id":"286",
//                            "fqdn":"audio class", "project_id":"1", "path":"/tmp/store/1/as",
//                            "updated_at":"1480791630", "status":"NEW",
//                            "updated_by":"537", "created_at":"1480450694"},
//    map[string]interface {}{"name":"asd2", "url":"/data/2/as", etc... },
//    map[string]interface {}{"name":"asd3", "url":"/data/3/as", etc... },
//    ...
// }
// NOTE: param key named 'password' is skipped (not sanitized)
func (mw *XssMw) HandleJson(c *gin.Context) error {
	var jsonBod interface{}
	d := json.NewDecoder(c.Request.Body)
	d.UseNumber()
	jsnErr := d.Decode(&jsonBod)
	//fmt.Printf("JSON BOD: %#v\n", jsonBod)

	if jsnErr == nil {
		switch jbt := jsonBod.(type) {
		// most common
		case map[string]interface{}:
			//fmt.Printf("\n\n\n1st type\n\n\n")
			xmj := jsonBod.(map[string]interface{})
			buff := mw.ApplyXssPolicyJson(xmj)
			err := mw.SetRequestBodyJson(c, buff)
			if err != nil {
				//fmt.Println("Set request body failed")
				return errors.New("Set Request.Body Error")
			}
		// a multi records request
		case []interface{}:
			var multiRec bytes.Buffer
			multiRec.WriteString(`[`)
			for _, n := range jbt {
				//fmt.Printf("Item: %v= %v\n", i, n)
				xmj := n.(map[string]interface{})
				buff := mw.ApplyXssPolicyJson(xmj)
				multiRec.WriteString(buff.String() + `,`)
			}
			multiRec.Truncate(multiRec.Len() - 1) // remove last ','
			multiRec.WriteString(`]`)
			err := mw.SetRequestBodyJson(c, multiRec)
			if err != nil {
				//fmt.Println("Set request body failed")
				return errors.New("Set Request.Body Error")
			}
		default:
			//var r = reflect.TypeOf(jbt) // debug type
			//fmt.Printf("Unknown Type!:%v\n", r)
			return errors.New("Unknown Content Type Received")
		}

	} else {
		return errors.New("Error attempting to decode JSON")
	}
	return nil
}

// encode processed body back to json and re set http request body
func (mw *XssMw) SetRequestBodyJson(c *gin.Context, buff bytes.Buffer) error {
	// XXX clean up - probably don't need to convert to string
	// only to convert back to NewBuffer for NopCloser
	bodOut := buff.String()

	enc := json.NewEncoder(ioutil.Discard)
	if merr := enc.Encode(&bodOut); merr != nil {
		fmt.Printf("%v", merr)
		return merr
	}

	//fmt.Printf("ReqBody Pre: %v\n", c.Request.Body)
	//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(buff.String())))
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bodOut)))

	//fmt.Printf("ReqBody Post: %v\n", c.Request.Body)
	//fmt.Printf("ReqBody Post: %#v\n", c.Request.Body)
	return nil
}

// De constructs the http request body
// removes undesirable content
// keep the good content to construct and return cleaned http request
// takes arg map[string]interface{} and a bluemonday Policy
// returns bytes.Buffer
func (mw *XssMw) ApplyXssPolicyJson(xmj XssMwJson) bytes.Buffer {
	//fmt.Printf("JSON BOD: %#v\n", xmj)

	var buff bytes.Buffer
	buff.WriteString(`{`)

	// TODO should be passed in to method
	// needs to be configurable - set in passed struct
	// right now it's strict mode or the highway...
	//p := bluemonday.UGCPolicy()
	p := bluemonday.StrictPolicy()

	m := xmj //m := jsonBod.(map[string]interface{})
	for k, v := range m {
		//fmt.Println(k, v)

		buff.WriteString(`"` + k + `":`)

		// TODO implement config passing fields to skip
		//for _, v := range mw.FieldsToSkip {
		//fmt.Printf(v)
		//if string(k) == v {
		if string(k) == "password" {
			// argh, work needed here - for now - assume string
			//fmt.Println(k, "is string", v)
			buff.WriteString(`"` + fmt.Sprintf("%s", v) + `",`)
			continue
		}
		//}

		switch vv := v.(type) { // FYI, JSON data is string or float
		case string:
			//fmt.Println(k, "is string", vv)
			buff.WriteString(`"` + p.Sanitize(vv) + `",`)
		case float64:
			//fmt.Println(k, "is float", vv)
			//buff.WriteString(strconv.FormatFloat(vv, 'g', 0, 64))
			//buff.WriteString(html.EscapeString(strconv.FormatFloat(vv, 'g', 0, 64)))
			buff.WriteString(p.Sanitize(strconv.FormatFloat(vv, 'g', 0, 64)) + `,`)
		default:
			switch vvv := vv.(type) {
			// probably not very common request but I do it
			// map[string]interface {}{"id":"1", "assoc_ids":[]interface {}{"1", "4", "8"}}
			case []interface{}:
				var lst bytes.Buffer
				lst.WriteString(`[`)
				for _, n := range vvv {
					//fmt.Printf("Iter: %v= %v\n", i, n)
					//lst.WriteString(p.Sanitize(fmt.Sprintf("\"%v\"", n)))
					// NOTE changes from ["1", "4", "8"] to [1,4,8]
					lst.WriteString(p.Sanitize(fmt.Sprintf("%v", n)))
					lst.WriteString(`,`)
				}
				lst.Truncate(lst.Len() - 1) // remove last ','
				lst.WriteString(`]`)
				buff.WriteString(lst.String())
				buff.WriteString(`,`) // add cause expected
			default:
				//fmt.Println(k, "don't know how to handle")
				//fmt.Println("%#v", vvv) ; fmt.Sprintf("%v", vvv)
				buff.WriteString(p.Sanitize(fmt.Sprintf("%v", vvv)) + `,`)
			}
		}
	}
	buff.Truncate(buff.Len() - 1) // remove last ','
	buff.WriteString(`}`)

	return buff
}

// TODO
// add feature to accept all content in Request and filter out on Response
// NOTE: I don't know how to achieve this yet... will something like this help?
// gin help said call Next first to capture Response
//func ConstructRequest(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		fmt.Println(r.Method, "-", r.RequestURI)
//		cookie, _ := r.Cookie("username")
//		if cookie != nil {
//			//Add data to context
//			ctx := context.WithValue(r.Context(), "Username", cookie.Value)
//			next.ServeHTTP(w, r.WithContext(ctx))
//		} else {
//			next.ServeHTTP(w, r)
//		}
//	})
//}
