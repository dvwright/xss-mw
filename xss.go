// Copyright 2016 David Wright. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

// XssMw provides an "auto remove XSS" from all user submitted input.
//
// It's applied on POST, PUT, and GET Requests only.
//
// We currently support three Request types:
//
// * JSON requests - Content-Type application/json
//
// * Form Encoded - Content-Type application/x-www-form-urlencoded
//
// * Multipart Form Data - Content-Type multipart/form-data
//
// XSS filtering is performed by HTML sanitizer https://github.com/microcosm-cc/bluemonday
//
// # The two packaged policies are available, UGCPolicy or StrictPolicy
//
// The default is to the strictest policy - StrictPolicy()
//
//	use of UGCPolicy is untested at this time
package xss

// TODO: support User supplied Bluemondy policy
// I believe we will have to expose a config option for
// the ways to build a bluemonday policy
// e.g AllowStandardAtritubes, AllowStandardURLs, AllowElements, AllowAttrs, etc

// TODO - filter on Response not Request -> r.Use(xss.FilterXss())
// add option to pass through XSS to the database and filter out only on the Response.
// - in other words - data would be stored in the database as it was submitted
// Pros: data integrity
// Cons: XSS exploits still present

import (
	"errors"

	"github.com/gin-gonic/gin"

	//"net/http/httputil" // debugging
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"

	"github.com/microcosm-cc/bluemonday"

	//"reflect" // debugging type
	"strconv"
	"strings"
)

// Config struct for passing options
type XssMw struct {
	// List of fields to not filter. i.e. password, created_on, created_at, etc
	// password is set to skip by the system i.e. FieldsToSkip = []string{"password", "cre_date"}
	FieldsToSkip []string

	// TODO: need more granular skipping...
	// List of tables to not filter any fields on
	// how would you know this, coming from front end forms/params?
	//TablesToSkip []string

	// Hash of table->field combinations to skip filtering on
	//TableFieldRelationToSkip map[string]string

	// Bluemonday comes with two default policies
	// Two options StrictPolicy // the default
	//             UGCPolicy
	// or you can specify you own policy
	// define it somewhere in your package so that you can call it here
	// see https://github.com/microcosm-cc/bluemonday/blob/master/policies.go
	// This must contain one of three possible settings:
	//             StrictPolicy // the default
	//             UGCPolicy
	//             New          // Specify your own policy - not yet supported
	BmPolicy string
}

type XssMwJson map[string]any

// XssMw implements the Gin Middleware any.
func (mw *XssMw) RemoveXss() gin.HandlerFunc {

	// TODO - should make this overwriteable in case user does not want any safe fields
	mw.FieldsToSkip = append(mw.FieldsToSkip, "password")

	return func(c *gin.Context) {
		mw.callRemoveXss(c)
	}
}

// call to do removal and pass to next handler
// bails if really bad stuff happens
func (mw *XssMw) callRemoveXss(c *gin.Context) {
	// Bluemonday Policy
	if mw.BmPolicy == "" {
		mw.BmPolicy = "StrictPolicy"
		// TODO
		//} else if mw.BmPolicy != "StrictPolicy" && mw.BmPolicy != "UGCPolicy" && mw.BmPolicy != "New" {
	} else if mw.BmPolicy != "StrictPolicy" && mw.BmPolicy != "UGCPolicy" {
		fmt.Println("BlueMondy Policy setting is incorrect!")
		c.Abort()
		return
	}

	err := mw.XssRemove(c)

	if err != nil {
		fmt.Printf("%v", err)
		c.Abort()
		return
	}

	// ok, pass to next handler
	c.Next()
}

// TODO: too bad we can't do reflection here. I believe the only way is to build
// a new policy config setting by config setting... argh

// Get which Bluemonday policy
func (mw *XssMw) GetBlueMondayPolicy() *bluemonday.Policy {

	if mw.BmPolicy == "UGCPolicy" {
		return bluemonday.UGCPolicy()
		//} else if mw.BmPolicy == "New" {
		//	// TODO: will have to construct one with settings passed
		//	fmt.Println("New Not Yet Implemented!")
	}

	// default
	return bluemonday.StrictPolicy()
}

// TODO refactor

// Receives an http request object, processes the body, removing html and returns the request.
//
// Headers (and other parts of the request) are passed through unaltered.
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
	ctHdr := c.Request.Header.Get("Content-Type")
	//fmt.Printf("%v\n", ctHdr)

	ctsLen := c.Request.Header.Get("Content-Length")
	//fmt.Printf("%v\n", ctsLen)
	ctLen, _ := strconv.Atoi(ctsLen)

	// https://golang.org/src/net/http/request.go
	// check expected application type
	switch ReqMethod {
	case "POST", "PUT":
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

		if ctLen > 1 && ctHdr == "application/json" {
			err := mw.HandleJson(c)
			if err != nil {
				return err
			}
		} else if ctHdr == "application/x-www-form-urlencoded" {
			err := mw.HandleXFormEncoded(c)
			if err != nil {
				return err
			}
		} else if strings.Contains(ctHdr, "multipart/form-data") {
			err := mw.HandleMultiPartFormData(c, ctHdr)
			if err != nil {
				return err
			}
		}
	case "GET":
		err := mw.HandleGETRequest(c)
		if err != nil {
			return err
		}
	}
	// if here, all should be well or nothing was actually done,
	// either way return happily
	return nil
}

// HandleGETRequest handles get request
func (mw *XssMw) HandleGETRequest(c *gin.Context) error {
	p := mw.GetBlueMondayPolicy()
	queryParams := c.Request.URL.Query()
	var fieldToSkip = map[string]bool{}
	for _, fts := range mw.FieldsToSkip {
		fieldToSkip[fts] = true
	}
	for key, items := range queryParams {
		if fieldToSkip[key] {
			continue
		}
		queryParams.Del(key)
		for _, item := range items {
			queryParams.Add(key, p.Sanitize(item))
		}
	}
	c.Request.URL.RawQuery = queryParams.Encode()
	return nil
}

// XXX file part uploads?
// just do basic fields - how to tell difference?

// Handles Content-Type "application/x-www-form-urlencoded"
//
// Has been tested with basic param=value form fields only:
//
//     comment=<img src=x onerror=alert(0)>
//     &cre_at=1481017167
//     &email=testUser@example.com
//     &flt=2.345
//     &id=2
//     &password=TestPass
//     &user=TestUser
//
// has not been tested on file/data uploads
//
func (mw *XssMw) HandleXFormEncoded(c *gin.Context) error {
	//fmt.Println("TODO handle application/x-www-form-urlencoded")
	//dump, _ := httputil.DumpRequest(c.Request, true)
	//fmt.Printf("%q", dump)
	if c.Request.Body == nil {
		return nil
	}

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

	p := mw.GetBlueMondayPolicy()

	var bq bytes.Buffer
	for k, v := range m {
		//fmt.Println(k, " => ", v)
		bq.WriteString(k)
		bq.WriteByte('=')

		// do fields to skip
		var fndFld bool = false
		for _, fts := range mw.FieldsToSkip {
			if k == fts {
				// dont saniitize these fields
				bq.WriteString(url.QueryEscape(v[0]))
				fndFld = true
				break
			}
		}
		if !fndFld {
			bq.WriteString(url.QueryEscape(p.Sanitize(v[0])))
		}
		bq.WriteByte('&')
	}

	if bq.Len() > 1 {
		bq.Truncate(bq.Len() - 1) // remove last '&'
		bodOut := bq.String()
		c.Request.Body = io.NopCloser(bytes.NewBuffer([]byte(bodOut)))
	} else {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(buf.Bytes()))
	}

	return nil
}

// Handles Content-Type "multipart/form-data"
//
// skips sanitizing if file upload
//    Content-Disposition: form-data; name="" filename=""
//
// tries to determine Content-type for form data file upload, defaults
// to application/octet-stream if unknown
//
// handles basic form field POST request for example:
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   Content-Disposition: form-data; name="flt"
//
//   2.345
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   Content-Disposition: form-data; name="user"
//
//   TestUser
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   Content-Disposition: form-data; name="email"
//
//   testUser@example.com
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   281         }
//   Content-Disposition: form-data; name="password"
//
//   !@$%^ASDF
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   Content-Disposition: form-data; name="comment"
//
//   &gt;&#39;&gt;\&#34;&gt;
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   Content-Disposition: form-data; name="cre_at"
//
//   1481017167
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909
//   Content-Disposition: form-data; name="id"
//
//   2
//   --3af5c5b7adcb2142f404a8e1ce280c47c58e563e3d4c1e172490737c9909--
//
// NOTE: form-data name 'password' is skipped (not sanitized)
func (mw *XssMw) HandleMultiPartFormData(c *gin.Context, ctHdr string) error {
	var ioreader io.Reader = c.Request.Body

	boundary := ctHdr[strings.Index(ctHdr, "boundary=")+9 : ]

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
			if part.FormName() == "password" {
				multiPrtFrm.WriteString(buf.String() + "\r\n")
			} else {
				multiPrtFrm.WriteString(p.Sanitize(buf.String()) + "\r\n")
			}
		}
	}
	multiPrtFrm.WriteString("--" + boundary + "--\r\n")

	//fmt.Println("MultiPartForm Out %v", multiPrtFrm.String())

	c.Request.Body = io.NopCloser(bytes.NewBuffer(multiPrtFrm.Bytes()))

	return nil
}

// Handles request Content-Type = application/json
//
// The four types of data handled.
//
// * 1st type filter - basic key:value - most common
//
//    map[string]any {}{"updated_by":"534", "updated_at":"1480831130", "id":"1", "name":"foo"}
//
// * 2nd type an id with associated ids list
//
//     map[string]any {}{"project_id":"1", "talent_ids":[]any {}{"1", "4", "8"}}
// - NOTE changes from ["1", "4", "8"] to [1,4,8]
//
// * 3rd type an "array of records"
//
//   []any {}{
//      map[string]any {}{"name":"asd", "url":"/data/1/as",
//                              "user_id":"537", "username":"Test User ©", "created_by":"537", "id":"286",
//                              "fqdn":"audio class", "project_id":"1", "path":"/tmp/store/1/as",
//                              "updated_at":"1480791630", "status":"NEW",
//                              "updated_by":"537", "created_at":"1480450694"},
//      map[string]any {}{"name":"asd2", "url":"/data/2/as", etc... },
//      map[string]any {}{"name":"asd3", "url":"/data/3/as", etc... },
//      ...
//   }
//
// * 4th type "complex array/nested records"
//
//  map[string]any {}{
//      "id":"1",
//      "users":[]any {}{
//           map[string]any {}{"id":"1", "flt":"1.345", "user":"TestUser1", "email":"testUser1@example.com", "password":"!@$%^ASDF<html>1", "comment":"<img src=x onerror=alert(0)>", "cre_at":"1481017167"},
//           map[string]any {}{"cre_at":"1481017167", "id":"2", "flt":"2.345", "user":"TestUser2", "email":"testUser2@example.com", "password":"!@$%^ASDF<html>2", "comment":"<img src=x onerror=alert(0)>"}
//      }
//}

func (mw *XssMw) HandleJson(c *gin.Context) error {
	jsonBod, err := decodeJson(c.Request.Body)
	if err != nil {
		return err
	}

	buff, err := mw.jsonToStringMap(bytes.Buffer{}, jsonBod)
	if err != nil {
		return err
	}
	//fmt.Println("DONE JSON")
	//fmt.Println(buff.String())

	err = mw.SetRequestBodyJson(c, buff)
	if err != nil {
		//fmt.Println("Set request body failed")
		return errors.New("set request.Body error")
	}
	return nil
}

func decodeJson(content io.Reader) (any, error) {
	var jsonBod any
	d := json.NewDecoder(content)
	d.UseNumber()
	err := d.Decode(&jsonBod)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("JSON BOD: %#v\n", jsonBod)
	return jsonBod, err
}

func (mw *XssMw) jsonToStringMap(buff bytes.Buffer, jsonBod any) (bytes.Buffer, error) {
	switch jbt := jsonBod.(type) {
	case map[string]any:
		//fmt.Printf("\n\n\n1st type\n\n\n")
		xmj := jsonBod.(map[string]any)
		var sbuff bytes.Buffer
		buff := mw.ConstructJson(xmj, sbuff)
		return buff, nil
	// TODO: need a test to prove this
	case []any:
		var multiRec bytes.Buffer
		multiRec.WriteByte('[')
		for _, n := range jbt {
			switch nt := n.(type) {
			case map[string]any:
				var sbuff bytes.Buffer
				buff = mw.ConstructJson(nt, sbuff)
				multiRec.WriteString(buff.String())
			case string:
				multiRec.WriteString(`"` + mw.escapeString(nt) + `"`)
			default:
				return bytes.Buffer{}, errors.New("unknown content type received")
			}
			multiRec.WriteByte(',')
		}
		if multiRec.Len() > 1 {
			multiRec.Truncate(multiRec.Len() - 1) // remove last ','
		}
		multiRec.WriteByte(']')
		return multiRec, nil
	default:
		//var r = reflect.TypeOf(jbt) // debug type
		//fmt.Printf("Unknown Type!:%v\n", r)
		return bytes.Buffer{}, errors.New("unknown content type received")
	}
}

// encode processed body back to json and re-set http request body
func (mw *XssMw) SetRequestBodyJson(c *gin.Context, buff bytes.Buffer) error {
	// XXX clean up - probably don't need to convert to string
	// only to convert back to NewBuffer for NopCloser
	bodOut := buff.String()
	//fmt.Printf("BodOut: %v\n", bodOut)

	enc := json.NewEncoder(io.Discard)
	//enc.SetEscapeHTML(false)
	if merr := enc.Encode(&bodOut); merr != nil {
		//fmt.Printf("%v", merr)
		return merr
	}
	//fmt.Printf("BodOut2: %v\n", bodOut)

	//fmt.Printf("ReqBody Pre: %v\n", c.Request.Body)
	//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(buff.String())))
	c.Request.Body = io.NopCloser(bytes.NewBuffer([]byte(bodOut)))

	//fmt.Printf("ReqBody Post: %v\n", c.Request.Body)
	//fmt.Printf("ReqBody Post: %#v\n", c.Request.Body)
	return nil
}

// De-constructs the http request body
// removes undesirable content
// keeps the good content to construct
// returns the cleaned http request
// Map to Bytes (struct to json string...)
func (mw *XssMw) ConstructJson(xmj XssMwJson, buff bytes.Buffer) bytes.Buffer {
	//var buff bytes.Buffer
	buff.WriteByte('{')

	p := mw.GetBlueMondayPolicy()

	m := xmj
	for k, v := range m {
		buff.WriteByte('"')
		buff.WriteString(k)
		buff.WriteByte('"')
		buff.WriteByte(':')

		// do fields to skip
		var fndFld bool = false
		for _, fts := range mw.FieldsToSkip {
			if string(k) == fts {
				//buff.WriteString(`"` + fmt.Sprintf("%s", v) + `",`)
				buff.WriteString(fmt.Sprintf("%q", v))
				buff.WriteByte(',')
				fndFld = true
				break
			}
		}
		if fndFld {
			continue
		}

		var b bytes.Buffer
		apndBuff := mw.buildJsonApplyPolicy(v, b, p)
		buff.WriteString(apndBuff.String())
	}
	buff.Truncate(buff.Len() - 1) // remove last ','
	buff.WriteByte('}')

	return buff
}

func (mw *XssMw) buildJsonApplyPolicy(interf any, buff bytes.Buffer, p *bluemonday.Policy) bytes.Buffer {
	switch v := interf.(type) {
	case map[string]any:
		var sbuff bytes.Buffer
		scnd := mw.ConstructJson(v, sbuff)
		buff.WriteString(scnd.String())
		buff.WriteByte(',')
	case []any:
		b := mw.unravelSlice(v, p)
		buff.WriteString(b.String())
		buff.WriteByte(',')
	case json.Number:
		buff.WriteString(p.Sanitize(fmt.Sprintf("%v", v)))
		buff.WriteByte(',')
	case string:
		buff.WriteString(fmt.Sprintf("%q", p.Sanitize(v)))
		buff.WriteByte(',')
	case float64:
		buff.WriteString(p.Sanitize(strconv.FormatFloat(v, 'g', 0, 64)))
		buff.WriteByte(',')
	default:
		if v == nil {
			buff.WriteString("null")
			buff.WriteByte(',')
		} else {
			buff.WriteString(p.Sanitize(fmt.Sprintf("%v", v)))
			buff.WriteByte(',')
		}
	}
	return buff
}

func (mw *XssMw) unravelSlice(slce []any, p *bluemonday.Policy) bytes.Buffer {
	var buff bytes.Buffer
	buff.WriteByte('[')
	for _, n := range slce {
		switch nn := n.(type) {
		case map[string]any:
			var sbuff bytes.Buffer
			scnd := mw.ConstructJson(nn, sbuff)
			buff.WriteString(scnd.String())
			buff.WriteByte(',')
		case string:
			buff.WriteString(fmt.Sprintf("%q", p.Sanitize(nn)))
			buff.WriteByte(',')
		}
	}
	buff.Truncate(buff.Len() - 1) // remove last ','
	buff.WriteByte(']')
	return buff
}

// escapeString escapes special JSON characters in a string.
func (mw *XssMw) escapeString(s string) string {
       var buf strings.Builder
       for _, r := range s {
               switch r {
               case '\\':
                       buf.WriteString(`\\`)
               case '"':
                       buf.WriteString(`\"`)
               case '\b':
                       buf.WriteString(`\b`)
               case '\f':
                       buf.WriteString(`\f`)
               case '\n':
                       buf.WriteString(`\n`)
               case '\r':
                       buf.WriteString(`\r`)
               case '\t':
                       buf.WriteString(`\t`)
               default:
                       buf.WriteRune(r)
               }
       }
       return buf.String()
}