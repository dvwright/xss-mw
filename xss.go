package xss

// MIT license
// Author david_v_wright@yahoo.com
//

// XssMw provides an auto remove malicious XSS from all submitted user input.
// The method is applied on all POST and PUT Requests only.

// it's highly configurable and uses HTML sanitizer https://github.com/microcosm-cc/bluemonday
// for filtering.
// TODO - how to expose bluemonday?

// TODO
// add option to accept XSS on http Request and apply filter on Response
// - in other words - data would be stored in the database as it was submitted
// - data integrity, XSS exploits and all

// NOTE: This is Beta level code at best and could be improved and speed ed up

import (
	"errors"
	"github.com/gin-gonic/gin"
	//"net/http/httputil" // debugging
	//"reflect" // debugging type
	"bytes"
	"encoding/json"
	"fmt"
	//"html"
	"io/ioutil"
	//"net/url"
	"github.com/microcosm-cc/bluemonday"
	"strconv"
)

// TODO - add features/configuration
type XssMw struct {
	// List of tables to not filter any fields on
	TableWhitelist []byte

	// List of fields to not filter . i.e. created_on, created_at, etc
	FieldWhitelist []byte

	// Hash of table->field combinations to skip filtering on
	TableFieldWhitelist []byte

	// Config options - how much filtering? Regular | Lite | Custom

	//PayloadFunc func(userID string) map[string]interface{}
	// User can define own Unauthorized func.
	//Unauthorized func(*gin.Context, int, string)

}

type XssMwJson map[string]interface{}

// makes XssMw implement the Gin Middleware interface.
func (mw *XssMw) RemoveXss() gin.HandlerFunc {
	return func(c *gin.Context) {
		mw.callRemoveXss(c)
		return
	}
}

func (mw *XssMw) callRemoveXss(c *gin.Context) {
	err := mw.XssRemove(c)

	if err != nil {
		fmt.Printf("%v", err)
		c.Abort()
		return
	}

	c.Next()
}

// NOTE: This middleware currently only supports on Content-Type = application/json

// only applied if http Request Method	"POST" or "PUT"
// removes xss of policy on 3 types of request

// 1st type filter - most common
//map[string]interface {}{"updated_by":"534", "updated_at":"1480831130", "id":"1", "name":"foo"}

// 2nd type an id with associated ids in array
// map[string]interface {}{"project_id":"1", "talent_ids":[]interface {}{"1", "4", "8"}}
// NOTE changes from ["1", "4", "8"] to [1,4,8]

// 3rd type an array of records
// []interface {}{map[string]interface {}{"name":"asd", "url":"/data/1/as",
// "user_id":"537", "username":"Test User ©", "created_by":"537", "id":"286",
//"fqdn":"audio class", "project_id":"1", "path":"/tmp/store/1/as",
// "updated_at":"1480791630", "status":"NEW",
// "updated_by":"537", "created_at":"1480450694"},  map[string]interface {}{"name":"asd", "url":"/data/1/as", etc
func (mw *XssMw) XssRemove(c *gin.Context) error {
	//dump, derr := httputil.DumpRequest(c.Request, true)
	//fmt.Print(derr)
	//fmt.Printf("%q", dump)

	//ReqHeader := c.Request.Header
	//fmt.Printf("%v Header\n", ReqHeader)

	// https://golang.org/pkg/net/http/#Request

	ReqMethod := c.Request.Method
	//fmt.Printf("%v Method\n", ReqMethod)

	ReqBody := c.Request.Body
	//fmt.Printf("%v URL\n", ReqBody)

	// [application/json] only supported
	ct_hdr := c.Request.Header.Get("Content-Type")
	//fmt.Printf("%v\n", ct_hdr)

	cts_len := c.Request.Header.Get("Content-Length")
	//fmt.Printf("%v\n", cts_len)
	ct_len, _ := strconv.Atoi(cts_len)

	// https://golang.org/src/net/http/request.go
	// set expected application type
	if ct_hdr == "application/json" && ct_len > 1 && (ReqMethod == "POST" || ReqMethod == "PUT") {

		//ReqURL := c.Request.URL
		//fmt.Printf("%v URL\n", ReqURL)

		//// TODO URL's TO SKIP
		//// will have to be a regex or index of in reality  -
		//// XXX we wont know id value (at end)
		//if ReqURL.String() == "/api/v1/project_talent_wanted/1" {
		//	fmt.Printf("Skipping URL: %v\n", ReqURL)
		//	return nil
		//}
		//if ReqURL.String() == "/api/v1/project_media/1" {
		//	fmt.Printf("Skipping URL: %v\n", ReqURL)
		//	return nil
		//}

		var jsonBod interface{}
		d := json.NewDecoder(ReqBody)
		d.UseNumber()
		jsnErr := d.Decode(&jsonBod)
		//fmt.Printf("JSON BOD: %#v\n", jsonBod)

		if jsnErr == nil {
			switch jbt := jsonBod.(type) {
			// most common
			case map[string]interface{}:
				//fmt.Printf("\n\n\n1st type\n\n\n")
				xmj := jsonBod.(map[string]interface{})
				buff := ApplyXssPolicy(xmj)
				err := SetRequestBody(c, buff)
				if err != nil {
					//fmt.Println("Set request body failed")
					return errors.New("Set Request.Body Error")
				}
			// a multi records request
			case []interface{}:
				var multiRec bytes.Buffer
				multiRec.WriteString(`[`)
				for i, n := range jbt {
					//fmt.Printf("Item: %v= %v\n", i, n)
					xmj := n.(map[string]interface{})
					buff := ApplyXssPolicy(xmj)
					multiRec.WriteString(buff.String() + `,`)
				}
				multiRec.Truncate(multiRec.Len() - 1) // remove last ','
				multiRec.WriteString(`]`)
				err := SetRequestBody(c, multiRec)
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
	}
	// if here, all should be well
	return nil
}

// encode json string to JSON
// set http request body to json string
func SetRequestBody(c *gin.Context, buff bytes.Buffer) error {
	// XXX clean up - probably don't need to convert to string
	// only to convert back to NewBuffer for NopCloser
	bodOut := buff.String()

	enc := json.NewEncoder(ioutil.Discard)
	if merr := enc.Encode(&bodOut); merr != nil {
		fmt.Printf("%v", merr)
		return merr
	}

	fmt.Printf("ReqBody Pre: %v\n", c.Request.Body)
	//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(buff.String())))
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bodOut)))

	fmt.Printf("ReqBody Post: %v\n", c.Request.Body)
	fmt.Printf("ReqBody Post: %#v\n", c.Request.Body)
	return nil
}

// TODO change method signature - func (xmj XssMwJson) ApplyXssPolicy(bytes.Buffer) {
// build response - method call
// takes arg map[string]interface{} and a bluemonday Policy
// returns bytes.Buffer
func ApplyXssPolicy(xmj XssMwJson) bytes.Buffer {

	fmt.Printf("JSON BOD: %#v\n", xmj)

	var buff bytes.Buffer
	buff.WriteString(`{`)

	// TODO should be passed in to method
	//p := bluemonday.UGCPolicy()
	p := bluemonday.StrictPolicy()

	m := xmj //m := jsonBod.(map[string]interface{})
	for k, v := range m {

		// TODO implement fields to skip
		//if string(k) == "fqdn_url" {
		//	continue
		//}

		//fmt.Println(k, v)

		buff.WriteString(`"` + k + `":`)

		switch vv := v.(type) { // FYI, JSON is string or float
		case string:
			buff.WriteString(`"` + p.Sanitize(vv) + `",`)
		case float64:
			//fmt.Println(k, "is float", vv)
			//buff.WriteString(strconv.FormatFloat(vv, 'g', 0, 64))
			//buff.WriteString(html.EscapeString(strconv.FormatFloat(vv, 'g', 0, 64)))
			buff.WriteString(p.Sanitize(strconv.FormatFloat(vv, 'g', 0, 64)) + `,`)
		default:
			switch vvv := vv.(type) {
			// probably not very common request but I do it!
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

// XXX will this help us create filter on Response functioality?
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
