package xss

// XssMw provides an auto remove malicious XSS from all submitted user input.
// The method is applied on all POST and PUT Requests only.

// it's highly configurable and uses HTML sanitizer https://github.com/microcosm-cc/bluemonday
// for filtering.
// TODO - how to expose bluemonday?

// TODO
// add option to accept XSS on http Request and apply filter on Response
// - in other words - data would be stored in the database as it was submitted
// - data integrity, XSS exploits and all

import (
	//"errors"
	"github.com/gin-gonic/gin"
	//"net/http/httputil" // debugging
	//"reflect" // debugging type
	//"net/http"
	//"strings"
	"bytes"
	//"time"
	"encoding/json"
	"fmt"
	//"html"
	//"io"
	"io/ioutil"
	//"net/url"
	//"os"
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
	//if err := mw.MiddlewareInit(); err != nil {
	//	return func(c *gin.Context) {
	//		mw.unauthorized(c, http.StatusInternalServerError, err.Error())
	//		return
	//	}
	//}

	return func(c *gin.Context) {
		mw.callRemoveXss(c)
		return
	}
}

func (mw *XssMw) callRemoveXss(c *gin.Context) {
	// remove xss
	err := mw.XssRemove(c)

	if err != nil {
		c.Abort()
		return
	}

	c.Next()
}

// Remove XSS
func (mw *XssMw) XssRemove(c *gin.Context) error {
	//dump, derr := httputil.DumpRequest(c.Request, true)
	//fmt.Print(derr)
	//fmt.Printf("%q", dump)

	//ReqHeader := c.Request.Header
	//fmt.Printf("%v Header\n", ReqHeader)

	//// https://golang.org/pkg/net/http/#Request

	ReqMethod := c.Request.Method
	//fmt.Printf("%v Method\n", ReqMethod)

	ReqURL := c.Request.URL
	fmt.Printf("%v URL\n", ReqURL)

	//// XXX doesn't work - all edit have some referrer
	//// XXX be able to skip some end points (referrer - url)
	//// URL's to skip processing on
	ct_rfr := c.Request.Header.Get("Referer")
	fmt.Printf("%v\n", ct_rfr)
	//if string(ct_rfr) == "http://local.hubtones.com/project/1/edit" {
	//	return nil
	//}

	ReqBody := c.Request.Body
	//fmt.Printf("%v URL\n", ReqBody)

	ct_hdr := c.Request.Header.Get("Content-Type") // [application/json]
	//fmt.Printf("%v\n", ct_hdr)                     // -> application/json

	cts_len := c.Request.Header.Get("Content-Length")
	//fmt.Printf("%v\n", cts_len)
	ct_len, _ := strconv.Atoi(cts_len)

	// https://golang.org/src/net/http/request.go
	// set expected application type
	if ct_hdr == "application/json" && ct_len > 1 && (ReqMethod == "POST" || ReqMethod == "PUT") {

		//// URL's TO SKIP
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
		//jsnErr := json.NewDecoder(ReqBody).Decode(&jsonBod)
		d := json.NewDecoder(ReqBody)
		d.UseNumber()
		jsnErr := d.Decode(&jsonBod)
		//fmt.Printf("JSON BOD: %v\n", jsonBod)
		fmt.Printf("JSON BOD: %#v\n", jsonBod)
		//map[string]interface {}{ - first form

		// 2nd - talents
		// JSON BOD: map[string]interface {}{"project_id":"1", "talent_ids":[]interface {}{"1", "4", "8"}}

		// 3rd - media table
		// []interface {}{map[string]interface {}{"name":"asd.mp3", "url":"/data/project/1/as.mp3",
		// "user_id":"537", "username":"Test User ©", "created_by":"537", "id":"286",
		//"fqdn_url":"<audio class", "project_id":"1", "path":"/Library/WebServer/Documents/data/project/1/.mp3",
		// "mtype":"application/octet-stream", "updated_at":"1480791630", "ptype":"IDEA", "status":"NEW",
		// "updated_by":"537", "created_at":"1480450694"},  map[string]interface {}{ and more
		// XXX so essentailly []interface is like an array we need to iterate over an apply the existing code to

		if jsnErr == nil {

			switch jbt := jsonBod.(type) {
			case []interface{}:
				// XXX how to build up type // []interface {} ?
				// append ?
				vals := []interface{}{}
				for i, n := range jbt {
					fmt.Printf("Item: %v= %v\n", i, n)
					xmj := n.(map[string]interface{})
					buff := BuildJsonBody(xmj)
					vals = append(vals, n, buff)
				}
				// cannot use vals (type []interface {}) as type bytes.Buffer in argument to SetRequestBody
				//err := SetRequestBody(c, vals)
				// XXX how to iterate and collect and pass as buff?
				err := SetRequestBody(c, vals)
				if err != nil {
					fmt.Printf("\n\n\nSet request body failed!\n\n\n")
				}
			case map[string]interface{}:
				fmt.Printf("\n\n\nMOOOOOO\n\n\n")
				xmj := jsonBod.(map[string]interface{})
				buff := BuildJsonBody(xmj)
				err := SetRequestBody(c, buff)
				if err != nil {
					fmt.Printf("\n\n\nSet request body failed!\n\n\n")
				}
			default:
				//var r = reflect.TypeOf(jbt)
				fmt.Printf("Unknown Type!:%v\n", r)
			}

		} else {
			fmt.Println("Failed")
		}

	}
	//return errors.New("XSS remaval error")
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

// TODO change method signature - func (xmj XssMwJson) BuildJsonBody(bytes.Buffer) {
// build response - method call
// takes arg map[string]interface{} and a bluemonday Policy
// returns bytes.Buffer
func BuildJsonBody(xmj XssMwJson) bytes.Buffer {

	var buff bytes.Buffer
	buff.WriteString(`{`)

	//p := bluemonday.UGCPolicy()
	p := bluemonday.StrictPolicy()

	//m := jsonBod.(map[string]interface{})
	m := xmj
	for k, v := range m {
		// to implement fields to skip
		if string(k) == "fqdn_url" {
			continue
		}
		//fmt.Println(k, v)
		//fmt.Println(k, v)
		buff.WriteString(`"`)
		buff.WriteString(k)
		buff.WriteString(`":`)

		// FYI, json is string or float
		switch vv := v.(type) {
		case string:
			//fmt.Println(k, "is string", vv)
			buff.WriteString(`"`)
			// TODO  need to escape [ "`{},: ]
			//buff.WriteString(vv)
			//buff.WriteString(html.EscapeString(vv))
			buff.WriteString(p.Sanitize(vv))
			buff.WriteString(`",`)
		case float64:
			//fmt.Println(k, "is float", vv)
			//buff.WriteString(strconv.FormatFloat(vv, 'g', 0, 64))
			//buff.WriteString(html.EscapeString(strconv.FormatFloat(vv, 'g', 0, 64)))
			buff.WriteString(p.Sanitize(strconv.FormatFloat(vv, 'g', 0, 64)))
			buff.WriteString(`,`)
		default:
			// XXX need to support json array sent i.e. [1 4 8]
			// XXX talent_ids [1] is an array of values (handle it!)
			// talent_ids is of a type I don't know how to handle

			fmt.Println(k, "is of a type I don't know how to handle")
			fmt.Println("%#v", vv)
			fmt.Sprintf("%v", vv)
			//buff.WriteString(fmt.Sprintf("%v", vv))
			//buff.WriteString(html.EscapeString(fmt.Sprintf("%v", vv)))
			buff.WriteString(p.Sanitize(fmt.Sprintf("%v", vv)))
			buff.WriteString(`,`)
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
