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
	//fmt.Printf("%v URL\n", ReqURL)

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

		// URL's TO SKIP
		// will have to be a regex or index of in reality  -
		// XXX we wont know id value (at end)
		if ReqURL.String() == "/api/v1/project_talent_wanted/1" {
			fmt.Printf("Skipping URL: %v\n", ReqURL)
			return nil
		}
		if ReqURL.String() == "/api/v1/project_media/1" {
			fmt.Printf("Skipping URL: %v\n", ReqURL)
			return nil
		}

		var jsonBod interface{}
		//jsnErr := json.NewDecoder(ReqBody).Decode(&jsonBod)
		d := json.NewDecoder(ReqBody)
		d.UseNumber()
		jsnErr := d.Decode(&jsonBod)
		if jsnErr == nil {
			var buff bytes.Buffer
			buff.WriteString(`{`)

			//p := bluemonday.UGCPolicy()
			p := bluemonday.StrictPolicy()

			m := jsonBod.(map[string]interface{})
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

			bodOut := buff.String()

			enc := json.NewEncoder(ioutil.Discard)
			if merr := enc.Encode(&bodOut); merr != nil {
				fmt.Printf("%v", merr)
			}

			fmt.Printf("ReqBody PRE: %v\n", ReqBody)
			//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(buff.String())))
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bodOut)))

			fmt.Printf("ReqBody Post: %v\n", c.Request.Body)
			fmt.Printf("ReqBody Post: %#v\n", c.Request.Body)
		} else {
			fmt.Println("Failed")
		}

	}
	//return errors.New("XSS remaval error")
	return nil
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
