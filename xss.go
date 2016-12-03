package xss

// XXX TODO
// bluemonday!
// also have option to accept XSS into the database and filter it out on display

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
	"html"
	//"html"
	//"io"
	"io/ioutil"
	//"net/url"
	//"os"
	"strconv"
)

// GinXSSMiddleware provides an 'auto' remove XSS malicious from all submitted user input.
// e.g. POST and PUT
// it's highly configurable.
// uses HTML sanitizer https://github.com/microcosm-cc/bluemonday

type GinXSSMiddleware struct {
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

// MiddlewareFunc makes GinXSSMiddleware implement the Middleware interface.
func (mw *GinXSSMiddleware) MiddlewareFunc() gin.HandlerFunc {
	//if err := mw.MiddlewareInit(); err != nil {
	//	return func(c *gin.Context) {
	//		mw.unauthorized(c, http.StatusInternalServerError, err.Error())
	//		return
	//	}
	//}

	return func(c *gin.Context) {
		mw.middlewareImpl(c)
		return
	}
}

func (mw *GinXSSMiddleware) middlewareImpl(c *gin.Context) {
	// remove xss
	err := mw.filterData(c)

	if err != nil {
		c.Abort()
		return
	}

	c.Next()
}

// Remove XSS
func (mw *GinXSSMiddleware) filterData(c *gin.Context) error {
	//dump, derr := httputil.DumpRequest(c.Request, true)
	//fmt.Print(derr)
	//fmt.Printf("%q", dump)

	//ReqHeader := c.Request.Header
	//fmt.Printf("%v Header\n", ReqHeader)

	//// https://golang.org/pkg/net/http/#Request

	ReqMethod := c.Request.Method
	//fmt.Printf("%v Method\n", ReqMethod)

	//ReqURL := c.Request.URL
	//fmt.Printf("%v URL\n", ReqURL)

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
		var jsonBod interface{}
		//jsnErr := json.NewDecoder(ReqBody).Decode(&jsonBod)
		d := json.NewDecoder(ReqBody)
		d.UseNumber()
		jsnErr := d.Decode(&jsonBod)
		if jsnErr == nil {
			var buff bytes.Buffer
			buff.WriteString(`{`)

			m := jsonBod.(map[string]interface{})
			for k, v := range m {
				fmt.Println(k, v)
				buff.WriteString(`"`)
				buff.WriteString(k)
				buff.WriteString(`":`)

				// FYI, json is string or float
				switch vv := v.(type) {
				case string:
					fmt.Println(k, "is string", vv)
					buff.WriteString(`"`)
					// TODO
					// XXX need to escape [ "`{},: ]
					//buff.WriteString(vv)
					// XXX to do  bluemonday!
					buff.WriteString(html.EscapeString(vv))
					buff.WriteString(`",`)
				case float64:
					fmt.Println(k, "is float", vv)
					//buff.WriteString(strconv.FormatFloat(vv, 'g', 0, 64))
					buff.WriteString(html.EscapeString(strconv.FormatFloat(vv, 'g', 0, 64)))
					buff.WriteString(`,`)
				default:
					// XXX talent_ids [1] is an array of values (handle it!)
					// talent_ids is of a type I don't know how to handle

					fmt.Println(k, "is of a type I don't know how to handle")
					fmt.Println("%#v", vv)
					//buff.WriteString(fmt.Sprintf("%v", vv))
					buff.WriteString(html.EscapeString(fmt.Sprintf("%v", vv)))
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
			//bf := `{"genre":"7","created_at":88812334,"updated_by":534,"updated_at":12344,"bpm":"117","key":"E","visibility": "Public","id":1,"name":"Project ß£áçkqùë Jâçqùë ¥  - value asdfasdfadfs","description": "Iñtërnâtiônàlizætiøn project  asdfasdf","status":"Recording","sub_genre":"77","created_by":534}`
			//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bf)))
			//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(buff.String())))
			//c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(string(encBuf))))
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(bodOut)))

			fmt.Printf("ReqBody Post: %v\n", c.Request.Body)
			fmt.Printf("ReqBody Post: %#v\n", c.Request.Body)
		} else {
			fmt.Println("Failed")
		}

	}
	//return errors.New("Filter error")
	return nil

}

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
