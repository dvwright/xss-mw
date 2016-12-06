package xss

// see https://raw.githubusercontent.com/gin-gonic/contrib/master/secure/secure_test.go

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	//"reflect"
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	//"io"
	//"os"
	"strconv"
	"testing"
)

//const (
//	testResponse = "bar"
//)

type User struct {
	Id       int     `json:"id" form:"id" binding:"required"`
	Flt      float64 `json:"flt" form:"flt"`
	User     string  `json:"user" form:"user"`
	Email    string  `json:"email" form:"email"`
	Password string  `json:"password" form:"password"`
	CreAt    int64   `json:"cre_at" form:"cre_at"`
	Comment  string  `json:"comment" form:"comment"`
}

// Test as Gin Middleware
//func newServer(options Options) *gin.Engine {
func newServer() *gin.Engine {
	r := gin.Default()

	//r.Use(Secure(options))
	//// the xss middleware
	//xssMdlwr := &xss.XssMw{
	////TableWhitelist: []byte,
	////FieldWhitelist []byte,
	////TableFieldWhitelist []byte,
	//}

	var xssMdlwr XssMw
	r.Use(xssMdlwr.RemoveXss())
	// TODO - filter on Response not Request
	//r.Use(xss.FilterXss())

	//r.PUT("/", func(c *gin.Context) {
	//	//c.Header("Content-Length", strconv.Itoa(len(testResponse)))
	//	//c.String(201, testResponse)
	//	//c.Request

	//})

	//r.POST("/", func(c *gin.Context) {
	//	message := c.PostForm("message")
	//	nick := c.DefaultPostForm("nick", "anonymous")

	//	c.JSON(200, gin.H{
	//		"status":  "posted",
	//		"message": message,
	//		"nick":    nick,
	//	})
	//})

	r.POST("/user", func(c *gin.Context) {
		fmt.Println(c.Request.Body)
		//fmt.Println(c.Header.Get("Content-Length"))
		var user User
		fmt.Printf("%v", user)
		err := c.BindJSON(&user)
		fmt.Printf("%v", user)
		if err != nil {
			fmt.Println(err)
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, user)
	})

	return r
}

func TestKeepsValuesStripsHtmlPost(t *testing.T) {
	//// we don't want to see log message while running tests!
	//log.SetOutput(ioutil.Discard)
	//defer log.SetOutput(os.Stderr)

	s := newServer()

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF"
	//xss := `>'>"><img src=x onerror=alert(0)>`
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := 1481017167
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + fmt.Sprintf("%d", cre_at) + `}`
	req, _ := http.NewRequest("POST", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	// XXX leave this out, fails
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	//fmt.Println(resp.Body.String())

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":"%d"
        }`
	//fmt.Println(resp.Body.String())

	// XXX we are using d.UseNumber on the JSON, why is it still float?!

	//xss_clnd := `>'>">`
	cmnt_clnd := ``

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

// TODO what is password is '<>Password<>'!

//func TestAcceptsJsonOnlyPOST(t *testing.T) {
//	s := newServer()
//	oParams := `{"email": "` + email + `", "html":"` + html + `", "user":"` + user + `"}`
//	req, _ := http.NewRequest("POST", "/", bytes.NewBufferString(oParams))
//	//req.Header.Add("Content-Type", "application/json")
//
//	resp := httptest.NewRecorder()
//	s.ServeHTTP(resp, req)
//	fmt.Println(resp.Body.String())
//	assert.Equal(t, 500, resp.Code)
//}
//
//func TestAcceptsJsonOnlyPUT(t *testing.T) {
//	s := newServer()
//	oParams := `{"email": "` + email + `", "html":"` + html + `", "user":"` + user + `"}`
//	req, _ := http.NewRequest("PUT", "/", bytes.NewBufferString(oParams))
//	//req.Header.Add("Content-Type", "application/json")
//
//	resp := httptest.NewRecorder()
//	s.ServeHTTP(resp, req)
//	fmt.Println(resp.Body.String())
//	assert.Equal(t, 500, resp.Code)
//}

//func TestKeepsValuesStripsHtmlPut(t *testing.T) {
//}

//func TestNoFilterAppliedGet(t *testing.T) {
//}

// Prove Headers left untouched
//      req.Header.Add("Authorization", "Bearer "+authToken)

//func TestBasic(t *testing.T) {
//	user := "TestUser"
//	email := "testUser@example.com"
//	html := "<p>My Markup Text</p>"
//	oParams := `{"email": "` + email + `", "html":"` + html + `", "user":"` + user + `"}`
//	req, _ := http.NewRequest("POST", "/", bytes.NewBufferString(oParams))
//	req.Header.Add("Content-Type", "application/json")
//
//	resp := httptest.NewRecorder()
//	ts.ServeHTTP(resp, req)
//	fmt.Println(resp.Body.String())
//
//	assert.Equal(t, 201, resp.Code)
//	expStr := `{
//            "id":1,
//            "username":"%v",
//            "email":"%v",
//            "password":"%v",
//            "status":"UNCONFIRMED",
//            "password_expire":%d,
//            "pass_reset_token":"%v",
//            "pass_reset_token_time":%d,
//            "created_at":%d,
//            "updated_at":%d
//        }`
//	apiRes := resp.Body.String()
//
//	expect := fmt.Sprintf(expStr, testUsername, testEmail, passEnc, in3Mnths, passTok, in3Hrs, tStamp, tStamp)
//	//fmt.Println(resp.Body.String())
//	assert.JSONEq(t, expect, resp.Body.String())
//
//}
//
//func TestNoConfig(t *testing.T) {
//	s := newServer(Options{
//	// Intentionally left blank.
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Body.String(), "bar")
//}
//
//func TestNoAllowHosts(t *testing.T) {
//	s := newServer(Options{
//		AllowedHosts: []string{},
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Body.String(), `bar`)
//}
//
//func TestGoodSingleAllowHosts(t *testing.T) {
//	s := newServer(Options{
//		AllowedHosts: []string{"www.example.com"},
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Body.String(), `bar`)
//}
//
//func TestBadSingleAllowHosts(t *testing.T) {
//	s := newServer(Options{
//		AllowedHosts: []string{"sub.example.com"},
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusInternalServerError)
//}
//
//func TestGoodMultipleAllowHosts(t *testing.T) {
//	s := newServer(Options{
//		AllowedHosts: []string{"www.example.com", "sub.example.com"},
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "sub.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Body.String(), `bar`)
//}
//
//func TestBadMultipleAllowHosts(t *testing.T) {
//	s := newServer(Options{
//		AllowedHosts: []string{"www.example.com", "sub.example.com"},
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www3.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusInternalServerError)
//}
//
//func TestAllowHostsInDevMode(t *testing.T) {
//	s := newServer(Options{
//		AllowedHosts:  []string{"www.example.com", "sub.example.com"},
//		IsDevelopment: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www3.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//}
//
//func TestBadHostHandler(t *testing.T) {
//
//	badHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		http.Error(w, "BadHost", http.StatusInternalServerError)
//	})
//
//	s := newServer(Options{
//		AllowedHosts:   []string{"www.example.com", "sub.example.com"},
//		BadHostHandler: badHandler,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www3.example.com"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusInternalServerError)
//
//	// http.Error outputs a new line character with the response.
//	expect(t, res.Body.String(), "BadHost\n")
//}
//
//func TestSSL(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "https"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//}
//
//func TestSSLInDevMode(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect:   true,
//		IsDevelopment: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//}
//
//func TestBasicSSL(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusMovedPermanently)
//	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
//}
//
//func TestBasicSSLWithHost(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect: true,
//		SSLHost:     "secure.example.com",
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusMovedPermanently)
//	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
//}
//
//func TestBadProxySSL(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//	req.Header.Add("X-Forwarded-Proto", "https")
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusMovedPermanently)
//	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
//}
//
//func TestCustomProxySSL(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect:     true,
//		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//	req.Header.Add("X-Forwarded-Proto", "https")
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//}
//
//func TestCustomProxySSLInDevMode(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect:     true,
//		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
//		IsDevelopment:   true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//	req.Header.Add("X-Forwarded-Proto", "http")
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//}
//
//func TestCustomProxyAndHostSSL(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect:     true,
//		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
//		SSLHost:         "secure.example.com",
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//	req.Header.Add("X-Forwarded-Proto", "https")
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//}
//
//func TestCustomBadProxyAndHostSSL(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect:     true,
//		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "superman"},
//		SSLHost:         "secure.example.com",
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//	req.Header.Add("X-Forwarded-Proto", "https")
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusMovedPermanently)
//	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
//}
//
//func TestCustomBadProxyAndHostSSLWithTempRedirect(t *testing.T) {
//	s := newServer(Options{
//		SSLRedirect:          true,
//		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "superman"},
//		SSLHost:              "secure.example.com",
//		SSLTemporaryRedirect: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//	req.Host = "www.example.com"
//	req.URL.Scheme = "http"
//	req.Header.Add("X-Forwarded-Proto", "https")
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusTemporaryRedirect)
//	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
//}
//
//func TestStsHeader(t *testing.T) {
//	s := newServer(Options{
//		STSSeconds: 315360000,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000")
//}
//
//func TestStsHeaderInDevMode(t *testing.T) {
//	s := newServer(Options{
//		STSSeconds:    315360000,
//		IsDevelopment: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("Strict-Transport-Security"), "")
//}
//
//func TestStsHeaderWithSubdomain(t *testing.T) {
//	s := newServer(Options{
//		STSSeconds:           315360000,
//		STSIncludeSubdomains: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000; includeSubdomains")
//}
//
//func TestFrameDeny(t *testing.T) {
//	s := newServer(Options{
//		FrameDeny: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("X-Frame-Options"), "DENY")
//}
//
//func TestCustomFrameValue(t *testing.T) {
//	s := newServer(Options{
//		CustomFrameOptionsValue: "SAMEORIGIN",
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
//}
//
//func TestCustomFrameValueWithDeny(t *testing.T) {
//	s := newServer(Options{
//		FrameDeny:               true,
//		CustomFrameOptionsValue: "SAMEORIGIN",
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
//}
//
//func TestContentNosniff(t *testing.T) {
//	s := newServer(Options{
//		ContentTypeNosniff: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("X-Content-Type-Options"), "nosniff")
//}
//
//func TestXSSProtection(t *testing.T) {
//	s := newServer(Options{
//		BrowserXssFilter: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("X-XSS-Protection"), "1; mode=block")
//}
//
//func TestCsp(t *testing.T) {
//	s := newServer(Options{
//		ContentSecurityPolicy: "default-src 'self'",
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("Content-Security-Policy"), "default-src 'self'")
//}
//
//func TestInlineSecure(t *testing.T) {
//	s := newServer(Options{
//		FrameDeny: true,
//	})
//
//	res := httptest.NewRecorder()
//	req, _ := http.NewRequest("GET", "/foo", nil)
//
//	s.ServeHTTP(res, req)
//
//	expect(t, res.Code, http.StatusOK)
//	expect(t, res.Header().Get("X-Frame-Options"), "DENY")
//}
//
///* Test Helpers */
//func expect(t *testing.T, a interface{}, b interface{}) {
//	if a != b {
//		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
//	}
//}
//
//// also
//
////package gzip
////
////import (
////  "compress/gzip"
////  "io/ioutil"
////  "net/http"
////  "net/http/httptest"
////  "strconv"
////  "testing"
////
////  "github.com/gin-gonic/gin"
////  "github.com/stretchr/testify/assert"
////)
////
////const (
////  testResponse = "Gzip Test Response "
////)
//
//func newServer() *gin.Engine {
//	router := gin.Default()
//	router.Use(Gzip(DefaultCompression))
//	router.GET("/", func(c *gin.Context) {
//		c.Header("Content-Length", strconv.Itoa(len(testResponse)))
//		c.String(200, testResponse)
//	})
//	return router
//}
//
//func TestGzip(t *testing.T) {
//	req, _ := http.NewRequest("GET", "/", nil)
//	req.Header.Add("Accept-Encoding", "gzip")
//
//	w := httptest.NewRecorder()
//	r := newServer()
//	r.ServeHTTP(w, req)
//
//	assert.Equal(t, w.Code, 200)
//	assert.Equal(t, w.Header().Get("Content-Encoding"), "gzip")
//	assert.Equal(t, w.Header().Get("Vary"), "Accept-Encoding")
//	assert.Equal(t, w.Header().Get("Content-Length"), "0")
//	assert.NotEqual(t, w.Body.Len(), 19)
//
//	gr, err := gzip.NewReader(w.Body)
//	assert.NoError(t, err)
//	defer gr.Close()
//
//	body, _ := ioutil.ReadAll(gr)
//	assert.Equal(t, string(body), testResponse)
//}
//
//func TestGzipPNG(t *testing.T) {
//	req, _ := http.NewRequest("GET", "/image.png", nil)
//	req.Header.Add("Accept-Encoding", "gzip")
//
//	router := gin.New()
//	router.Use(Gzip(DefaultCompression))
//	router.GET("/image.png", func(c *gin.Context) {
//		c.String(200, "this is a PNG!")
//	})
//
//	w := httptest.NewRecorder()
//	router.ServeHTTP(w, req)
//
//	assert.Equal(t, w.Code, 200)
//	assert.Equal(t, w.Header().Get("Content-Encoding"), "")
//	assert.Equal(t, w.Header().Get("Vary"), "")
//	assert.Equal(t, w.Body.String(), "this is a PNG!")
//}
//
//func TestNoGzip(t *testing.T) {
//	req, _ := http.NewRequest("GET", "/", nil)
//
//	w := httptest.NewRecorder()
//	r := newServer()
//	r.ServeHTTP(w, req)
//
//	assert.Equal(t, w.Code, 200)
//	assert.Equal(t, w.Header().Get("Content-Encoding"), "")
//	assert.Equal(t, w.Header().Get("Content-Length"), "19")
//	assert.Equal(t, w.Body.String(), testResponse)
//}
