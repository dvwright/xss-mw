// Copyright 2016 David Wright. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package xss

// see https://raw.githubusercontent.com/gin-gonic/contrib/master/secure/secure_test.go

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"

	//"reflect"
	"bytes"
	//"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type User struct {
	Id       int     `json:"id" form:"id" binding:"required"`
	Flt      float64 `json:"flt" form:"flt"`
	User     string  `json:"user" form:"user"`
	Email    string  `json:"email" form:"email"`
	Password string  `json:"password" form:"password"`
	CreAt    int64   `json:"cre_at" form:"cre_at"`
	Comment  string  `json:"comment" form:"comment"`
}

type Users struct {
	Id    int    `json:"id" form:"id" binding:"required"`
	Users []User `json:"users"`
}

type UserExtended struct {
	Id       int      `json:"id" form:"id" binding:"required"`
	Flt      float64  `json:"flt" form:"flt"`
	User     string   `json:"user" form:"user"`
	Email    string   `json:"email" form:"email"`
	Password string   `json:"password" form:"password"`
	CreAt    int64    `json:"cre_at" form:"cre_at"`
	Comment  string   `json:"comment" form:"comment"`
	Users    []User   `json:"users"`
	Ids      []string `json:"ids"`
}

type FileUpload struct {
	PType     string                `json:"ptype"`
	ProjectID string                `json:"project_id"`
	Media     *multipart.FileHeader `json:"media"`
}

// Test as Gin Middleware
func newServer(xssMdlwr XssMw) *gin.Engine {

	r := gin.Default()

	r.Use(xssMdlwr.RemoveXss())
	// TODO - filter on Response not Request
	//r.Use(xss.FilterXss())

	r.GET("/user/:id", func(c *gin.Context) {
		c.String(200, fmt.Sprintf("%v", c.Request.Body))
	})

	r.GET("/user", func(c *gin.Context) {
		var id = c.DefaultQuery("id", "")
		var userName = c.DefaultQuery("name", "")
		var email = c.DefaultQuery("email", "")
		c.JSON(201, gin.H{
			"id":    id,
			"name":  userName,
			"email": email,
		})
	})

	r.PUT("/user", func(c *gin.Context) {
		//fmt.Println(c.Request.Body)
		var user User
		//fmt.Printf("%#v", user)
		err := c.Bind(&user)
		//fmt.Printf("%#v", user)
		if err != nil {
			//fmt.Println(err)
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(200, user)
	})

	r.POST("/user", func(c *gin.Context) {
		//fmt.Println(c.Request.Body)
		//fmt.Println(c.Header.Get("Content-Length"))
		var user User
		//fmt.Printf("%#v", user)
		err := c.Bind(&user)
		//fmt.Printf("%#v", user)
		if err != nil {
			//fmt.Println(err)
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, user)
	})

	r.POST("/user_post", func(c *gin.Context) {
		id, _ := strconv.Atoi(c.PostForm("id"))
		user := c.PostForm("user")
		flt, _ := strconv.ParseFloat(c.PostForm("flt"), 64)
		email := c.PostForm("email")
		password := c.PostForm("password")
		comment := c.PostForm("comment")
		cre_at, _ := strconv.ParseInt(c.PostForm("cre_at"), 10, 64)

		usr := User{
			Id:       id,
			User:     user,
			Flt:      flt,
			Email:    email,
			Password: password,
			Comment:  comment,
			CreAt:    cre_at,
		}
		c.JSON(200, usr)
	})

	r.POST("/user_extended", func(c *gin.Context) {
		var userExtnd UserExtended
		err := c.Bind(&userExtnd)
		if err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, userExtnd)
	})

	// nested JSON
	r.POST("/user_post_nested_json", func(c *gin.Context) {
		var users Users
		err := c.Bind(&users)
		if err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, users)
	})

	r.POST("/file_upload", func(c *gin.Context) {
		var fileUpld FileUpload
		err := c.Bind(&fileUpld)
		if err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, fileUpld)
	})

	r.POST("/json_array_payload", func(c *gin.Context) {
		var jsnArrPld []string
		err := c.BindJSON(&jsnArrPld)
		if err != nil {
			c.JSON(400, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, jsnArrPld)
	})

	r.GET("/console/assets", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Assets endpoint"})
	})

	return r
}

func TestKeepsValuesStripsHtmlOnGet(t *testing.T) {
	// don't want to see log message while running tests
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	id := "2"
	name := "<img src=x onerror=alert(0)>"
	email := "testUser@example.com<html>"

	var queryParams = url.Values{}
	queryParams.Set("id", id)
	queryParams.Set("name", name)
	queryParams.Set("email", email)

	req, _ := http.NewRequest("GET", "/user?"+queryParams.Encode(), nil)
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":"%v",
			"name":"%v",
			"email": "%v"
		}`

	expect := fmt.Sprintf(expStr, id, "", "testUser@example.com")
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestKeepsValuesStripsHtmlWithSkipOnGet(t *testing.T) {
	// don't want to see log message while running tests
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	xssMdlwr.FieldsToSkip = []string{"id"}
	s := newServer(xssMdlwr)

	id := "2<img src=x onerror=alert(0)>"
	name := "<img src=x onerror=alert(0)>"
	email := "testUser@example.com<html>"

	var queryParams = url.Values{}
	queryParams.Set("id", id)
	queryParams.Set("name", name)
	queryParams.Set("email", email)

	req, _ := http.NewRequest("GET", "/user?"+queryParams.Encode(), nil)
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":"%v",
			"name":"%v",
			"email": "%v"
		}`

	expect := fmt.Sprintf(expStr, id, "", "testUser@example.com")
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestKeepsValuesStripsHtmlOnPost(t *testing.T) {
	// don't want to see log message while running tests
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	req, _ := http.NewRequest("POST", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`

	cmnt_clnd := `` // malicious markup content stripped

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestSupportsList(t *testing.T) {
	// don't want to see log message while running tests
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	userA := `{"id":1,  "flt":1.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	oParams := `{"id":1,  "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `, "users": [ ` + userA + `], "ids": ["4.4563", "Bill", "8", "14", "900001"] }`
	req, _ := http.NewRequest("POST", "/user_extended", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":1,
			"flt":2.345,
			"user":"%v",
			"email":"%v",
			"password":"%v",
			"comment":"%v",
			"cre_at":%v,
			"users":[
			  {"id":1, "flt":1.345, "user":"%v", "email":"%v", "password":"%v", "comment":"%v", "cre_at":%v}
			 ],
			"ids": ["4.4563","Bill","8","14","900001"]
        }`

	cmnt_clnd := `` // malicious markup content stripped
	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at, user, email, password, cmnt_clnd, cre_at)
	//fmt.Println(expect)

	//fmt.Println(resp.Body.String())
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestSupportNestedJSONPost(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	user1 := "TestUser1"
	email1 := "testUser1@example.com"
	password1 := "!@$%^ASDF<html>1"
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	userA := `{"id":1,  "flt":1.345, "user":"` + user1 + `", "email": "` + email1 + `", "password":"` + password1 + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`

	user2 := "TestUser2"
	email2 := "testUser2@example.com"
	password2 := "!@$%^ASDF<html>2"
	userB := `{"id":2,  "flt":2.345, "user":"` + user2 + `", "email": "` + email2 + `", "password":"` + password2 + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`

	oParams := `{"id":1, "users": [ ` + userA + `,` + userB + `]}`
	// YES Can Parse This
	//oParams = `{
	//"id": "0001",
	//"type": "donut",
	//"name": "Cake",
	//"ppu": 0.55,
	//"batters":
	//	{
	//		"batter":
	//			[
	//				{ "id": "1001", "type": "Regular" },
	//				{ "id": "1002", "type": "Chocolate" },
	//				{ "id": "1003", "type": "Blueberry" },
	//				{ "id": "1004", "type": "Devil's Food" }
	//			]
	//	},
	//"topping":
	//	[
	//		{ "id": "5001", "type": "None" },
	//		{ "id": "5002", "type": "Glazed" },
	//		{ "id": "5005", "type": "Sugar" },
	//		{ "id": "5007", "type": "Powdered Sugar" },
	//		{ "id": "5006", "type": "Chocolate with Sprinkles" },
	//		{ "id": "5003", "type": "Chocolate" },
	//		{ "id": "5004", "type": "Maple" }
	//	]
	//}`
	// YES - Parses correctly
	//oParams = `[
	//{
	//	"id": "0001",
	//	"type": "donut",
	//	"name": "Cake",
	//	"ppu": 0.55,
	//	"batters":
	//		{
	//			"batter":
	//				[
	//					{ "id": "1001", "type": "Regular" },
	//					{ "id": "1002", "type": "Chocolate" },
	//					{ "id": "1003", "type": "Blueberry" },
	//					{ "id": "1004", "type": "Devil's Food" }
	//				]
	//		},
	//	"topping":
	//		[
	//			{ "id": "5001", "type": "None" },
	//			{ "id": "5002", "type": "Glazed" },
	//			{ "id": "5005", "type": "Sugar" },
	//			{ "id": "5007", "type": "Powdered Sugar" },
	//			{ "id": "5006", "type": "Chocolate with Sprinkles" },
	//			{ "id": "5003", "type": "Chocolate" },
	//			{ "id": "5004", "type": "Maple" }
	//		]
	//},
	//{
	//	"id": "0002",
	//	"type": "donut",
	//	"name": "Raised",
	//	"ppu": 0.55,
	//	"batters":
	//		{
	//			"batter":
	//				[
	//					{ "id": "1001", "type": "Regular" }
	//				]
	//		},
	//	"topping":
	//		[
	//			{ "id": "5001", "type": "None" },
	//			{ "id": "5002", "type": "Glazed" },
	//			{ "id": "5005", "type": "Sugar" },
	//			{ "id": "5003", "type": "Chocolate" },
	//			{ "id": "5004", "type": "Maple" }
	//		]
	//},
	//{
	//	"id": "0003",
	//	"type": "donut",
	//	"name": "Old Fashioned",
	//	"ppu": 0.55,
	//	"batters":
	//		{
	//			"batter":
	//				[
	//					{ "id": "1001", "type": "Regular" },
	//					{ "id": "1002", "type": "Chocolate" }
	//				]
	//		},
	//	"topping":
	//		[
	//			{ "id": "5001", "type": "None" },
	//			{ "id": "5002", "type": "Glazed" },
	//			{ "id": "5003", "type": "Chocolate" },
	//			{ "id": "5004", "type": "Maple" }
	//		]
	//}
	//]`
	//oParams = `{"comment": "test", "id": 0, "media_id": 381, "parent_id": 0, "status": null, "updated_at": 1540673110}`

	req, _ := http.NewRequest("POST", "/user_post_nested_json", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":1,
			"users":[
			  {"id":1, "flt":1.345, "user":"%v", "email":"%v", "password":"%v", "comment":"%v", "cre_at":%v},
              {"id":2, "flt":2.345, "user":"%v", "email":"%v", "password":"%v", "comment":"%v", "cre_at":%v}
			]
        }`

	cmnt_clnd := `` // malicious markup content stripped
	expect := fmt.Sprintf(expStr, user1, email1, password1, cmnt_clnd, cre_at, user2, email2, password2, cmnt_clnd, cre_at)
	//fmt.Println(expect)

	//fmt.Println(resp.Body.String())
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestKeepsValuesStripsHtmlOnPut(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `>'>\"><img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	req, _ := http.NewRequest("PUT", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`
	cmnt_clnd := `&gt;&#39;&gt;&#34;&gt;` //i.e. >'>">

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestXssSkippedOnNoContentLength(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	req, _ := http.NewRequest("POST", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`

	expect := fmt.Sprintf(expStr, user, email, password, cmnt, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestXssSkippedOnGetRequest(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	cmnt := `<img src=x onerror=alert(0)>`
	oParams := `{"id":2, "comment":"` + cmnt + `"}`

	req, _ := http.NewRequest("GET", "/user/2", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)
	assert.Equal(t, `{{"id":2, "comment":"`+cmnt+`"}}`, resp.Body.String())
}

// TODO - conf feature pass in fields to skip
func TestPasswordIsNotFiltered(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "<>!@$%^ASDF<>" // the 'password' keyword is set to not filter out xss
	cmnt := `<script>alert(0)</script>`
	cre_at := "1481017167"
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	req, _ := http.NewRequest("POST", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`

	cmnt_clnd := `` // malicious markup content stripped

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

// multipart form posts really need to be filtered!
// TODO careful with content body such as files, images, audio files, etc!
// Content-Disposition: form-data; name="comment"
// >'>\"><img src=x onerror=alert(0)>
func TestXssFiltersMultiPartFormData(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	//xssMdlwr = XssMw{
	//	FieldsToSkip: []string{"password"},
	//	BmPolicy:     "UGCPolicy",
	//}
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `>'>\"><img src=x onerror=alert(0)>`
	cre_at := "1481017167"

	Oparams := map[string]string{
		"id":       "2",
		"user":     user,
		"flt":      "2.345",
		"email":    email,
		"password": password,
		"comment":  cmnt,
		"cre_at":   cre_at,
	}

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	for key, val := range Oparams {
		_ = writer.WriteField(key, val)
	}
	err := writer.Close()
	assert.Nil(t, err)

	boundary := writer.Boundary()
	close_buf := bytes.NewBufferString(fmt.Sprintf("\r\n--%s--\r\n", boundary))

	req, perr := http.NewRequest("POST", "/user", body)
	assert.Nil(t, perr)
	// Set headers for multipart, and Content Length
	req.Header.Add("Content-Type", "multipart/form-data; boundary="+boundary)
	req.ContentLength = int64(body.Len()) + int64(close_buf.Len())

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
            "cre_at":%v
        }`

	//cmnt_clnd := `>'>\\\"><img src=x onerror=alert(0)>` // left intact
	//cmnt_clnd := `&gt;&#39;&gt;&#34;&gt;` //i.e. >'>">
	// XXX look at why the escape...
	cmnt_clnd := `&gt;&#39;&gt;\\&#34;&gt;`

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

// TODO
// POST /post?id=1234&page=1 HTTP/1.1
// Content-Type: application/x-www-form-urlencoded
// name=manu&message=this_is_great
// application/x-www-form-urlencoded
func TestXssFiltersXFormEncoded(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	//fmt.Println("TODO TestXssFiltersXFormEncoded")
	//t.Skip()

	var xssMdlwr XssMw
	//xssMdlwr = XssMw{
	//	FieldsToSkip: []string{"password"},
	//	BmPolicy:     "UGCPolicy",
	//}
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `>'>\"><img src=x onerror=alert(0)>`
	cre_at := "1481017167"

	values := url.Values{}
	values.Set("id", "2")
	values.Add("user", user)
	values.Add("flt", "2.345")
	values.Add("email", email)
	values.Add("password", password)
	values.Add("comment", cmnt)
	values.Add("cre_at", cre_at)

	req, err := http.NewRequest(
		"POST",
		"/user_post",
		strings.NewReader(values.Encode()),
	)
	assert.Nil(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	//fmt.Println(resp.Body.String())
	assert.Equal(t, 200, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`

	//cmnt_clnd := `>'>\\\"><img src=x onerror=alert(0)>` // left intact
	cmnt_clnd := `&gt;&#39;&gt;\\&#34;&gt;`

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

// TODO - prove Headers and Other Request fields left intact
// Prove Headers left untouched
// for example
//
//	req.Header.Add("Authorization", "Bearer "+authToken)
func TestKeepsHeadersIntact(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	fmt.Println("TODO TestKeepsHeadersIntact")
	t.Skip()

	//// we don't want to see log message while running tests
	//log.SetOutput(io.Discard)
	//defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	//xssMdlwr = XssMw{
	//	FieldsToSkip: []string{"password"},
	//	BmPolicy:     "UGCPolicy",
	//}
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	req, _ := http.NewRequest("POST", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))
	//req.Header.Add("Authorization", "Bearer "+authToken)

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`

	cmnt_clnd := `` // malicious markup content stripped

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestUGCPolityAllowSomeHTMLOnPost(t *testing.T) {
	// don't want to see log message while running tests
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr = XssMw{
		//TableWhitelist: []byte,
		//FieldWhitelist []byte,
		//TableFieldWhitelist []byte,
		//FieldsToSkip: []string{"password"},
		BmPolicy: "UGCPolicy",
	}
	s := newServer(xssMdlwr)

	user := "TestUser"
	email := "testUser@example.com"
	password := "!@$%^ASDF<html>"
	cmnt := `<img src=x onerror=alert(0)>`
	cre_at := "1481017167"
	oParams := `{"id":2, "flt":2.345, "user":"` + user + `", "email": "` + email + `", "password":"` + password + `", "comment":"` + cmnt + `", "cre_at":` + cre_at + `}`
	req, _ := http.NewRequest("POST", "/user", bytes.NewBufferString(oParams))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(oParams)))

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)
	expStr := `{
            "id":2,
            "flt":2.345,
            "user":"%v",
            "email":"%v",
            "password":"%v",
            "comment":"%v",
            "cre_at":%v
        }`

	cmnt_clnd := `<img src=\"x\">` // malicious markup content stripped, valid html left

	expect := fmt.Sprintf(expStr, user, email, password, cmnt_clnd, cre_at)
	assert.JSONEq(t, expect, resp.Body.String())
}

func TestMissingQuery(t *testing.T) {
	ctx := &gin.Context{
		Request: &http.Request{},
	}
	ctx.Request.URL, _ = url.Parse("http://localhost/foo?k1[]=1&k1[]=2")
	expected := ctx.Request.URL.Query()["k1[]"]
	var xss XssMw
	xss.HandleGETRequest(ctx)

	got := ctx.QueryArray("k1[]")
	assert.Equal(t, len(expected), len(got), "Check query after handle")
}

// TODO
// prove the 3 types of filtering

func TestPostRequestWithFormData(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	boundary := "----WebKitFormBoundaryNPigYRiWD8pd0yeW"

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("ptype", "PDF")
	_ = writer.WriteField("id", "1")

	file, err := os.Open("test.pdf")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile("media", "test.pdf")
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatal(err)
	}

	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/file_upload", body)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Add("Content-Type", "multipart/form-data; boundary="+boundary)

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	if resp.Code != 201 {
		t.Errorf("Expected status code 201, but got %d", resp.Code)
	}
}

func TestPostRequestWithJsonPayload(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var xssMdlwr XssMw
	s := newServer(xssMdlwr)

	payload := `["11","22"]`
	req, err := http.NewRequest("POST", "/json_array_payload", bytes.NewBufferString(payload))
	assert.Nil(t, err)

	req.Header.Add("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 201, resp.Code)

	var responseBody []string
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.Nil(t, err)

	assert.Equal(t, []string{"11", "22"}, responseBody)
}

func TestConsoleAssets(t *testing.T) {
    log.SetOutput(io.Discard)
    defer log.SetOutput(os.Stderr)

    var xssMdlwr XssMw
    s := newServer(xssMdlwr)

    req, err := http.NewRequest("GET", "/console/assets?sort=0&rule_tags=%E5%83%B5%E5%B0%B8%E7%BD%91%E7%BB%9C&rule_tags=%E6%97%A0%E6%95%88FID", nil)
    assert.Nil(t, err)

    resp := httptest.NewRecorder()
    s.ServeHTTP(resp, req)

    assert.Equal(t, 200, resp.Code)

    if resp.Code != 200 {
        return
    }

    var responseBody map[string]any
    err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
    if err != nil {
        t.Logf("Error unmarshaling response body: %v", err)
        return
    }

    // Verify the response body as needed
}