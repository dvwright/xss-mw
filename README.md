# README #

TODO - FIX JSON SUBMIT ARRAY BUGS:


[GIN-debug] Listening and serving HTTP on :11062
talent_ids is of a type I don't know how to handle
%#v [1 4 8]
ReqBody PRE: &{0xc4202a5ae0 <nil> <nil> false true {0 0} true false false <nil>}
ReqBody Post: {{"project_id":"1","talent_ids":[1 4 8]}}
ReqBody Post: ioutil.nopCloser{Reader:(*bytes.Buffer)(0xc4202a08c0)}
[GIN] 2016/12/03 - 10:17:24 | 400 |     2.23932ms | 127.0.0.1 |   PUT     /api/v1/project_talent_wanted/1

DOES NOT WORK:
2016/12/03 10:17:24 project_talent_wanted.go:87: <nil>
2016/12/03 10:17:24 project_talent_wanted.go:88: "PUT /api/v1/project_talent_wanted/1 HTTP/1.1\r\nHost: local.hubtones.com:11062\r\nAccept: application/json\r\nAccept-Encoding: gzip, deflate, sdch\r\nAccept-Language: en-US,en;q=0.8\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODA5Njg0NjIsImlkIjoiVGVzdCBVc2VyIMKpIiwib3JpZ19pYXQiOjE0ODA0MDc2MzEsInVzZXJfaWQiOjUzNywidXNlcm5hbWUiOiJUZXN0IFVzZXIgwqkifQ.KYuZ77m5o8OGO9Cq6seCEgKdmbQ0bh5fj4ZGlRw26BI\r\nConnection: keep-alive\r\nContent-Length: 45\r\nContent-Type: application/json\r\nOrigin: http://local.hubtones.com\r\nReferer: http://local.hubtones.com/project/1/edit\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36\r\n\r\n{\"project_id\":\"1\",\"talent_ids\":[1 4 8]}"


WORKS:

2016/12/03 10:18:33 project_talent_wanted.go:87: <nil>
2016/12/03 10:18:33 project_talent_wanted.go:88: "PUT /api/v1/project_talent_wanted/1 HTTP/1.1\r\nHost: local.hubtones.com:11062\r\nAccept: application/json\r\nAccept-Encoding: gzip, deflate, sdch\r\nAccept-Language: en-US,en;q=0.8\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODA5Njg0NjIsImlkIjoiVGVzdCBVc2VyIMKpIiwib3JpZ19pYXQiOjE0ODA0MDc2MzEsInVzZXJfaWQiOjUzNywidXNlcm5hbWUiOiJUZXN0IFVzZXIgwqkifQ.KYuZ77m5o8OGO9Cq6seCEgKdmbQ0bh5fj4ZGlRw26BI\r\nConnection: keep-alive\r\nContent-Length: 45\r\nContent-Type: application/json\r\nOrigin: http://local.hubtones.com\r\nReferer: http://local.hubtones.com/project/1/edit\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36\r\n\r\n{\"project_id\":\"1\",\"talent_ids\":[\"1\",\"4\",\"8\"]}"
2016/12/03 10:18:33 project_talent_wanted.go:130: deleteAllTalentFromProject
2016/12/03 10:18:33 gorp.go:1164: INSERT INTO project_talent_wanted (project_id, talent_id) VALUES (?, ?),(?, ?),(?, ?); [1:<nil>]
2016/12/03 10:18:33 gorp.go:1164: SELECT * FROM project_talent_wanted WHERE project_id=? [1:"1"]
2016/12/03 10:18:33 project_talent_wanted.go:185: <nil>



full project submit broken - table media (final step)

Referer: http://local.hubtones.com/project/1/edit
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36


interface conversion: interface {} is []interface {}, not map[string]interface {}
/usr/local/go/src/runtime/panic.go:458 (0x2f2e3)
        gopanic: reflectcall(nil, unsafe.Pointer(d.fn), deferArgs(d), uint32(d.siz), uint32(d.siz))
/usr/local/go/src/runtime/iface.go:201 (0x12c8f)
        panicdottype: panic(&TypeAssertionError{iface.string(), haveString, want.string(), ""})
/Users/dwright/Dev/go/src/bitbucket.org/dvwright/gin-xss/xss.go:122 (0x6008e)
        (*XssMw).XssRemove: m := jsonBod.(map[string]interface{})


NEED TO SUPPORT : interface conversion: interface {} is []interface {}, not map[string]interface {}

2016/12/03 10:28:20 media.go:112: "PUT /api/v1/project_media/1 HTTP/1.1\r\nHost: local.hubtones.com:11062\r\nAccept: application/json\r\nAccept-Encoding: gzip, deflate, sdch\r\nAccept-Language: en-US,en;q=0.8\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODA5Njg0NjIsImlkIjoiVGVzdCBVc2VyIMKpIiwib3JpZ19pYXQiOjE0ODA0MDc2MzEsInVzZXJfaWQiOjUzNywidXNlcm5hbWUiOiJUZXN0IFVzZXIgwqkifQ.KYuZ77m5o8OGO9Cq6seCEgKdmbQ0bh5fj4ZGlRw26BI\r\nConnection: keep-alive\r\nContent-Length: 9011\r\nContent-Type: application/json\r\nOrigin: http://local.hubtones.com\r\nReferer: http://local.hubtones.com/project/1/edit\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36\r\n\r\n[{\"id\":286,\"name\":\"asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3\",\"url\":\"/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3' download='/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493957,\"updated_by\":537,\"created_at\":1480450694,\"created_by\":537},{\"id\":285,\"name\":\"asdf\",\"url\":\"/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3' download='/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddd70dd75.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493955,\"updated_by\":537,\"created_at\":1480450655,\"created_by\":537},{\"id\":284,\"name\":\"asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddddddddd.mp3\",\"url\":\"/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddddddddd.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddddddddd.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddddddddd.mp3' download='/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddddddddd.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/asdfasdddddddddddddddddddddddddddddddddsdfasdfiqwerasdfasdddddddddddddddddd.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493954,\"updated_by\":537,\"created_at\":1480450583,\"created_by\":537},{\"id\":283,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493952,\"updated_by\":537,\"created_at\":1480450495,\"created_by\":537},{\"id\":282,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493951,\"updated_by\":537,\"created_at\":1480441943,\"created_by\":537},{\"id\":281,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493949,\"updated_by\":537,\"created_at\":1480441639,\"created_by\":537},{\"id\":280,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493947,\"updated_by\":537,\"created_at\":1480441185,\"created_by\":537},{\"id\":279,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493946,\"updated_by\":537,\"created_at\":1480440648,\"created_by\":537},{\"id\":278,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493944,\"updated_by\":537,\"created_at\":1480440539,\"created_by\":537},{\"id\":277,\"name\":\"sb.mp3\",\"url\":\"/data/project/1/sb.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/sb.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/sb.mp3' download='/data/project/1/sb.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/sb.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493943,\"updated_by\":537,\"created_at\":1480440440,\"created_by\":537},{\"id\":276,\"name\":\"ampm.mp3\",\"url\":\"/data/project/1/ampm.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/ampm.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/ampm.mp3' download='/data/project/1/ampm.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/ampm.mp3\",\"mtype\":\"audio/mpeg\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493942,\"updated_by\":537,\"created_at\":1480437869,\"created_by\":537},{\"id\":275,\"name\":\"ampm.mp3\",\"url\":\"/data/project/1/ampm.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/ampm.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/ampm.mp3' download='/data/project/1/ampm.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/ampm.mp3\",\"mtype\":\"audio/mpeg\",\"ptype\":\"IDEA\",\"status\":\"NEW\",\"username\":\"Test User ©\",\"updated_at\":1480493940,\"updated_by\":537,\"created_at\":1480437779,\"created_by\":537},{\"id\":273,\"name\":\"test_audio.mp3\",\"url\":\"/data/project/1/test_audio.mp3\",\"fqdn_url\":\"<audio class='mda_elem' src='http://local.hubtones.com/data/project/1/test_audio.mp3' controls='controls'></audio><a href='http://local.hubtones.com/data/project/1/test_audio.mp3' download='/data/project/1/test_audio.mp3'><span class='glyphicon glyphicon-download-alt'></span></a>\",\"user_id\":\"537\",\"project_id\":\"1\",\"path\":\"/Library/WebServer/Documents/data/project/1/test_audio.mp3\",\"mtype\":\"application/octet-stream\",\"ptype\":\"IDEA\",\"status\":\"ACCEPTED\",\"username\":\"Test User ©\",\"updated_at\":1480493938,\"updated_by\":537,\"created_at\":1476080139,\"created_by\":537}]"

Should Probably rename this to xss-mw is currently gin-xss

I think this will work with any framework which uses middleware, try to generalize it.

This README would normally document whatever steps are necessary to get your application up and running.


Thanks to
https://github.com/goware/jsonp
https://github.com/appleboy/gin-jwt/tree/v2.1.1
Whose source I read throughly to aid in writing this

and of course
https://github.com/microcosm-cc/bluemonday

and
https://static.googleusercontent.com/intl/hu/about/appsecurity/learning/xss/
for inspiring me to to look for and not finding a framework, so having to write one.
>> A note on manually escaping input
>> Writing your own code for escaping input and then properly and consistently applying it is extremely difficult. We do not recommend that you manually escape user-supplied data. Instead, we strongly recommend that you use a templating system or web development framework that provides context-aware auto-escaping. 


### What is this repository for? ###

* Quick summary
* Version
* [Learn Markdown](https://bitbucket.org/tutorials/markdowndemo)

### How do I get set up? ###

* Summary of set up
* Configuration
* Dependencies
* Database configuration
* How to run tests
* Deployment instructions

### Contribution guidelines ###

* Writing tests
* Code review
* Other guidelines

### Who do I talk to? ###

* Repo owner or admin
* Other community or team contact

