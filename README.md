# Xss Middleware 

XssMw is an middleware written in [Golang](https://golang.org/) for the 
[Gin](https://github.com/gin-gonic/gin) web framework.

Although, it should be useable with any Go web framework which utilizes Golang's "net/http" native 
library in a similiar way to Gin.

The idea behind XssMw is to auto remove XSS from user submitted input. 

It's applied on http POST and PUT Requests.

Currently it only supports JSON requests - Content-Type application/json. So no filtering on multipart requests yet.


# How To Use it?

Somthing like this.


```
package main

import "gopkg.in/gin-gonic/gin.v1"
import "bitbucket.org/dvwright/xss-mw"

func main() {
    r := gin.Default()

    // include as standard middleware
    var xssMdlwr xss.XssMw
    r.Use(xssMdlwr.RemoveXss())

    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "pong",
        })
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}

```

# Notes

There are a few things to watch out for. For example it will skip filtering for a field named 'password' 

but will filter everything else, there is a TODO for configs to add passing excude tables/fields from filtering.


It's highly configurable (not yet but will be) and uses HTML sanitizer https://github.com/microcosm-cc/bluemonday 

for filtering.  

It uses the strictest policy StrictPolicy() and is not confiurable at this time but will be soon. 

e.g. The plan is the you can provide whatever Policy you want to enforce.


Currently, it removes (deletes) all HTML and malicious detected input from user input on 

the submitted request to the server. In the future the plan is have a feature to store 

all user submitted data

intact and filter it out on the http Response, so you can choose your preference.

- in other words - data would be stored in the database as it was submitted and removed in Responses back to the user.

Pros: data integrity

Cons: XSS exploits still present


NOTE: This is Beta level code with minimal actual usage and currently no features.


## Contributing 

You are welcome to contribute to this project. 
Please update/add tests as appropriate.
Send pull request against the Develop branch.
Please use the same formatting as the Go authors. Run code through gofmt before submitting. 
Thanks


### Misc ###

Thanks to

https://github.com/goware/jsonp

https://github.com/appleboy/gin-jwt/tree/v2.1.1

Whose source I read throughly to aid in writing this

and of course

https://github.com/microcosm-cc/bluemonday

and the gin middleware

and

https://static.googleusercontent.com/intl/hu/about/appsecurity/learning/xss/

for inspiring me to to look for and not finding a framework, so attempting to write one.

> A note on manually escaping input
> Writing your own code for escaping input and then properly and consistently applying it is extremely difficult. 
> We do not recommend that you manually escape user-supplied data. Instead, we strongly recommend that you 
> use a templating system or web development framework that provides context-aware auto-escaping. 

