package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.POST("/jwt", CreatJWT)
	r.POST("/login", Middleware(), Login)
	r.Run(":8080")
}

func CreatJWT(c *gin.Context) {
	username := c.PostForm("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "请提交用户名"})
	}
	jwt := CreateJWT(username)
	c.JSON(http.StatusOK, gin.H{
		"jwt": jwt,
	})

}

func Login(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"msg": "login successfully"})
}

func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwt := c.PostForm("jwt")
		if !IsValidJWT(jwt) {
			c.JSON(http.StatusBadRequest, gin.H{"err": "token无效"})
			c.Abort()
			return
		}
		fmt.Println("jwt认证成功")
		c.Next()
	}
}

// CreateJWT 生成jwt
func CreateJWT(username string) string {

	header, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		fmt.Println("marshal err")
		return ""
	}
	jwtHeader := base64.URLEncoding.EncodeToString(header)

	body, err := json.Marshal(map[string]interface{}{
		"iss": username,
		"exp": "20231216",
		"jti": "100",
	})
	if err != nil {
		fmt.Println("marshal err")
		return ""
	}
	jwtBody := base64.URLEncoding.EncodeToString(body)

	sign := SignCreatFunc(jwtHeader + "." + jwtBody)
	return jwtHeader + "." + jwtBody + "." + sign
}

// SignCreatFunc sha256加密
func SignCreatFunc(HeaderPointBody string) string {
	h := sha256.New()
	secret := "xiaote33"
	h.Write([]byte(HeaderPointBody + secret))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func IsValidJWT(jwt string) bool {
	arr := strings.Split(jwt, ".")
	if len(arr) != 3 {
		return false
	}
	if arr[2] != SignCreatFunc(arr[0]+"."+arr[1]) {
		return false
	}
	return true
}
