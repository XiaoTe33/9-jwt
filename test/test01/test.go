package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func main() {
	jwt := CreateJWT("ksa")
	fmt.Println(jwt)
}

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

	sign := SignCreatFunc(jwtHeader + "." + jwtBody + "secret")
	return jwtHeader + "." + jwtBody + "." + sign
}
func main01() {
	h := sha256.New()
	h.Write([]byte("sda"))
	fmt.Println(fmt.Sprintf("%x", h.Sum(nil)))

}

func SignCreatFunc(HeaderPointBody string) string {
	h := sha256.New()
	h.Write([]byte(HeaderPointBody))
	return fmt.Sprintf("%x", h.Sum(nil))
}
