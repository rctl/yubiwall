package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/GeertJohan/yubigo"
	jwt "github.com/dgrijalva/jwt-go"
)

func contains(arr []string, v string) bool {
	for _, s := range arr {
		if s == v {
			return true
		}
	}
	return false
}

func main() {
	//Fetch parameters from ENV
	domain := os.Getenv("DOMAIN")
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	clientId := os.Getenv("YUBICO_CLIENT_ID")
	clientSecret := os.Getenv("YUBICO_SECRET_KEY")
	keyTTL := int64(60 * 120) //2h
	allowedKeys := strings.Split(os.Getenv("ALLOWED_KEYS"), ",")

	//Parse key TTL value in minutes
	envKeyTTL := os.Getenv("KEY_TTL")
	if envKeyTTL != "" {
		v, err := strconv.Atoi(envKeyTTL)
		if err != nil {
			panic(err)
		}
		keyTTL = int64(v * 60)
	}

	if domain == "" || len(jwtSecret) == 0 || clientId == "" || clientSecret == "" || len(allowedKeys) == 0 {
		panic(errors.New("Environment values are misconfigured"))
	}

	fmt.Println("Auth server is up and running")
	fmt.Printf("Domain: %s, Allowed Keys: %v\n", domain, allowedKeys)

	//Yubico Client
	yubiAuth, err := yubigo.NewYubiAuth(clientId, clientSecret)
	if err != nil {
		panic(err)
	}

	//Endpoint for verifying existance of a token
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		for _, cookie := range r.Cookies() {
			if cookie.Name == "yubiwall-token" {
				//Verify token provided by client
				token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}
					return jwtSecret, nil
				})
				if err != nil {
					fmt.Println("GET /verify - Bad token")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Failed to parse token"))
					return
				}
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					expires, err := strconv.ParseInt(claims["expires"].(string), 10, 64)
					if err != nil {
						panic(err)
					}
					if expires < time.Now().Unix() {
						fmt.Println("GET /verify - Bad token (expired)")
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte("Token Expired"))
					}
					w.Header().Set("Yubikey-ID", claims["id"].(string))
					fmt.Println("GET /verify - OK")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Authentication succeeded"))
					return
				}
			}
		}
		fmt.Println("GET /verify - Needs authentication")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authentication failed"))
	})

	//Endpoint to verify login
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		//Request parsing
		if err := r.ParseForm(); err != nil {
			fmt.Println("POST /auth - bad request")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Request was malformed!"))
			return
		}
		secret := r.FormValue("secret")
		redirect := r.FormValue("redirect")
		fmt.Printf("POST /auth - redirect: %s\n", redirect)
		//Verify Yubikey Token
		_, ok, err := yubiAuth.Verify(secret)
		if err != nil {
			msg := "Token was invalid, please try again."
			url := fmt.Sprintf("/login?message=%s&rd=%s", url.QueryEscape(msg), url.QueryEscape(redirect))
			http.Redirect(w, r, url, http.StatusFound)
			return
		}
		if ok {
			//Token is valid but not allowed
			if !contains(allowedKeys, secret[:12]) {
				msg := "Token was valid, but is not in list of allowed keys."
				url := fmt.Sprintf("/login?message=%s&rd=%s", url.QueryEscape(msg), url.QueryEscape(redirect))
				http.Redirect(w, r, url, http.StatusFound)
				return
			}
			//Generate and return cookie
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"expires": strconv.FormatInt(time.Now().Unix()+keyTTL, 10),
				"id":      secret[:12],
			})
			tokenString, err := token.SignedString(jwtSecret)
			if err != nil {
				panic(err)
			}
			http.SetCookie(w, &http.Cookie{
				Name:   "yubiwall-token",
				Value:  tokenString,
				Domain: domain,
				Secure: true,
			})
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		//Token invalid
		fmt.Println("POST /auth - bad secret")
		msg := "Authentication failed, please try again."
		url := fmt.Sprintf("/login?message=%s&rd=%s", url.QueryEscape(msg), url.QueryEscape(redirect))
		http.Redirect(w, r, url, http.StatusFound)
	})

	//Login frontend
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("GET /login")
		http.ServeFile(w, r, "./index.html")
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
