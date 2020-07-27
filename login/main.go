package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/go-github/v32/github"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	postURL = "https://github.com/login/oauth/access_token"
)

type exchange struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

var (
	ctx = context.Background()
)

func main() {
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		exc, err := exchangeCode(r.URL.Query().Get("code"))
		if fail(w, err) {
			return
		}
		usr, err := authenticate(ctx, exc.AccessToken)
		if fail(w, err) {
			return
		}
		ses, err := session(usr)
		if fail(w, err) {
			return
		}
		w.Header().Add("Location", fmt.Sprintf("/dashboard/%s", usr))
		http.SetCookie(w, &http.Cookie{Name: "session", Value: ses})
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte("<!DOCTYPE HTML><html><body>Redirecting</body></html>"))
	})
	log.Fatal(http.ListenAndServe(":80", nil))
}

func session(usr string) (string, error) {
	file, err := os.Open(os.Getenv("SESSION_KEY"))
	if err != nil {
		return "", err
	}
	defer file.Close()
	bin, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}
	key, err := x509.ParsePKIXPublicKey(bin)
	if err != nil {
		return "", err
	}
	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key.(*rsa.PublicKey), []byte(usr), nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

func exchangeCode(code string) (*exchange, error) {
	form := url.Values{
		"client_id":     {os.Getenv("OAUTH_CLIENT")},
		"client_secret": {os.Getenv("OAUTH_SECRET")},
		"code":          {code},
	}
	req, err := http.NewRequest("POST", postURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}
	res := new(exchange)
	if err := json.NewDecoder(rsp.Body).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

func authenticate(ctx context.Context, token string) (string, error) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	gh := github.NewClient(tc)
	usr, _, err := gh.Users.Get(ctx, "")
	if err != nil {
		return "", err
	}
	return usr.GetLogin(), nil
}

func fail(w http.ResponseWriter, err error) bool {
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return true
	}
	return false
}
