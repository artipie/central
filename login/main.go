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
	"time"
)

const (
	postURL = "https://github.com/login/oauth/access_token"
)

type ctxKey struct {
	k int
}

type exchange struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func (e *exchange) String() string {
	return fmt.Sprintf("AccessToken: '%s', Scope: '%s', TokenType: '%s'",
		hide(e.AccessToken), e.Scope, e.TokenType)
}

var (
	ctxHint = ctxKey{1}
)

func main() {
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()
		log.Printf("processing: %s", r.URL)
		code := r.URL.Query().Get("code")
		exc, err := exchangeCode(code)
		ctx = context.WithValue(ctx, ctxHint, code)
		if fail(w, err) {
			return
		}
		usr, err := authenticate(ctx, exc.AccessToken)
		if fail(w, err) {
			return
		}
		ses, err := session(ctx, usr)
		if fail(w, err) {
			return
		}
		log.Printf("processed successfully: `%s` -> `%s`", code, usr)
		w.Header().Add("Location", fmt.Sprintf("/dashboard/%s", usr))
		http.SetCookie(w, &http.Cookie{Name: "session", Value: ses})
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte("<!DOCTYPE HTML><html><body>Redirecting</body></html>"))
	})
	log.Fatal(http.ListenAndServe(":80", nil))
}

type errSession struct {
	origin error
	hint   string
	user   string
}

func (e *errSession) Error() string {
	return fmt.Sprintf("session error for `%s` (user=`%s`): %s", e.hint, e.user, e.origin)
}

func session(ctx context.Context, usr string) (string, error) {
	hint := ctx.Value(ctxHint).(string)
	file, err := os.Open(os.Getenv("SESSION_KEY"))
	if err != nil {
		return "", &errSession{err, hint, usr}
	}
	defer file.Close()
	bin, err := ioutil.ReadAll(file)
	if err != nil {
		return "", &errSession{err, hint, usr}
	}
	key, err := x509.ParsePKIXPublicKey(bin)
	if err != nil {
		return "", &errSession{err, hint, usr}
	}
	enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key.(*rsa.PublicKey), []byte(usr), nil)
	if err != nil {
		return "", &errSession{err, hint, usr}
	}
	hx := hex.EncodeToString(enc)
	log.Printf("created session key for `%s` (user=`%s`): `%s`", hint, usr, hide(hx))
	return hx, nil
}

type errExchange struct {
	origin error
	code   string
}

func (e *errExchange) Error() string {
	return fmt.Sprintf("failed to exchange code `%s` due to: %s", e.code, e.origin)
}

func exchangeCode(code string) (*exchange, error) {
	log.Printf("exchanging code: `%s`", code)
	form := url.Values{
		"client_id":     {os.Getenv("OAUTH_CLIENT")},
		"client_secret": {os.Getenv("OAUTH_SECRET")},
		"code":          {code},
	}
	req, err := http.NewRequest("POST", postURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &errExchange{err, code}
	}
	req.Header.Add("Accept", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &errExchange{err, code}
	}
	defer rsp.Body.Close()
	res := new(exchange)
	if err := json.NewDecoder(rsp.Body).Decode(res); err != nil {
		return nil, &errExchange{err, code}
	}
	log.Printf("code `%s` exchanged succesfully for `%s`", code, res)
	return res, nil
}

type errAuth struct {
	origin error
	hint   string
}

func (e *errAuth) Error() string {
	return fmt.Sprintf("auth error for `%s`: %s", e.hint, e.origin)
}

func authenticate(ctx context.Context, token string) (string, error) {
	hint := ctx.Value(ctxHint).(string)
	log.Printf("authenticating for `%s`", hint)
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	gh := github.NewClient(tc)
	usr, _, err := gh.Users.Get(ctx, "")
	if err != nil {
		return "", &errAuth{err, hint}
	}
	log.Printf("authenticated `%s` as `%s`", hint, usr)
	return usr.GetLogin(), nil
}

func fail(w http.ResponseWriter, err error) bool {
	if err != nil {
		log.Printf("ERROR: %s", err)
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return true
	}
	return false
}

func hide(s string) string {
	if len(s) <= 5 {
		return strings.Repeat("*", len(s))
	}
	if len(s) <= 8 {
		return strings.Repeat("*", len(s)-2) + s[len(s)-2:]
	}
	return strings.Repeat("*", len(s)-3) + s[len(s)-3:]
}
