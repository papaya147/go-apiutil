package apiutil

import (
	"aidanwoods.dev/go-paseto"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"net/http"
	"time"
)

func init() {
	gob.Register(TokenType(0))
}

type TokenType int

type TokenPayload interface {
	GetIssuedAt() time.Time
	GetExpiresAt() time.Time
	GetType() TokenType
	SetIssuedAt(time.Time)
	SetExpiresAt(time.Time)
	SetType(TokenType)
}

type TokenMaker[P TokenPayload] interface {
	CreateToken(P, TokenType) (string, P, error)
	VerifyToken(string, TokenType) (P, error)
	Middleware(*sessions.CookieStore, string, TokenType) func(http.Handler) http.Handler
	TokenFromRequest(*http.Request, TokenType) (P, error)
}

type PasetoMaker[P TokenPayload] struct {
	tokenDuration                                      map[TokenType]time.Duration
	secretKey                                          paseto.V4SymmetricKey
	parser                                             paseto.Parser
	errInvalidToken, errExpiredToken, errInvalidCookie error
}

func (p PasetoMaker[P]) Middleware(store *sessions.CookieStore, sessionName string, tokenType TokenType) func(http.Handler) http.Handler {
	return tokenMiddleware[P](p, store, sessionName, tokenType, p.errInvalidCookie)
}

func (p PasetoMaker[P]) TokenFromRequest(request *http.Request, tokenType TokenType) (P, error) {
	return tokenFromRequest[P](request, tokenType, p.errInvalidCookie)
}

func (p PasetoMaker[P]) CreateToken(payload P, tokenType TokenType) (string, P, error) {
	now := time.Now()

	payload.SetIssuedAt(now)
	payload.SetExpiresAt(now.Add(p.tokenDuration[tokenType]))
	payload.SetType(tokenType)

	token := paseto.NewToken()
	token.SetIssuedAt(payload.GetIssuedAt())
	token.SetNotBefore(payload.GetIssuedAt().Add(-time.Hour)) // arbitrary amount
	token.SetExpiration(payload.GetExpiresAt())

	j, err := json.Marshal(payload)
	if err != nil {
		return "", payload, err
	}

	token.SetString("payload", string(j))

	return token.V4Encrypt(p.secretKey, nil), payload, nil
}

func (p PasetoMaker[P]) VerifyToken(s string, tokenType TokenType) (P, error) {
	var payload P
	decrypted, err := p.parser.ParseV4Local(p.secretKey, s, nil)
	if err != nil {
		if err.Error() == "this token has expired" {
			return payload, p.errExpiredToken
		}
		return payload, p.errInvalidToken
	}

	j, err := decrypted.GetString("payload")
	if err != nil {
		return payload, p.errInvalidToken
	}

	if json.Unmarshal([]byte(j), &payload) != nil {
		return payload, p.errInvalidToken
	}

	if payload.GetType() != tokenType {
		return payload, p.errInvalidToken
	}

	return payload, nil
}

func NewPasetoMaker[P TokenPayload](durations map[TokenType]time.Duration, errInvalidToken, errExpiredToken, errInvalidCookie error) TokenMaker[P] {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired(), paseto.NotBeforeNbf())

	return &PasetoMaker[P]{
		tokenDuration:    durations,
		secretKey:        paseto.NewV4SymmetricKey(),
		parser:           parser,
		errInvalidToken:  errInvalidToken,
		errExpiredToken:  errExpiredToken,
		errInvalidCookie: errInvalidCookie,
	}
}

type JWTPayload struct {
	jwt.Claims
	MarshalledPayload string `json:"payload"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
}

func (j JWTPayload) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(j.ExpiresAt, 0)), nil
}

func (j JWTPayload) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(j.IssuedAt, 0)), nil
}

func (j JWTPayload) GetNotBefore() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(j.IssuedAt, 0)), nil
}

func (j JWTPayload) GetIssuer() (string, error) {
	return "", nil
}

func (j JWTPayload) GetSubject() (string, error) {
	return "", nil
}

func (j JWTPayload) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

type JWTMaker[P TokenPayload] struct {
	tokenDuration                                      map[TokenType]time.Duration
	secretKey                                          []byte
	signingMethod                                      jwt.SigningMethod
	parser                                             *jwt.Parser
	errInvalidToken, errExpiredToken, errInvalidCookie error
}

func (j JWTMaker[P]) CreateToken(payload P, tokenType TokenType) (string, P, error) {
	now := time.Now()

	payload.SetIssuedAt(now)
	payload.SetExpiresAt(now.Add(j.tokenDuration[tokenType]))
	payload.SetType(tokenType)

	js, err := json.Marshal(payload)
	if err != nil {
		return "", payload, err
	}

	tokenPayload := JWTPayload{
		MarshalledPayload: string(js),
		IssuedAt:          payload.GetIssuedAt().Unix(),
		ExpiresAt:         payload.GetExpiresAt().Unix(),
	}
	token := jwt.NewWithClaims(j.signingMethod, tokenPayload)
	signed, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", payload, err
	}

	return signed, payload, nil
}

func (j JWTMaker[P]) VerifyToken(s string, tokenType TokenType) (P, error) {
	var payload P
	token, err := j.parser.Parse(s, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, j.errInvalidToken
		}
		return j.secretKey, nil
	})
	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return payload, j.errExpiredToken
		}
		return payload, err
	}

	tokenPayload, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return payload, j.errInvalidToken
	}

	if err := json.Unmarshal([]byte(tokenPayload["payload"].(string)), &payload); err != nil {
		return payload, err
	}

	if payload.GetType() != tokenType {
		return payload, j.errInvalidToken
	}

	return payload, nil
}

func (j JWTMaker[P]) Middleware(store *sessions.CookieStore, sessionName string, tokenType TokenType) func(http.Handler) http.Handler {
	return tokenMiddleware[P](j, store, sessionName, tokenType, j.errInvalidCookie)
}

func (j JWTMaker[P]) TokenFromRequest(request *http.Request, tokenType TokenType) (P, error) {
	return tokenFromRequest[P](request, tokenType, j.errInvalidCookie)
}

func NewJWTMaker[P TokenPayload](durations map[TokenType]time.Duration, errInvalidToken, errExpiredToken, errInvalidCookie error, secret string) TokenMaker[P] {
	signingMethod := jwt.SigningMethodHS256

	return &JWTMaker[P]{
		tokenDuration: durations,
		secretKey:     []byte(secret),
		signingMethod: signingMethod,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{signingMethod.Name}),
			jwt.WithExpirationRequired(),
		),
		errInvalidToken:  errInvalidToken,
		errExpiredToken:  errExpiredToken,
		errInvalidCookie: errInvalidCookie,
	}
}

func tokenMiddleware[P TokenPayload](tokenMaker TokenMaker[P], cookieStore *sessions.CookieStore, sessionName string, tokenType TokenType, errInvalidCookie error) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, _ := cookieStore.Get(r, sessionName)
			token, ok := sess.Values[tokenType].(string)
			if !ok {
				ErrorJson(w, errInvalidCookie)
				return
			}

			payload, err := tokenMaker.VerifyToken(token, tokenType)
			if err != nil {
				ErrorJson(w, err)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, tokenType, payload)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func tokenFromRequest[P TokenPayload](r *http.Request, tokenType TokenType, errInvalidToken error) (P, error) {
	ctx := r.Context()
	var payload P

	payload, ok := ctx.Value(tokenType).(P)
	if !ok {
		return payload, errInvalidToken
	}

	return payload, nil
}
