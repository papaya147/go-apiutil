package apiutil

import (
	"aidanwoods.dev/go-paseto"
	"encoding/json"
	"errors"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type TokenType int

type TokenPayload interface {
	GetTokenId() uuid.UUID
	GetIssuedAt() time.Time
	GetExpiresAt() time.Time
	GetType() TokenType
	SetTokenId(uuid.UUID)
	SetIssuedAt(time.Time)
	SetExpiresAt(time.Time)
	SetType(TokenType)
}

type TokenMaker[P TokenPayload] interface {
	CreateToken(P, TokenType) (string, P, error)
	VerifyToken(string, TokenType) (P, error)
}

type PasetoMaker[P TokenPayload] struct {
	tokenDuration                        map[TokenType]time.Duration
	secretKey                            paseto.V4SymmetricKey
	parser                               paseto.Parser
	invalidTokenError, expiredTokenError error
}

func (p PasetoMaker[P]) CreateToken(payload P, tokenType TokenType) (string, P, error) {
	now := time.Now()

	payload.SetTokenId(uuid.New())
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
			return payload, p.expiredTokenError
		}
		return payload, p.invalidTokenError
	}

	j, err := decrypted.GetString("payload")
	if err != nil {
		return payload, p.invalidTokenError
	}

	if json.Unmarshal([]byte(j), &payload) != nil {
		return payload, p.invalidTokenError
	}

	if payload.GetType() != tokenType {
		return payload, p.invalidTokenError
	}

	return payload, nil
}

func NewPasetoMaker[P TokenPayload](durations map[TokenType]time.Duration, invalidTokenError, expiredTokenError error) TokenMaker[P] {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired(), paseto.NotBeforeNbf())

	return &PasetoMaker[P]{
		tokenDuration:     durations,
		secretKey:         paseto.NewV4SymmetricKey(),
		parser:            parser,
		invalidTokenError: invalidTokenError,
		expiredTokenError: expiredTokenError,
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
	tokenDuration                        map[TokenType]time.Duration
	secretKey                            []byte
	signingMethod                        jwt.SigningMethod
	parser                               *jwt.Parser
	invalidTokenError, expiredTokenError error
}

func (j JWTMaker[P]) CreateToken(payload P, tokenType TokenType) (string, P, error) {
	now := time.Now()

	payload.SetTokenId(uuid.New())
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
			return nil, j.invalidTokenError
		}
		return j.secretKey, nil
	})
	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return payload, j.expiredTokenError
		}
		return payload, err
	}

	tokenPayload, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return payload, j.invalidTokenError
	}

	if err := json.Unmarshal([]byte(tokenPayload["payload"].(string)), &payload); err != nil {
		return payload, err
	}

	if payload.GetType() != tokenType {
		return payload, j.invalidTokenError
	}

	return payload, nil
}

func NewJWTMaker[P TokenPayload](durations map[TokenType]time.Duration, invalidTokenError, expiredTokenError error, secret string) TokenMaker[P] {
	signingMethod := jwt.SigningMethodHS256

	return &JWTMaker[P]{
		tokenDuration: durations,
		secretKey:     []byte(secret),
		signingMethod: signingMethod,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{signingMethod.Name}),
			jwt.WithExpirationRequired(),
		),
		invalidTokenError: invalidTokenError,
		expiredTokenError: expiredTokenError,
	}
}
