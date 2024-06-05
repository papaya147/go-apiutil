package apiutil

import (
	"errors"
	"github.com/google/uuid"
	"github.com/papaya147/randomize"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type TestTokenPayload struct {
	TokenId   uuid.UUID `json:"token_id"`
	Arg1      uuid.UUID `json:"arg1"`
	Arg2      string    `json:"arg2"`
	Arg3      int       `json:"arg3"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenType TokenType `json:"token_type"`
}

func (t TestTokenPayload) GetTokenId() uuid.UUID {
	return t.TokenId
}

func (t TestTokenPayload) GetIssuedAt() time.Time {
	return t.IssuedAt
}

func (t TestTokenPayload) GetExpiresAt() time.Time {
	return t.ExpiresAt
}

func (t TestTokenPayload) GetType() TokenType {
	return t.TokenType
}

func (t TestTokenPayload) SetTokenId(u uuid.UUID) {
	t.TokenId = u
}

func (t TestTokenPayload) SetIssuedAt(time time.Time) {
	t.IssuedAt = time
}

func (t TestTokenPayload) SetExpiresAt(time time.Time) {
	t.ExpiresAt = time
}

func (t TestTokenPayload) SetType(tokenType TokenType) {
	t.TokenType = tokenType
}

const (
	AccessTokenTypeTest TokenType = iota
	RefreshTokenTypeTest
)

func randomTokenType() TokenType {
	return AccessTokenTypeTest
}

func createRandomToken(t *testing.T, maker Maker[TestTokenPayload]) (string, TestTokenPayload) {
	randomize.RegisterCustomRandomizer(randomTokenType)
	arg, err := randomize.Do[TestTokenPayload]()
	require.NoError(t, err)

	token, p, err := maker.CreateToken(arg, AccessTokenTypeTest)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, p)

	return token, p
}

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

var pasetoMaker = NewPasetoMaker[TestTokenPayload](map[TokenType]time.Duration{
	AccessTokenTypeTest:  time.Minute,
	RefreshTokenTypeTest: time.Hour,
}, ErrInvalidToken, ErrExpiredToken)

var jwtMaker = NewJWTMaker[TestTokenPayload](map[TokenType]time.Duration{
	AccessTokenTypeTest:  time.Minute,
	RefreshTokenTypeTest: time.Hour,
}, ErrInvalidToken, ErrExpiredToken, "secret!")

func TestPasetoMaker_CreateToken(t *testing.T) {
	createRandomToken(t, pasetoMaker)
}

func TestPasetoMaker_VerifyToken(t *testing.T) {
	token, payload1 := createRandomToken(t, pasetoMaker)
	payload2, err := pasetoMaker.VerifyToken(token, payload1.TokenType)
	require.NoError(t, err)
	require.NotEmpty(t, payload2)
	require.Equal(t, payload1, payload2)
}

func TestJWTMaker_CreateToken(t *testing.T) {
	createRandomToken(t, jwtMaker)
}

func TestJWTMaker_VerifyToken(t *testing.T) {
	token, payload1 := createRandomToken(t, jwtMaker)
	payload2, err := jwtMaker.VerifyToken(token, payload1.TokenType)
	require.NoError(t, err)
	require.NotEmpty(t, payload2)
	require.Equal(t, payload1, payload2)
}
