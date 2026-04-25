package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/AYaSmyslov/sso/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrInvalidClaim = errors.New("invalid claim")
)

func NewToken(
	user models.User,
	app models.App,
	duration time.Duration,
) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

// AppIDUnverified extracts app_id from an unverified token. Used to look up
// the signing secret before doing real signature verification.
func AppIDUnverified(tokenString string) (int, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return 0, fmt.Errorf("%w: %s", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrInvalidClaim
	}

	raw, ok := claims["app_id"].(float64)
	if !ok {
		return 0, fmt.Errorf("%w: app_id", ErrInvalidClaim)
	}

	return int(raw), nil
}

// Parse validates the token signature against the given secret and returns
// its claims. Expiration is verified by the underlying library.
func Parse(tokenString string, secret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unexpected signing method %v", ErrInvalidToken, t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
