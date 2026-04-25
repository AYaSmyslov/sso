package auth

import (
	"context"
	"net/http"
	"strings"

	ssojwt "github.com/AYaSmyslov/sso/internal/lib/jwt"
)

type ctxKey int

const userIDCtxKey ctxKey = iota

const bearerPrefix = "Bearer "

func (s *serverAPI) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, bearerPrefix) {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
			return
		}
		tokenString := strings.TrimPrefix(header, bearerPrefix)
		if tokenString == "" {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
			return
		}

		appID, err := ssojwt.AppIDUnverified(tokenString)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		secret, err := s.auth.AppSecret(r.Context(), appID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		claims, err := ssojwt.Parse(tokenString, secret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		uidF, ok := claims["uid"].(float64)
		if !ok || int64(uidF) == 0 {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), userIDCtxKey, int64(uidF))
		next(w, r.WithContext(ctx))
	}
}

func userIDFromContext(ctx context.Context) (int64, bool) {
	v, ok := ctx.Value(userIDCtxKey).(int64)
	return v, ok
}
