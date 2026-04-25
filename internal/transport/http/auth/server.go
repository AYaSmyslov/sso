package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/AYaSmyslov/sso/internal/services/auth"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	ChangePassword(
		ctx context.Context,
		userID int64,
		oldPassword string,
		newPassword string,
	) error
	AppSecret(ctx context.Context, appID int) ([]byte, error)
}

type InputLogin struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	AppId    int64  `json:"app_id"`
}

type InputRegister struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type InputChangePassword struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

const (
	emptyValue = 0
)

type serverAPI struct {
	auth Auth
	mux  *http.ServeMux
}

func Register(httpSever *http.Server, auth Auth) {
	httpSever.Handler = newServer(auth)
}

func newServer(auth Auth) *serverAPI {
	server := &serverAPI{
		auth: auth,
		mux:  http.NewServeMux(),
	}

	server.routes()

	return server
}

func (s *serverAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *serverAPI) routes() {
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("POST /register", s.register)
	s.mux.HandleFunc("GET /is-admin", s.isAdmin)
	s.mux.HandleFunc("POST /change-password", s.requireAuth(s.changePassword))
}

func (s *serverAPI) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var inputLogin InputLogin
	if err := readJSON(r, &inputLogin); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if !validateLogin(w, inputLogin) {
		return
	}

	token, err := s.auth.Login(ctx, inputLogin.Email, inputLogin.Password, int(inputLogin.AppId))
	if err != nil {

		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"token": token})
}

func (s *serverAPI) register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var inputRegister InputRegister
	if err := readJSON(r, &inputRegister); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if !validateRegister(w, inputRegister) {
		return
	}

	userID, err := s.auth.RegisterNewUser(ctx, inputRegister.Email, inputRegister.Password)
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return

	}

	writeJSON(w, http.StatusCreated, map[string]int64{"user_id": userID})
}

func (s *serverAPI) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := userIDFromContext(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var input InputChangePassword
	if err := readJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if !validateChangePassword(w, input) {
		return
	}

	err := s.auth.ChangePassword(ctx, userID, input.OldPassword, input.NewPassword)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid old password")
			return
		}
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *serverAPI) isAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	raw := r.URL.Query().Get("user_id")
	if raw == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	userID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || userID == emptyValue {
		writeError(w, http.StatusBadRequest, "user_id must be a positive integer")
		return
	}

	isAdmin, err := s.auth.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"is_admin": isAdmin})
}

func validateLogin(w http.ResponseWriter, inputLogin InputLogin) bool {
	if inputLogin.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return false
	}
	if inputLogin.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return false
	}
	if inputLogin.AppId == emptyValue {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return false
	}

	return true
}

func validateRegister(w http.ResponseWriter, inputRegister InputRegister) bool {
	if inputRegister.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return false
	}
	if inputRegister.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return false
	}
	return true
}

func validateChangePassword(w http.ResponseWriter, input InputChangePassword) bool {
	if input.OldPassword == "" {
		writeError(w, http.StatusBadRequest, "old_password is required")
		return false
	}
	if input.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "new_password is required")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
