package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

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
