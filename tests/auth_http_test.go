package tests

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/AYaSmyslov/sso/tests/suite"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTP_RegisterLogin_HappyPath(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	statusReg, regBody := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, statusReg)

	userIDFloat, ok := regBody["user_id"].(float64)
	require.True(t, ok, "user_id missing in response: %v", regBody)
	userID := int64(userIDFloat)
	assert.NotZero(t, userID)

	statusLogin, loginBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": password,
		"app_id":   appID,
	})
	require.Equal(t, http.StatusAccepted, statusLogin)

	loginTime := time.Now()

	token, ok := loginBody["token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, userID, int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1
	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestHTTP_Register_Duplicate(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	statusFirst, _ := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, statusFirst)

	statusDup, body := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusConflict, statusDup)
	assert.Equal(t, "user already exists", body["error"])
}

func TestHTTP_Register_FailCases(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{"Empty Password", gofakeit.Email(), "", "password is required"},
		{"Empty Email", "", randomFakePassword(), "email is required"},
		{"Both Empty", "", "", "email is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
				"email":    tt.email,
				"password": tt.password,
			})
			require.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tt.expectedErr, body["error"])
		})
	}
}

func TestHTTP_Register_InvalidJSON(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	status, body := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":         gofakeit.Email(),
		"password":      randomFakePassword(),
		"unknown_field": "x",
	})
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid json", body["error"])
}

func TestHTTP_Login_FailCases(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	tests := []struct {
		name           string
		email          string
		password       string
		appID          int
		expectedStatus int
		expectedErr    string
	}{
		{
			name:           "Empty Password",
			email:          gofakeit.Email(),
			password:       "",
			appID:          appID,
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "password is required",
		},
		{
			name:           "Empty Email",
			email:          "",
			password:       randomFakePassword(),
			appID:          appID,
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "email is required",
		},
		{
			name:           "Both Empty",
			email:          "",
			password:       "",
			appID:          appID,
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "email is required",
		},
		{
			name:           "Missing AppID",
			email:          gofakeit.Email(),
			password:       randomFakePassword(),
			appID:          emptyAppID,
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "app_id is required",
		},
		{
			name:           "Wrong Password",
			email:          gofakeit.Email(),
			password:       randomFakePassword(),
			appID:          appID,
			expectedStatus: http.StatusUnauthorized,
			expectedErr:    "invalid email or password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusReg, _ := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
				"email":    gofakeit.Email(),
				"password": randomFakePassword(),
			})
			require.Equal(t, http.StatusCreated, statusReg)

			status, body := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
				"email":    tt.email,
				"password": tt.password,
				"app_id":   tt.appID,
			})
			require.Equal(t, tt.expectedStatus, status)
			assert.Equal(t, tt.expectedErr, body["error"])
		})
	}
}

func TestHTTP_IsAdmin_HappyPath(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	statusReg, regBody := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    gofakeit.Email(),
		"password": randomFakePassword(),
	})
	require.Equal(t, http.StatusCreated, statusReg)
	userID := int64(regBody["user_id"].(float64))

	status, body := st.GetWithQuery(ctx, "/is-admin", url.Values{
		"user_id": []string{strconv.FormatInt(userID, 10)},
	})
	require.Equal(t, http.StatusOK, status)
	isAdmin, ok := body["is_admin"].(bool)
	require.True(t, ok, "is_admin missing in response: %v", body)
	assert.False(t, isAdmin)
}

func TestHTTP_IsAdmin_UserNotFound(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	status, body := st.GetWithQuery(ctx, "/is-admin", url.Values{
		"user_id": []string{strconv.FormatInt(int64(gofakeit.Number(1_000_000_000, 2_000_000_000)), 10)},
	})
	require.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "user not found", body["error"])
}

func TestHTTP_ChangePassword_HappyPath(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	email := gofakeit.Email()
	oldPassword := randomFakePassword()
	newPassword := randomFakePassword()

	regStatus, _ := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": oldPassword,
	})
	require.Equal(t, http.StatusCreated, regStatus)

	loginStatus, loginBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": oldPassword,
		"app_id":   appID,
	})
	require.Equal(t, http.StatusAccepted, loginStatus)
	token := loginBody["token"].(string)

	status, _ := st.DoJSONWithToken(ctx, http.MethodPost, "/change-password", token, map[string]any{
		"old_password": oldPassword,
		"new_password": newPassword,
	})
	require.Equal(t, http.StatusNoContent, status)

	staleLogin, staleBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": oldPassword,
		"app_id":   appID,
	})
	require.Equal(t, http.StatusUnauthorized, staleLogin)
	assert.Equal(t, "invalid email or password", staleBody["error"])

	freshLogin, freshBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": newPassword,
		"app_id":   appID,
	})
	require.Equal(t, http.StatusAccepted, freshLogin)
	assert.NotEmpty(t, freshBody["token"])
}

func TestHTTP_ChangePassword_WrongOldPassword(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	regStatus, _ := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, regStatus)

	_, loginBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": password,
		"app_id":   appID,
	})
	token := loginBody["token"].(string)

	status, body := st.DoJSONWithToken(ctx, http.MethodPost, "/change-password", token, map[string]any{
		"old_password": randomFakePassword(),
		"new_password": randomFakePassword(),
	})
	require.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid old password", body["error"])
}

func TestHTTP_ChangePassword_AuthFailures(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	tests := []struct {
		name        string
		header      string
		expectedErr string
	}{
		{"Missing header", "", "missing or invalid authorization header"},
		{"Bearer without token", "Bearer ", "missing or invalid authorization header"},
		{"Wrong scheme", "Basic abc", "missing or invalid authorization header"},
		{"Garbage token", "Bearer not-a-jwt", "invalid token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := st.DoJSONWithHeader(ctx, http.MethodPost, "/change-password", tt.header, map[string]any{
				"old_password": "x",
				"new_password": "y",
			})
			require.Equal(t, http.StatusUnauthorized, status)
			assert.Equal(t, tt.expectedErr, body["error"])
		})
	}
}

func TestHTTP_ChangePassword_BadSignature(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	regStatus, _ := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, regStatus)

	_, loginBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": password,
		"app_id":   appID,
	})
	token := loginBody["token"].(string)

	tampered := token + "x"
	status, body := st.DoJSONWithToken(ctx, http.MethodPost, "/change-password", tampered, map[string]any{
		"old_password": password,
		"new_password": randomFakePassword(),
	})
	require.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid token", body["error"])
}

func TestHTTP_ChangePassword_ValidationFailures(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	regStatus, _ := st.DoJSON(ctx, http.MethodPost, "/register", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusCreated, regStatus)

	_, loginBody := st.DoJSON(ctx, http.MethodPost, "/login", map[string]any{
		"email":    email,
		"password": password,
		"app_id":   appID,
	})
	token := loginBody["token"].(string)

	tests := []struct {
		name        string
		body        map[string]any
		expectedErr string
	}{
		{"Empty old", map[string]any{"old_password": "", "new_password": randomFakePassword()}, "old_password is required"},
		{"Empty new", map[string]any{"old_password": password, "new_password": ""}, "new_password is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := st.DoJSONWithToken(ctx, http.MethodPost, "/change-password", token, tt.body)
			require.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tt.expectedErr, body["error"])
		})
	}
}

func TestHTTP_IsAdmin_FailCases(t *testing.T) {
	ctx, st := suite.NewHTTP(t)

	tests := []struct {
		name        string
		query       url.Values
		expectedErr string
	}{
		{
			name:        "Missing user_id",
			query:       url.Values{},
			expectedErr: "user_id is required",
		},
		{
			name:        "Zero user_id",
			query:       url.Values{"user_id": []string{"0"}},
			expectedErr: "user_id must be a positive integer",
		},
		{
			name:        "Non-numeric user_id",
			query:       url.Values{"user_id": []string{"abc"}},
			expectedErr: "user_id must be a positive integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := st.GetWithQuery(ctx, "/is-admin", tt.query)
			require.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, tt.expectedErr, body["error"])
		})
	}
}
