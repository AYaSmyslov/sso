package suite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/AYaSmyslov/sso/internal/config"
)

type HTTPSuite struct {
	*testing.T
	Cfg     *config.Config
	BaseURL string
	Client  *http.Client
}

const httpHost = "localhost"

func NewHTTP(t *testing.T) (context.Context, *HTTPSuite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadByPath("../config/local.yaml")

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)
	t.Cleanup(cancelCtx)

	return ctx, &HTTPSuite{
		T:       t,
		Cfg:     cfg,
		BaseURL: "http://" + net.JoinHostPort(httpHost, strconv.Itoa(cfg.GRPC.Port)),
		Client:  &http.Client{Timeout: cfg.GRPC.Timeout},
	}
}

func (s *HTTPSuite) DoJSON(ctx context.Context, method, path string, body any) (int, map[string]any) {
	s.T.Helper()
	return s.do(ctx, method, path, "", body)
}

func (s *HTTPSuite) DoJSONWithToken(ctx context.Context, method, path, token string, body any) (int, map[string]any) {
	s.T.Helper()
	return s.do(ctx, method, path, "Bearer "+token, body)
}

func (s *HTTPSuite) DoJSONWithHeader(ctx context.Context, method, path, authHeader string, body any) (int, map[string]any) {
	s.T.Helper()
	return s.do(ctx, method, path, authHeader, body)
}

func (s *HTTPSuite) do(ctx context.Context, method, path, authHeader string, body any) (int, map[string]any) {
	s.T.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.T.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.BaseURL+path, reader)
	if err != nil {
		s.T.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		s.T.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.T.Fatalf("read body: %v", err)
	}

	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			s.T.Fatalf("unmarshal body: %v (raw=%s)", err, string(raw))
		}
	}

	return resp.StatusCode, out
}

func (s *HTTPSuite) GetWithQuery(ctx context.Context, path string, query url.Values) (int, map[string]any) {
	s.T.Helper()

	full := path
	if len(query) > 0 {
		full = fmt.Sprintf("%s?%s", path, query.Encode())
	}
	return s.DoJSON(ctx, http.MethodGet, full, nil)
}
