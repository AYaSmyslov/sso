package httpapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	httpauth "github.com/AYaSmyslov/sso/internal/transport/http/auth"
)

type App struct {
	log        *slog.Logger
	httpServer *http.Server
	port       int
}

func New(
	log *slog.Logger,
	authService httpauth.Auth,
	port int,
) *App {

	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
	}

	httpauth.Register(httpServer, authService)

	return &App{
		log:        log,
		httpServer: httpServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "httpapp.Run"
	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("HTTP Server is running", slog.String("addr", a.httpServer.Addr))
	err := a.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		log.Info("HTTP Server stopped")
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop(ctx context.Context) error {
	const op = "httpapp.Stop"
	a.log.With(slog.String("op", op)).
		Info("Stopping HTTP Server")

	if err := a.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
