package app

import (
	"log/slog"
	"time"

	// grpcapp "github.com/AYaSmyslov/sso/internal/app/grpc"
	httpapp "github.com/AYaSmyslov/sso/internal/app/http"
	"github.com/AYaSmyslov/sso/internal/services/auth"
	"github.com/AYaSmyslov/sso/internal/storage/sqlite"
)

type App struct {
	// GRPCSrv *grpcapp.App
	HTTPSrv *httpapp.App
}

func New(
	log *slog.Logger,
	port int,
	storagePath string,
	tokenTTL time.Duration,
) *App {

	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTL)

	// grpcApp := grpcapp.New(log, authService, port)
	httpApp := httpapp.New(log, authService, port)

	return &App{
		// GRPCSrv: grpcApp,
		HTTPSrv: httpApp,
	}
}
