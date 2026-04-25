package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/AYaSmyslov/sso/internal/domain/models"
	"github.com/AYaSmyslov/sso/internal/lib/jwt"
	"github.com/AYaSmyslov/sso/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
	UpdatePassHash(ctx context.Context, userID int64, passHash []byte) error
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	UserByID(ctx context.Context, userID int64) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user exists")
	ErrUserNotFound       = errors.New("user not found")
)

// New returns a new instance of the Auth service
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		log:          log,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

// Login checks if user with given credentials exitsts int the system
//
// If user exists, but password is incorrect, returns error
// If user doesnt exists, returns error
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", err.Error())
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", err.Error())

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("nvalid credentials", err.Error())

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", err.Error())
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// RegisterNewUser registers new user in the system and returns user ID
// If user with given username already exists, returns error
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	const op = "Auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", err.Error())

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("user exists", err.Error())
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", err.Error())

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil

}

// ChangePassword verifies the user's old password and replaces it with a new one.
func (a *Auth) ChangePassword(
	ctx context.Context,
	userID int64,
	oldPassword string,
	newPassword string,
) error {
	const op = "Auth.ChangePassword"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("changing password")

	user, err := a.userProvider.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(oldPassword)); err != nil {
		log.Info("invalid old password")
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.userSaver.UpdatePassHash(ctx, userID, newHash); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// AppSecret returns the signing secret for the given app. Used by transport
// middleware for verifying JWT signatures.
func (a *Auth) AppSecret(ctx context.Context, appID int) ([]byte, error) {
	const op = "Auth.AppSecret"

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return []byte(app.Secret), nil
}

// IsAdmin checks if user is admin
func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("user not found", err.Error())
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
