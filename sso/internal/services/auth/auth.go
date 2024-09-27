package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/storage"
	"time"

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
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

// New returns a new instance of the Auth service
func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
		log:          log,
	}
}

// Login authenticates a user and returns a token for the given app ID.
//
// The method returns ErrUserNotFound if the user is not found, ErrInvalidPassword
// if the password is invalid, or ErrInternal if an internal error occurs.
func (a *Auth) Login(ctx context.Context, email, password string, appID int) (token string, err error) {
	const op = "auth.Login"

	log := a.log.With(slog.String("op", op), slog.String("username", email))

	log.Info("attempting to login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", slog.String("error", err.Error()))
		}

		return "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Warn("invalid credentials", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", slog.String("error", err.Error()))
		}

		return "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
	}

	log.Info("user logged in successfully")

	token, err = jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to create token", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// RegisterNewUser creates a new user in the database with the given email and password.
//
// The method returns ErrUserAlreadyExists if the user already exists, or ErrInternal
// if an internal error occurs.
func (a *Auth) RegisterNewUser(ctx context.Context, email, password string) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(slog.String("op", op), slog.String("email", email))

	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", slog.String("error", err.Error()))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("failed to save user", slog.String("error", err.Error()))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")

	return id, nil
}

// IsAdmin checks whether the given user is an admin or not.
//
// The method returns true if the user is an admin, false otherwise, and an error
// if an internal error occurs.
func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(slog.String("op", op), slog.Int64("user_id", userID))

	log.Info("checking if is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		log.Error("failed to check if is admin", slog.String("error", err.Error()))

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
