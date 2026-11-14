package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env         string
	Addr        string
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
	AccessTTL   time.Duration
	RefreshTTL  time.Duration
	BcryptCost  int
}

func Load() (Config, error) {
	cfg := Config{
		Env:         getenv("ENV", "development"),
		Addr:        getenv("ADDR", ":8000"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    os.Getenv("REDIS_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		AccessTTL:   15 * time.Minute,
		RefreshTTL:  7 * 24 * time.Hour,
		BcryptCost:  12,
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.JWTSecret == "" {
		return Config{}, errors.New("JWT_SECRET is required")
	}

	if v := os.Getenv("ACCESS_TTL_SECONDS"); v != "" {
		sec, err := strconv.Atoi(v)
		if err != nil || sec <= 0 {
			return Config{}, errors.New("ACCESS_TTL_SECONDS must be a positive integer")
		}
		cfg.AccessTTL = time.Duration(sec) * time.Second
	}
	if v := os.Getenv("REFRESH_TTL_SECONDS"); v != "" {
		sec, err := strconv.Atoi(v)
		if err != nil || sec <= 0 {
			return Config{}, errors.New("REFRESH_TTL_SECONDS must be a positive integer")
		}
		cfg.RefreshTTL = time.Duration(sec) * time.Second
	}
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		cost, err := strconv.Atoi(v)
		if err != nil || cost < 12 {
			return Config{}, errors.New("BCRYPT_COST must be an integer >= 12")
		}
		cfg.BcryptCost = cost
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
