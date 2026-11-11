package config

import (
	"errors"
	"os"
)

type Config struct {
	Env         string
	Addr        string
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
}

func Load() (Config, error) {
	cfg := Config{
		Env:         getenv("ENV", "development"),
		Addr:        getenv("ADDR", ":8000"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    os.Getenv("REDIS_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}

	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
