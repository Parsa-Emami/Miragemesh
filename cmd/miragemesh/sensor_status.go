package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/config"
	"github.com/Parsa-Emami/Miragemesh/internal/sensor"
	"github.com/Parsa-Emami/Miragemesh/internal/storage"
)

var errSensorStatusConfiguration = errors.New("invalid sensor status configuration")

type sensorStatusOptions struct {
	directory     string
	limits        storage.Limits
	publicKeyPath string
	maxSensors    int
	bounds        config.Bounds
}

func openSensorStatus(options sensorStatusOptions) (*localSensorStatus, error) {
	if options.directory == "" || options.publicKeyPath == "" || options.limits.MaxOperations <= 0 || options.limits.MaxBytes <= 0 || options.limits.MaxManifestBytes <= 0 || options.maxSensors <= 0 {
		return nil, errSensorStatusConfiguration
	}
	publicKey, err := os.ReadFile(options.publicKeyPath)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errSensorStatusConfiguration
	}
	verifier := config.Verifier{
		PublicKey:  ed25519.PublicKey(publicKey),
		Clock:      time.Now,
		MaxSensors: options.maxSensors,
		Bounds:     options.bounds,
	}
	if _, err := config.New(verifier); err != nil {
		return nil, errSensorStatusConfiguration
	}
	store, err := storage.Open(options.directory, options.limits)
	if err != nil {
		return nil, errSensorStatusConfiguration
	}
	applier, err := sensor.NewApplier(context.Background(), store, verifier)
	if err != nil {
		store.Close()
		return nil, errSensorStatusConfiguration
	}
	return &localSensorStatus{store: store, applier: applier}, nil
}
