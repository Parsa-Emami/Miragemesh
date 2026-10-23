package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/storage"
	"github.com/Parsa-Emami/Miragemesh/internal/update"
)

type updateOptions struct {
	Enabled            bool
	HTTPStatus         bool
	StateDir           string
	PublisherKeyFile   string
	RecoveryKeyFile    string
	Platform           string
	Limits             storage.Limits
	MaxSensors         int
	MaxArtifactBytes   int64
	MaxMetadataTTL     int64
	MaxRecoveryTTL     int64
	Action             string
	MetadataFile       string
	SignatureFile      string
	SensorID           string
	Version            uint64
	ArtifactFile       string
	GrantFile          string
	GrantSignatureFile string
}

func updateFlags() *updateOptions {
	o := new(updateOptions)
	flag.BoolVar(&o.Enabled, "verify-update", false, "run one local signed update verification action and exit")
	flag.BoolVar(&o.HTTPStatus, "update-status", false, "enable read-only local signed update status")
	flag.StringVar(&o.StateDir, "update-state-dir", "", "C05 update authority directory")
	flag.StringVar(&o.PublisherKeyFile, "update-publisher-key-file", "", "raw 32-byte Ed25519 publisher public key file")
	flag.StringVar(&o.RecoveryKeyFile, "update-recovery-key-file", "", "separate raw 32-byte Ed25519 recovery public key file")
	flag.StringVar(&o.Platform, "update-platform", "", "explicit sensor platform, such as linux/amd64")
	flag.IntVar(&o.Limits.MaxOperations, "update-max-operations", 0, "explicit C05 operation limit")
	flag.Int64Var(&o.Limits.MaxBytes, "update-max-bytes", 0, "explicit C05 byte limit")
	flag.Int64Var(&o.Limits.MaxManifestBytes, "update-max-manifest-bytes", 0, "explicit C05 manifest limit")
	flag.IntVar(&o.MaxSensors, "update-max-sensors", 0, "explicit managed update sensor limit")
	flag.Int64Var(&o.MaxArtifactBytes, "update-max-artifact-bytes", 0, "explicit local artifact length limit, at most 64 MiB")
	flag.Int64Var(&o.MaxMetadataTTL, "update-max-metadata-ttl-seconds", 0, "maximum signed metadata validity period")
	flag.Int64Var(&o.MaxRecoveryTTL, "update-max-recovery-ttl-seconds", 0, "maximum signed recovery validity period")
	flag.StringVar(&o.Action, "update-action", "", "status, accept-metadata or verify")
	flag.StringVar(&o.MetadataFile, "update-metadata-file", "", "exact canonical metadata JSON file")
	flag.StringVar(&o.SignatureFile, "update-signature-file", "", "raw 64-byte detached Ed25519 metadata signature")
	flag.StringVar(&o.SensorID, "update-sensor", "", "sensor identity whose artifact is verified")
	flag.Uint64Var(&o.Version, "update-version", 0, "positive ordered release number")
	flag.StringVar(&o.ArtifactFile, "update-artifact-file", "", "local artifact to hash; never executed")
	flag.StringVar(&o.GrantFile, "update-grant-file", "", "exact canonical single-use signed rollback grant")
	flag.StringVar(&o.GrantSignatureFile, "update-grant-signature-file", "", "raw detached recovery-key signature")
	return o
}

func updateConfigured() bool {
	configured := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "verify-update" || f.Name == "update-status" || strings.HasPrefix(f.Name, "update-") {
			configured = true
		}
	})
	return configured
}

func validUpdateFlags(action string, httpStatus bool) bool {
	common := map[string]bool{"update-state-dir": true, "update-publisher-key-file": true, "update-recovery-key-file": true, "update-platform": true, "update-max-operations": true, "update-max-bytes": true, "update-max-manifest-bytes": true, "update-max-sensors": true, "update-max-artifact-bytes": true, "update-max-metadata-ttl-seconds": true, "update-max-recovery-ttl-seconds": true}
	if httpStatus {
		common["update-status"] = true
	} else {
		common["verify-update"] = true
		common["update-action"] = true
		switch action {
		case "status":
		case "accept-metadata":
			common["update-metadata-file"] = true
			common["update-signature-file"] = true
		case "verify":
			for _, name := range []string{"update-sensor", "update-version", "update-artifact-file", "update-grant-file", "update-grant-signature-file"} {
				common[name] = true
			}
		default:
			return false
		}
	}
	valid := flag.NArg() == 0
	flag.Visit(func(f *flag.Flag) {
		if (f.Name == "verify-update" || strings.HasPrefix(f.Name, "update-")) && !common[f.Name] || !httpStatus && !common[f.Name] {
			valid = false
		}
	})
	return valid
}

func openUpdateVerifier(ctx context.Context, o updateOptions, shared *storage.Store, create bool) (*update.Verifier, *storage.Store, func(), error) {
	pub, err := readCertificateFile(o.PublisherKeyFile, false)
	if err != nil {
		return nil, nil, nil, err
	}
	recovery, err := readCertificateFile(o.RecoveryKeyFile, false)
	if err != nil {
		return nil, nil, nil, err
	}
	ttl, err := rotationDuration(o.MaxMetadataTTL)
	if err != nil {
		return nil, nil, nil, update.ErrInvalidInput
	}
	recoveryTTL, err := rotationDuration(o.MaxRecoveryTTL)
	if err != nil {
		return nil, nil, nil, update.ErrInvalidInput
	}
	if o.StateDir == "" || o.Limits.MaxOperations <= 0 || o.Limits.MaxBytes <= 0 || o.Limits.MaxManifestBytes <= 0 || len(pub) != ed25519.PublicKeySize || len(recovery) != ed25519.PublicKeySize {
		return nil, nil, nil, update.ErrInvalidInput
	}
	store := shared
	if store == nil {
		if !create {
			if err := requireExistingC05Store(o.StateDir); err != nil {
				return nil, nil, nil, storage.ErrRecovery
			}
		}
		store, err = storage.Open(o.StateDir, o.Limits)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	closeStore := func() {
		if shared == nil {
			store.Close()
		}
	}
	v, err := update.New(ctx, store, update.Options{PublisherKey: pub, RecoveryKey: recovery, Platform: o.Platform, MaxSensors: o.MaxSensors, MaxArtifactBytes: o.MaxArtifactBytes, MaxMetadataTTL: ttl, MaxRecoveryTTL: recoveryTTL, Clock: time.Now})
	if err != nil {
		closeStore()
		return nil, nil, nil, err
	}
	return v, store, closeStore, nil
}

func updateErrorKind(err error) string {
	switch {
	case errors.Is(err, update.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, update.ErrSignature):
		return "untrusted_signature"
	case errors.Is(err, update.ErrExpired):
		return "expired_authority"
	case errors.Is(err, update.ErrStale):
		return "stale_authority"
	case errors.Is(err, update.ErrConflict):
		return "authority_conflict"
	case errors.Is(err, update.ErrRevoked):
		return "revoked_version"
	case errors.Is(err, update.ErrRollback):
		return "rollback_denied"
	case errors.Is(err, update.ErrRecovery):
		return "invalid_recovery"
	case errors.Is(err, update.ErrArtifact):
		return "artifact_mismatch"
	case errors.Is(err, update.ErrEvidence):
		return "missing_evidence"
	default:
		return certificateErrorKind(err)
	}
}

func openUpdateArtifact(path string, maxBytes int64) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, update.ErrInvalidInput
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil || parent != filepath.Dir(absolute) {
		return nil, update.ErrInvalidInput
	}
	f, err := os.OpenFile(absolute, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, storage.ErrIO
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, storage.ErrIO
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || stat.Nlink != 1 || info.Size() < 1 || info.Size() > maxBytes {
		f.Close()
		return nil, update.ErrInvalidInput
	}
	return f, nil
}

func runUpdateAction(o updateOptions) int {
	type outcome struct {
		Scope     string                 `json:"scope"`
		Status    string                 `json:"status"`
		Metadata  *update.MetadataResult `json:"metadata,omitempty"`
		Result    *update.Result         `json:"result,omitempty"`
		Snapshot  *update.Snapshot       `json:"snapshot,omitempty"`
		ErrorKind string                 `json:"error_kind,omitempty"`
	}
	value := outcome{Scope: "sensor-update-verification", Status: "failed"}
	finish := func(err error) int {
		if err != nil {
			value.Status = "failed"
			value.ErrorKind = updateErrorKind(err)
		}
		if json.NewEncoder(os.Stdout).Encode(value) != nil {
			return 1
		}
		if err == nil {
			return 0
		}
		if updateErrorKind(err) == "invalid_input" {
			return 2
		}
		return 1
	}
	if !o.Enabled || o.HTTPStatus || !validUpdateFlags(o.Action, false) {
		return finish(update.ErrInvalidInput)
	}
	var payload, signature, grant, grantSignature []byte
	var artifact *os.File
	var err error
	switch o.Action {
	case "accept-metadata":
		payload, err = readCertificateFile(o.MetadataFile, false)
		if err != nil {
			return finish(err)
		}
		signature, err = readCertificateFile(o.SignatureFile, false)
		if err != nil {
			return finish(err)
		}
	case "verify":
		if (o.GrantFile == "") != (o.GrantSignatureFile == "") {
			return finish(update.ErrInvalidInput)
		}
		if o.GrantFile != "" {
			grant, err = readCertificateFile(o.GrantFile, false)
			if err != nil {
				return finish(err)
			}
			grantSignature, err = readCertificateFile(o.GrantSignatureFile, false)
			if err != nil {
				return finish(err)
			}
		}
		artifact, err = openUpdateArtifact(o.ArtifactFile, o.MaxArtifactBytes)
		if err != nil {
			return finish(err)
		}
		defer artifact.Close()
	}
	ctx := context.Background()
	v, _, closeStore, err := openUpdateVerifier(ctx, o, nil, o.Action == "accept-metadata")
	if err != nil {
		return finish(err)
	}
	defer closeStore()
	switch o.Action {
	case "status":
		snapshot, err := v.Snapshot(ctx)
		if err != nil {
			return finish(err)
		}
		value.Snapshot = &snapshot
		value.Status = "snapshot"
	case "accept-metadata":
		r, err := v.Accept(ctx, payload, signature)
		if err != nil {
			return finish(err)
		}
		value.Metadata = &r
		value.Status = "metadata_accepted"
	case "verify":
		r, err := v.Verify(ctx, update.Request{SensorID: o.SensorID, Version: o.Version, Artifact: artifact, RecoveryPayload: grant, RecoverySignature: grantSignature})
		if err != nil {
			return finish(err)
		}
		value.Result = &r
		value.Status = "artifact_verified"
	}
	return finish(nil)
}

type updateStatusReader interface {
	Snapshot(context.Context) (update.Snapshot, error)
}

func sameUpdateStore(o updateOptions, directory string, limits storage.Limits) bool {
	first, err := filepath.Abs(o.StateDir)
	if err != nil {
		return false
	}
	second, err := filepath.Abs(directory)
	return err == nil && first == second && o.Limits == limits
}
