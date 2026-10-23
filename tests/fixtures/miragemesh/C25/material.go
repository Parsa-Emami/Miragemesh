package c25fixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Material struct {
	Publisher ed25519.PrivateKey
	Recovery  ed25519.PrivateKey
}

func Generate() Material {
	_, p, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	_, r, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Material{p, r}
}

func Artifact(version uint64) []byte {
	raw, _ := json.Marshal(map[string]any{"synthetic_sensor_release": version, "executable": false})
	return raw
}

func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func Metadata(at time.Time, revision uint64, sensor string, revoked []uint64, versions ...uint64) []byte {
	type release struct {
		Version uint64 `json:"version"`
		SHA256  string `json:"sha256"`
		Length  int64  `json:"length"`
	}
	type metadata struct {
		SchemaVersion   string    `json:"schema_version"`
		Kind            string    `json:"kind"`
		SensorID        string    `json:"sensor_id"`
		Revision        uint64    `json:"revision"`
		Platform        string    `json:"platform"`
		IssuedAt        string    `json:"issued_at"`
		ExpiresAt       string    `json:"expires_at"`
		Releases        []release `json:"releases"`
		RevokedVersions []uint64  `json:"revoked_versions"`
	}
	list := []release{}
	for _, v := range versions {
		a := Artifact(v)
		list = append(list, release{v, Digest(a), int64(len(a))})
	}
	if revoked == nil {
		revoked = []uint64{}
	}
	raw, _ := json.Marshal(metadata{"1", "sensor-update-metadata", sensor, revision, "linux/amd64", at.UTC().Format(time.RFC3339Nano), at.Add(time.Hour).UTC().Format(time.RFC3339Nano), list, revoked})
	return raw
}

func Grant(at time.Time, id, sensor string, revision, from, to uint64) []byte {
	type grant struct {
		SchemaVersion    string `json:"schema_version"`
		Kind             string `json:"kind"`
		ID               string `json:"id"`
		SensorID         string `json:"sensor_id"`
		MetadataRevision uint64 `json:"metadata_revision"`
		Platform         string `json:"platform"`
		FromVersion      uint64 `json:"from_version"`
		ToVersion        uint64 `json:"to_version"`
		SHA256           string `json:"sha256"`
		Length           int64  `json:"length"`
		IssuedAt         string `json:"issued_at"`
		ExpiresAt        string `json:"expires_at"`
		Reason           string `json:"reason"`
	}
	a := Artifact(to)
	raw, _ := json.Marshal(grant{"1", "sensor-update-recovery", id, sensor, revision, "linux/amd64", from, to, Digest(a), int64(len(a)), at.UTC().Format(time.RFC3339Nano), at.Add(10 * time.Minute).UTC().Format(time.RFC3339Nano), "Recover synthetic sensor after an incompatible release"})
	return raw
}
