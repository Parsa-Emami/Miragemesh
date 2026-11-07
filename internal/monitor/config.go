package monitor

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/pki"
)

type listenerConfig struct {
	Listen      string `json:"listen"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	CA          string `json:"ca"`
	CRL         string `json:"crl"`
}

type operator struct {
	ID      string   `json:"id"`
	Role    string   `json:"role"`
	Sensors []string `json:"sensors"`
}

type configuration struct {
	StateDir       string              `json:"state_dir"`
	WebDir         string              `json:"web_dir"`
	RetentionHours int                 `json:"retention_hours"`
	EventsPerHour  int                 `json:"max_events_per_hour"`
	EventAge       int                 `json:"max_event_age_minutes"`
	AlertThreshold int                 `json:"requests_per_hour_alert"`
	Origin         string              `json:"workspace_origin"`
	Collector      listenerConfig      `json:"collector"`
	Workspace      listenerConfig      `json:"workspace"`
	Sensors        map[string][]string `json:"sensors"`
	Operators      map[string]operator `json:"operators"`
}

func readConfig(path string, target any) error {
	raw, err := readRegularFile(path, 262144, false)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected a single JSON configuration object")
	}
	return nil
}

func readRegularFile(path string, limit int64, private bool) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("configuration and certificate paths must be clean and absolute")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || private && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("configuration input must be a regular file, with private keys restricted to their owner")
	}
	return readLimit(f, limit)
}

func privateListen(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		return "", errors.New("listener must use a private or loopback IP address and an explicit port")
	}
	return strconv.Itoa(number), nil
}

func (c configuration) validate() (map[string][]string, string, error) {
	if !cleanAbsolute(c.StateDir) || !cleanAbsolute(c.WebDir) ||
		c.RetentionHours < 2 || c.RetentionHours > 168 ||
		c.EventsPerHour < 1 || c.EventsPerHour > 60000 || c.EventsPerHour*c.RetentionHours > 1000000 ||
		c.EventAge < 1 || c.EventAge >= (c.RetentionHours-1)*60 ||
		c.AlertThreshold < 1 || c.AlertThreshold > c.EventsPerHour {
		return nil, "", errors.New("invalid monitoring storage policy")
	}
	origin, err := url.Parse(c.Origin)
	port, listenErr := privateListen(c.Workspace.Listen)
	if err != nil || listenErr != nil || origin.Scheme != "https" || origin.User != nil || origin.Hostname() == "" ||
		c.Origin != "https://"+origin.Host || (origin.Port() != port && !(origin.Port() == "" && port == "443")) {
		return nil, "", errors.New("workspace origin must be the exact HTTPS origin on the workspace listener port")
	}
	if _, err := privateListen(c.Collector.Listen); err != nil {
		return nil, "", err
	}
	if c.Collector.Listen == c.Workspace.Listen || len(c.Sensors) < 1 || len(c.Sensors) > 256 ||
		len(c.Operators) < 1 || len(c.Operators) > 256 {
		return nil, "", errors.New("configure separate listeners and up to 256 sensor and operator identities")
	}
	known := make(map[string]bool)
	for _, ids := range c.Sensors {
		if len(ids) < 1 || len(ids) > 64 {
			return nil, "", errors.New("each sensor identity must have 1 to 64 scopes")
		}
		for _, id := range ids {
			if !contracts.ValidSensorID(id) {
				return nil, "", errors.New("invalid sensor ID")
			}
			known[id] = true
		}
	}
	if len(known) > 256 {
		return nil, "", errors.New("too many configured sensors")
	}
	operatorScopes := make(map[string][]string, len(c.Operators))
	for fingerprint, op := range c.Operators {
		if !contracts.ValidIncidentActor(op.ID) || (op.Role != "viewer" && op.Role != "analyst") ||
			len(op.Sensors) < 1 || len(op.Sensors) > 64 || c.Sensors[fingerprint] != nil {
			return nil, "", errors.New("invalid operator identity, role or sensor scopes")
		}
		for _, id := range op.Sensors {
			if !known[id] {
				return nil, "", errors.New("operator scope references an unconfigured sensor")
			}
		}
		operatorScopes[fingerprint] = op.Sensors
	}
	return operatorScopes, origin.Host, nil
}

func (c listenerConfig) guard(scopes map[string][]string) (*pki.Guard, string, error) {
	ca, err := readRegularFile(c.CA, 65536, false)
	if err != nil {
		return nil, "", fmt.Errorf("read certificate authority: %w", err)
	}
	cert, err := readRegularFile(c.Certificate, 65536, false)
	if err != nil {
		return nil, "", fmt.Errorf("read server certificate: %w", err)
	}
	key, err := readRegularFile(c.Key, 65536, true)
	if err != nil {
		return nil, "", fmt.Errorf("read private key: %w", err)
	}
	crl, err := readRegularFile(c.CRL, 1<<20, false)
	if err != nil {
		return nil, "", fmt.Errorf("read revocation list: %w", err)
	}
	guard, err := pki.New(pki.Options{
		Anchors: []string{string(ca)}, ServerCertificatePEM: string(cert),
		ServerKeyPEM: string(key), RevocationListPEM: string(crl), Scopes: scopes,
		MaxAnchors: 1, MaxScopes: 256, MaxScopesPerIdentity: 64, Clock: time.Now,
	})
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(ca)
	return guard, digest(block.Bytes), nil
}

func allowed(ids []string, id string) bool {
	return slices.Contains(ids, id)
}
