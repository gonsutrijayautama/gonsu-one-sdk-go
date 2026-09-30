package web

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Mode adalah cara pemasangan ini dijalankan.
type Mode string

// Dua mode yang dikenal kit.
const (
	// ModeCloud: GONSU memasang dan menjalankan aplikasinya; nilainya datang
	// dari Secret aplikasi.
	ModeCloud Mode = "cloud"
	// ModeSelfHost: aplikasi berjalan di mesin pelanggan bersama agent GONSU.
	ModeSelfHost Mode = "self_host"
)

// Jalur agent self-host, di bawah GONSU_AGENT_URL.
const (
	agentLicensePath    = "/v1/license"
	agentOIDCPath       = "/v1/oidc"
	agentIdentitiesPath = "/v1/identities"
)

// cloudIdentitiesPath adalah jalur pemberian identitas di API GONSU.
const cloudIdentitiesPath = "/license/v1/identities"

// environment adalah nilai GONSU yang dibaca dari environment.
//
// Nama variabelnya kontrak GONSU, bukan pilihan produk. Nilai yang TIDAK ADA
// dibedakan dari nilai kosong hanya di tempat GONSU memang membedakannya.
type environment struct {
	mode Mode

	// Self-host: alamat lengkap tiap jalur agent.
	agentLicenseURL    string
	agentOIDCURL       string
	agentIdentitiesURL string

	// Login cloud.
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string

	// Kebijakan sesi; nol berarti bawaan paket auth.
	recheck      time.Duration
	offlineGrace time.Duration

	// Lisensi cloud.
	baseURL         string
	installationID  string
	activationToken string
	stateDir        string
	publicKeys      []string

	// Pemberian identitas cloud.
	identityToken string

	// Pemilik pemasangan (cloud; self-host membacanya dari agent).
	organizationID string
	ownerSubject   string

	// portalURL adalah alamat Portal GONSU (GONSU_PORTAL_URL), di kedua mode:
	// cloud dari Secret, self-host dari berkas env pemasangan.
	portalURL string
}

// readEnvironment membaca environment. Tidak menghubungi siapa pun.
func readEnvironment(getenv func(string) string) (environment, error) {
	get := func(name string) string { return strings.TrimSpace(getenv(name)) }
	var env environment
	var errs []error

	agent := strings.TrimRight(get("GONSU_AGENT_URL"), "/")
	legacyLicense, legacyOIDC := get("GONSU_LICENSE_URL"), get("GONSU_OIDC_URL")
	if agent == "" && legacyLicense != "" {
		// Paket self-host sebelum GONSU_AGENT_URL ada hanya mengisi alamat
		// lengkap jalur lisensi dan login.
		agent = strings.TrimSuffix(strings.TrimRight(legacyLicense, "/"), agentLicensePath)
	}

	if agent != "" {
		env.mode = ModeSelfHost
		if err := checkURL("GONSU_AGENT_URL", agent); err != nil {
			errs = append(errs, err)
		}
		env.agentLicenseURL = agent + agentLicensePath
		env.agentOIDCURL = agent + agentOIDCPath
		env.agentIdentitiesURL = agent + agentIdentitiesPath
		if legacyLicense != "" {
			env.agentLicenseURL = legacyLicense
		}
		if legacyOIDC != "" {
			env.agentOIDCURL = legacyOIDC
		}
	} else {
		env.mode = ModeCloud
		env.issuer = get("GONSU_OIDC_ISSUER")
		env.clientID = get("GONSU_OIDC_CLIENT_ID")
		// Tidak ada pada self-host, dan boleh tidak ada di cloud sebelum
		// login diterbitkan; auth.New yang menilai kelengkapannya.
		env.clientSecret = get("GONSU_OIDC_CLIENT_SECRET")
		env.redirectURI = get("GONSU_OIDC_REDIRECT_URI")
		if env.issuer != "" && (env.clientID == "" || env.redirectURI == "") {
			errs = append(errs, errors.New(
				"GONSU_OIDC_ISSUER terisi tetapi GONSU_OIDC_CLIENT_ID atau GONSU_OIDC_REDIRECT_URI kosong"))
		}

		env.baseURL = strings.TrimRight(get("GONSU_BASE_URL"), "/")
		env.installationID = get("GONSU_INSTALLATION_ID")
		env.activationToken = get("GONSU_ACTIVATION_TOKEN")
		env.stateDir = get("GONSU_STATE_DIR")
		env.publicKeys = splitList(get("GONSU_LICENSE_PUBLIC_KEYS"))
		env.identityToken = get("GONSU_IDENTITY_TOKEN")
		env.organizationID = get("GONSU_ORGANIZATION_ID")
		env.ownerSubject = get("GONSU_OWNER_SUBJECT")
	}

	env.portalURL = strings.TrimRight(get("GONSU_PORTAL_URL"), "/")
	if env.portalURL != "" {
		if err := checkURL("GONSU_PORTAL_URL", env.portalURL); err != nil {
			errs = append(errs, err)
		}
	}

	var err error
	if env.recheck, err = seconds(get("GONSU_OIDC_RECHECK_SECONDS")); err != nil {
		errs = append(errs, fmt.Errorf("GONSU_OIDC_RECHECK_SECONDS: %w", err))
	}
	if env.offlineGrace, err = seconds(get("GONSU_OIDC_OFFLINE_GRACE_SECONDS")); err != nil {
		errs = append(errs, fmt.Errorf("GONSU_OIDC_OFFLINE_GRACE_SECONDS: %w", err))
	}

	return env, errors.Join(errs...)
}

// loginConfigured melaporkan apakah GONSU memberi pemasangan ini login.
//
// Di self-host jawabannya baru diketahui saat agent ditanya, jadi di sini
// cukup "ada agent".
func (e environment) loginConfigured() bool {
	return e.issuer != "" || e.agentOIDCURL != ""
}

// leaseConfigured melaporkan apakah lisensi cloud dapat dibaca dari lease.
func (e environment) leaseConfigured() bool {
	return e.mode == ModeCloud && e.baseURL != "" && e.installationID != "" && e.stateDir != ""
}

// identitiesURL mengembalikan alamat pemberian identitas, atau kosong bila
// pemasangan ini tidak diberi jalan itu.
func (e environment) identitiesURL() string {
	switch {
	case e.mode == ModeSelfHost:
		return e.agentIdentitiesURL
	case e.baseURL != "" && e.identityToken != "":
		return e.baseURL + cloudIdentitiesPath
	default:
		return ""
	}
}

func checkURL(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("%s bukan alamat http(s): %q", name, raw)
	}
	return nil
}

func seconds(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("harus bilangan bulat detik, diterima %q", raw)
	}
	return time.Duration(n) * time.Second, nil
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
