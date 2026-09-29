package web

import (
	"testing"
	"time"
)

func envFrom(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestReadEnvironment_ModeDariAgent(t *testing.T) {
	cases := []struct {
		name       string
		values     map[string]string
		mode       Mode
		license    string
		oidc       string
		identities string
	}{
		{
			name:       "GONSU_AGENT_URL",
			values:     map[string]string{"GONSU_AGENT_URL": "http://agent:8099/"},
			mode:       ModeSelfHost,
			license:    "http://agent:8099/v1/license",
			oidc:       "http://agent:8099/v1/oidc",
			identities: "http://agent:8099/v1/identities",
		},
		{
			// Paket self-host lama hanya mengisi alamat lengkap.
			name: "paket self-host lama",
			values: map[string]string{
				"GONSU_LICENSE_URL": "http://agent:8099/v1/license",
				"GONSU_OIDC_URL":    "http://agent:8099/v1/oidc",
			},
			mode:       ModeSelfHost,
			license:    "http://agent:8099/v1/license",
			oidc:       "http://agent:8099/v1/oidc",
			identities: "http://agent:8099/v1/identities",
		},
		{
			name: "cloud",
			values: map[string]string{
				"GONSU_BASE_URL": "https://api.gonsu.example/", "GONSU_IDENTITY_TOKEN": "gid_1",
			},
			mode:       ModeCloud,
			identities: "https://api.gonsu.example/license/v1/identities",
		},
		{
			// Tanpa token, cloud tidak diberi jalan pemberian akses — bukan
			// memanggil GONSU dengan bearer kosong.
			name:   "cloud tanpa token identitas",
			values: map[string]string{"GONSU_BASE_URL": "https://api.gonsu.example"},
			mode:   ModeCloud,
		},
	}
	for _, tc := range cases {
		env, err := readEnvironment(envFrom(tc.values))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if env.mode != tc.mode || env.agentLicenseURL != tc.license || env.agentOIDCURL != tc.oidc ||
			env.identitiesURL() != tc.identities {
			t.Errorf("%s: mode=%s license=%q oidc=%q identities=%q", tc.name,
				env.mode, env.agentLicenseURL, env.agentOIDCURL, env.identitiesURL())
		}
	}
}

func TestReadEnvironment_CloudLengkap(t *testing.T) {
	env, err := readEnvironment(envFrom(map[string]string{
		"GONSU_OIDC_ISSUER": "https://accounts.gonsu.example/oidc", "GONSU_OIDC_CLIENT_ID": "app_1",
		"GONSU_OIDC_REDIRECT_URI": "https://konveksiku.apps.example/auth/gonsu/callback",
		"GONSU_BASE_URL":          "https://api.gonsu.example", "GONSU_INSTALLATION_ID": "inst_1",
		"GONSU_STATE_DIR":            "/var/lib/gonsu-license",
		"GONSU_LICENSE_PUBLIC_KEYS":  " kunci-baru , kunci-lama ,",
		"GONSU_OIDC_RECHECK_SECONDS": "60", "GONSU_OIDC_OFFLINE_GRACE_SECONDS": "3600",
		"GONSU_ORGANIZATION_ID": "org_1", "GONSU_OWNER_SUBJECT": "usr_1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !env.leaseConfigured() || !env.loginConfigured() {
		t.Errorf("lease=%v login=%v", env.leaseConfigured(), env.loginConfigured())
	}
	if len(env.publicKeys) != 2 || env.publicKeys[0] != "kunci-baru" {
		t.Errorf("kunci publik = %q", env.publicKeys)
	}
	if env.recheck != time.Minute || env.offlineGrace != time.Hour {
		t.Errorf("recheck=%s grace=%s", env.recheck, env.offlineGrace)
	}
}

func TestReadEnvironment_MenolakYangSetengah(t *testing.T) {
	for _, values := range []map[string]string{
		{"GONSU_OIDC_ISSUER": "https://accounts.gonsu.example/oidc"},
		{"GONSU_OIDC_RECHECK_SECONDS": "lima belas"},
		{"GONSU_AGENT_URL": "agent:8099"},
	} {
		if _, err := readEnvironment(envFrom(values)); err == nil {
			t.Errorf("%v diterima", values)
		}
	}
}
