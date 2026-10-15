package mintcore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// botRoleGitHub configures the fake GitHub API used by bot-role tests.
type botRoleGitHub struct {
	// apps maps an App slug to the /apps/{slug} status and body.
	apps map[string]botRoleFakeResponse
	// installs maps "owner/repo" to the installation lookup status.
	installs map[string]int
	// appsAuth, when set, collects the Authorization header of every
	// /apps/{slug} request.
	appsAuth *[]string
	// rejectAppsAuth makes /apps/{slug} answer 401 to any authenticated
	// request, as GitHub does for a rotated or revoked App key.
	rejectAppsAuth bool
}

type botRoleFakeResponse struct {
	status int
	body   string
}

func newBotRoleGitHub(t *testing.T, cfg botRoleGitHub) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if slug, ok := strings.CutPrefix(r.URL.Path, "/apps/"); ok {
			if cfg.appsAuth != nil {
				*cfg.appsAuth = append(*cfg.appsAuth, r.Header.Get("Authorization"))
			}
			if r.Header.Get("Accept") != "application/vnd.github+json" {
				t.Errorf("unexpected Accept header %q", r.Header.Get("Accept"))
			}
			if r.Header.Get("User-Agent") == "" {
				t.Errorf("missing User-Agent header")
			}
			if cfg.rejectAppsAuth && r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			resp, ok := cfg.apps[slug]
			if !ok {
				t.Errorf("unexpected app lookup: %s", slug)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(resp.status)
			w.Write([]byte(resp.body))
			return
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/repos/"); ok && strings.HasSuffix(rest, "/installation") {
			repo := strings.TrimSuffix(rest, "/installation")
			status, ok := cfg.installs[repo]
			if !ok {
				t.Errorf("unexpected installation lookup: %s", repo)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			owner, _, _ := strings.Cut(repo, "/")
			json.NewEncoder(w).Encode(installationResponse{
				ID: 42, Account: struct {
					Login string `json:"login"`
				}{Login: owner},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newBotRoleEnv builds an OIDC test environment with PEMs for every role in
// roles and the fake GitHub API attached.
func newBotRoleEnv(t *testing.T, cfg botRoleGitHub, roles ...string) *testOIDCEnv {
	t.Helper()
	pemData, err := generateTestRSAKey()
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	pems := make(map[string][]byte, len(roles))
	for _, role := range roles {
		pems[PemSecretRole(role)] = pemData
	}
	env := newTestOIDCEnv(t, &fakePEMAccessor{pems: pems})
	env.handler.githubBaseURL = newBotRoleGitHub(t, cfg).URL
	return env
}

func postBotRole(t *testing.T, env *testOIDCEnv, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, botRolePath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	env.handler.ServeHTTP(rec, req)
	return rec
}

func decodeBotRole(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response %q: %v", rec.Body.String(), err)
	}
	return resp
}

func assertBotRoleOK(t *testing.T, rec *httptest.ResponseRecorder, outcome, role string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	resp := decodeBotRole(t, rec)
	if resp["outcome"] != outcome || resp["role"] != role {
		t.Fatalf("got outcome=%q role=%q, want outcome=%q role=%q", resp["outcome"], resp["role"], outcome, role)
	}
	if _, ok := resp["role"]; !ok && role != "" {
		t.Fatalf("role missing from response")
	}
	if _, ok := resp["role"]; ok && role == "" {
		t.Fatalf("no_match response must not carry a role: %s", rec.Body.String())
	}
}

func assertBotRoleError(t *testing.T, rec *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("expected %d, got %d: %s", status, rec.Code, rec.Body.String())
	}
	if got := decodeBotRole(t, rec)["error"]; got != msg {
		t.Fatalf("error = %q, want %q", got, msg)
	}
}

const botRoleBody = `{"actor_login":"fullsend-review[bot]","repo":"test-org/test-repo"}`

func TestBotRole_Recognized(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:     map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300,"slug":"fullsend-review"}`}},
		installs: map[string]int{"test-org/test-repo": http.StatusOK},
	}, "review")
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeRecognized, "review")
}

func TestBotRole_RecognizedCaseInsensitive(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:     map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
		installs: map[string]int{"test-org/test-repo": http.StatusOK},
	}, "review")
	body := `{"actor_login":"Fullsend-Review[BOT]","repo":"Test-Org/Test-Repo"}`
	rec := postBotRole(t, env, env.signToken(t, nil), body)
	assertBotRoleOK(t, rec, botRoleOutcomeRecognized, "review")
}

func TestBotRole_NoMatchUnknownAppID(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps: map[string]botRoleFakeResponse{"dependabot": {http.StatusOK, `{"id":29110}`}},
	})
	body := `{"actor_login":"dependabot[bot]","repo":"test-org/test-repo"}`
	rec := postBotRole(t, env, env.signToken(t, nil), body)
	assertBotRoleOK(t, rec, botRoleOutcomeNoMatch, "")
}

func TestBotRole_AppsLookupAuthenticatedAsMintApp(t *testing.T) {
	var auth []string
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:     map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
		installs: map[string]int{"test-org/test-repo": http.StatusOK},
		appsAuth: &auth,
	}, "review", "coder")
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeRecognized, "review")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || len(auth[0]) <= len("Bearer ") {
		t.Fatalf("/apps lookup Authorization = %q, want one App JWT bearer", auth)
	}
}

func TestBotRole_AppsLookupAnonymousWithoutPEM(t *testing.T) {
	var auth []string
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:     map[string]botRoleFakeResponse{"dependabot": {http.StatusOK, `{"id":29110}`}},
		appsAuth: &auth,
	}) // no PEMs registered: the lookup falls back to an anonymous request
	body := `{"actor_login":"dependabot[bot]","repo":"test-org/test-repo"}`
	rec := postBotRole(t, env, env.signToken(t, nil), body)
	assertBotRoleOK(t, rec, botRoleOutcomeNoMatch, "")
	if len(auth) != 1 || auth[0] != "" {
		t.Fatalf("/apps lookup Authorization = %q, want one anonymous request", auth)
	}
}

func TestBotRole_AppsLookupFallsBackWhenCredentialRejected(t *testing.T) {
	var auth []string
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:           map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
		installs:       map[string]int{"test-org/test-repo": http.StatusOK},
		appsAuth:       &auth,
		rejectAppsAuth: true,
	}, "review", "coder") // coder sorts first, so its JWT authenticates /apps and is rejected
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeRecognized, "review")
	if len(auth) != 2 || auth[0] == "" || auth[1] != "" {
		t.Fatalf("/apps lookup Authorization = %q, want an App JWT then an anonymous retry", auth)
	}
}

func TestBotRole_RecognizedNonCanonicalRegisteredAppID(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:     map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
		installs: map[string]int{"test-org/test-repo": http.StatusOK},
	}, "review")
	env.handler.roleAppIDs["review"] = "00300"
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeRecognized, "review")
}

func TestBotRole_NoMatchAppNotFound(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps: map[string]botRoleFakeResponse{"fullsend-review": {http.StatusNotFound, `{"message":"Not Found"}`}},
	})
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeNoMatch, "")
}

func TestBotRole_NoMatchNotInstalledOnRepo(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps:     map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
		installs: map[string]int{"test-org/test-repo": http.StatusNotFound},
	}, "review")
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeNoMatch, "")
}

func TestBotRole_LookupFailures(t *testing.T) {
	tests := []struct {
		name    string
		app     botRoleFakeResponse
		install int
	}{
		{name: "apps 500", app: botRoleFakeResponse{http.StatusInternalServerError, ""}},
		{name: "apps 403", app: botRoleFakeResponse{http.StatusForbidden, `{"message":"rate limited"}`}},
		{name: "apps bad json", app: botRoleFakeResponse{http.StatusOK, `not json`}},
		{name: "apps missing id", app: botRoleFakeResponse{http.StatusOK, `{"slug":"fullsend-review"}`}},
		{name: "apps non-numeric id", app: botRoleFakeResponse{http.StatusOK, `{"id":"300"}`}},
		{name: "installation 500", app: botRoleFakeResponse{http.StatusOK, `{"id":300}`}, install: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := botRoleGitHub{apps: map[string]botRoleFakeResponse{"fullsend-review": tt.app}}
			if tt.install != 0 {
				cfg.installs = map[string]int{"test-org/test-repo": tt.install}
			}
			env := newBotRoleEnv(t, cfg, "review")
			rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
			assertBotRoleError(t, rec, http.StatusBadGateway, "bot-role lookup failed")
		})
	}
}

func TestBotRole_LookupFailureTransport(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{}, "review")
	// The server drops the connection without answering.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		conn.Close()
	}))
	t.Cleanup(srv.Close)
	env.handler.githubBaseURL = srv.URL
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleError(t, rec, http.StatusBadGateway, "bot-role lookup failed")
}

func TestBotRole_LookupFailurePEM(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps: map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
	}) // no PEMs registered
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleError(t, rec, http.StatusBadGateway, "bot-role lookup failed")
}

func TestBotRole_LookupFailureBadPEM(t *testing.T) {
	env := newTestOIDCEnv(t, &fakePEMAccessor{pems: map[string][]byte{"review": []byte("not a pem")}})
	env.handler.githubBaseURL = newBotRoleGitHub(t, botRoleGitHub{
		apps: map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
	}).URL
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleError(t, rec, http.StatusBadGateway, "bot-role lookup failed")
}

func TestBotRole_BadRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
		msg  string
	}{
		{"bad json", `{not json`, "invalid JSON body"},
		{"empty body", ``, "invalid JSON body"},
		{"missing login", `{"repo":"test-org/test-repo"}`, "invalid actor_login"},
		{"human login", `{"actor_login":"octocat","repo":"test-org/test-repo"}`, "invalid actor_login"},
		{"bare suffix", `{"actor_login":"[bot]","repo":"test-org/test-repo"}`, "invalid actor_login"},
		{"leading hyphen", `{"actor_login":"-app[bot]","repo":"test-org/test-repo"}`, "invalid actor_login"},
		{"path in slug", `{"actor_login":"a/b[bot]","repo":"test-org/test-repo"}`, "invalid actor_login"},
		{"missing repo", `{"actor_login":"fullsend-review[bot]"}`, "invalid repo"},
		{"repo without owner", `{"actor_login":"fullsend-review[bot]","repo":"test-repo"}`, "invalid repo"},
		{"repo bad owner", `{"actor_login":"fullsend-review[bot]","repo":"bad--org/test-repo"}`, "invalid repo"},
		{"repo extra segment", `{"actor_login":"fullsend-review[bot]","repo":"test-org/test-repo/x"}`, "invalid repo"},
		{"repo dotdot", `{"actor_login":"fullsend-review[bot]","repo":"test-org/.."}`, "invalid repo"},
	}
	env := newBotRoleEnv(t, botRoleGitHub{}, "review")
	token := env.signToken(t, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postBotRole(t, env, token, tt.body)
			assertBotRoleError(t, rec, http.StatusBadRequest, tt.msg)
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestBotRole_UnreadableBody(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{}, "review")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, botRolePath, errReader{})
	req.Header.Set("Authorization", "Bearer "+env.signToken(t, nil))
	env.handler.ServeHTTP(rec, req)
	assertBotRoleError(t, rec, http.StatusBadRequest, "invalid JSON body")
}

func TestBotRole_AuthenticationFailed(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{}, "review")
	t.Run("missing token", func(t *testing.T) {
		assertBotRoleError(t, postBotRole(t, env, "", botRoleBody), http.StatusUnauthorized, "authentication failed")
	})
	t.Run("invalid token", func(t *testing.T) {
		assertBotRoleError(t, postBotRole(t, env, "not-a-jwt", botRoleBody), http.StatusUnauthorized, "authentication failed")
	})
	t.Run("not enrolled", func(t *testing.T) {
		token := env.signToken(t, map[string]interface{}{
			"repository":       "evil-org/test-repo",
			"repository_owner": "evil-org",
		})
		body := `{"actor_login":"fullsend-review[bot]","repo":"evil-org/test-repo"}`
		assertBotRoleError(t, postBotRole(t, env, token, body), http.StatusUnauthorized, "authentication failed")
	})
}

func TestBotRole_RepoMismatch(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{}, "review")
	body := `{"actor_login":"fullsend-review[bot]","repo":"test-org/other-repo"}`
	rec := postBotRole(t, env, env.signToken(t, nil), body)
	assertBotRoleError(t, rec, http.StatusForbidden, "repo must be the requesting repository")
}

func TestBotRole_RequestRoleFieldIgnored(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{
		apps: map[string]botRoleFakeResponse{"dependabot": {http.StatusOK, `{"id":29110}`}},
	}, "coder")
	body := `{"actor_login":"dependabot[bot]","repo":"test-org/test-repo","role":"coder","outcome":"recognized"}`
	rec := postBotRole(t, env, env.signToken(t, nil), body)
	assertBotRoleOK(t, rec, botRoleOutcomeNoMatch, "")
}

func TestBotRole_RoleNotAllowedIgnored(t *testing.T) {
	t.Setenv("ALLOWED_ROLES", "coder")
	env := newBotRoleEnv(t, botRoleGitHub{
		apps: map[string]botRoleFakeResponse{"fullsend-review": {http.StatusOK, `{"id":300}`}},
	}, "coder", "review")
	rec := postBotRole(t, env, env.signToken(t, nil), botRoleBody)
	assertBotRoleOK(t, rec, botRoleOutcomeNoMatch, "")
}

func TestBotRole_SharedAppIDPicksFirstRole(t *testing.T) {
	t.Run("distinct roles sharing an app", func(t *testing.T) {
		t.Setenv("ROLE_APP_IDS", `{"triage":"300","review":"300","coder":"200"}`)
		env := newBotRoleEnv(t, botRoleGitHub{
			apps:     map[string]botRoleFakeResponse{"shared-app": {http.StatusOK, `{"id":300}`}},
			installs: map[string]int{"test-org/test-repo": http.StatusOK},
		}, "review", "triage", "coder")
		body := `{"actor_login":"shared-app[bot]","repo":"test-org/test-repo"}`
		assertBotRoleOK(t, postBotRole(t, env, env.signToken(t, nil), body), botRoleOutcomeRecognized, "review")
	})
	t.Run("fix reuses the coder app", func(t *testing.T) {
		t.Setenv("ROLE_APP_IDS", `{"coder":"200","fix":"200"}`)
		env := newBotRoleEnv(t, botRoleGitHub{
			apps:     map[string]botRoleFakeResponse{"fullsend-coder": {http.StatusOK, `{"id":200}`}},
			installs: map[string]int{"test-org/test-repo": http.StatusOK},
		}, "coder", "fix")
		body := `{"actor_login":"fullsend-coder[bot]","repo":"test-org/test-repo"}`
		assertBotRoleOK(t, postBotRole(t, env, env.signToken(t, nil), body), botRoleOutcomeRecognized, "coder")
	})
}

func TestBotRole_MethodNotAllowed(t *testing.T) {
	env := newBotRoleEnv(t, botRoleGitHub{}, "review")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, botRolePath, nil))
	assertBotRoleError(t, rec, http.StatusMethodNotAllowed, "method not allowed")
}

func TestBotRole_LookupGitHubAppIDBadURL(t *testing.T) {
	h := mustNewHandler(t, &fakePEMAccessor{}, &fakeOIDCVerifier{})
	h.githubBaseURL = "://bad"
	if _, err := h.lookupGitHubAppID(context.Background(), "app", ""); err == nil {
		t.Fatal("expected error for invalid base URL")
	}
}
