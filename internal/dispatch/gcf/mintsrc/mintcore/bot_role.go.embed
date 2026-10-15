package mintcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Wire contract of the GitHub bot-role lookup (ADR 0107). The client side
// lives in internal/botidentity (mint.go); this module cannot import it, so
// the names are duplicated here. Change both together.
const (
	botRolePath = "/v1/bot-role"

	botRoleOutcomeRecognized = "recognized"
	botRoleOutcomeNoMatch    = "no_match"

	// maxBotRoleBodyBytes bounds the request body and the GitHub /apps
	// response body read by the lookup.
	maxBotRoleBodyBytes = 64 << 10
)

// botLoginPattern matches a GitHub App bot login: the App slug followed by
// the literal "[bot]" suffix. Matching is case-insensitive.
var botLoginPattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?\[bot\]$`)

// errBotRoleNoMatch signals a completed lookup that found no registered role
// for the bot on the target repository.
var errBotRoleNoMatch = errors.New("no registered bot role")

// errAppsAuthRejected signals that GitHub rejected the App JWT used to
// authenticate the GET /apps/{slug} lookup (401 or 403).
var errAppsAuthRejected = errors.New("GitHub rejected the App credential")

// botRoleRequest is the JSON body of POST /v1/bot-role. Unknown fields
// (for example a caller-supplied "role") are ignored: the role is always
// derived from the mint's own registration, never from the request.
type botRoleRequest struct {
	ActorLogin string `json:"actor_login"`
	Repo       string `json:"repo"`
}

// botRoleResponse is the 200 body of POST /v1/bot-role.
type botRoleResponse struct {
	Outcome string `json:"outcome"`
	Role    string `json:"role,omitempty"`
}

// githubAppResponse is the subset of GET /apps/{slug} the lookup reads.
type githubAppResponse struct {
	ID *int64 `json:"id"`
}

// handleBotRole serves POST /v1/bot-role: it resolves a GitHub App bot login
// to the mint role registered for that App, scoped to the caller's own
// repository (ADR 0107). It answers with role names only, never credentials.
func (h *Handler) handleBotRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBotRoleBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var req botRoleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !botLoginPattern.MatchString(req.ActorLogin) {
		writeError(w, http.StatusBadRequest, "invalid actor_login")
		return
	}
	if !validBotRoleRepo(req.Repo) {
		writeError(w, http.StatusBadRequest, "invalid repo")
		return
	}

	claims, oidcErr := h.verifyOIDCRequest(r.Context(), r)
	if oidcErr != nil {
		log.Printf("bot-role authentication failed: %v", oidcErr)
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	// Target binding: a caller may only ask about its own repository.
	if !strings.EqualFold(req.Repo, claims.Repository) {
		log.Printf("bot-role denied: caller_repo=%s requested_repo=%s actor_login=%s",
			claims.Repository, req.Repo, req.ActorLogin)
		writeError(w, http.StatusForbidden, "repo must be the requesting repository")
		return
	}

	// Scope the installation lookup to the authoritative OIDC repository
	// claim (equal to req.Repo up to case).
	owner, name, _ := strings.Cut(claims.Repository, "/")
	role, err := h.resolveBotRole(r.Context(), req.ActorLogin, owner, name)
	switch {
	case errors.Is(err, errBotRoleNoMatch):
		log.Printf("bot-role lookup: caller_repo=%s actor_login=%s outcome=%s role=",
			claims.Repository, req.ActorLogin, botRoleOutcomeNoMatch)
		writeBotRoleResponse(w, botRoleResponse{Outcome: botRoleOutcomeNoMatch})
	case err != nil:
		log.Printf("bot-role lookup: caller_repo=%s actor_login=%s outcome=error role= err=%v",
			claims.Repository, req.ActorLogin, err)
		writeError(w, http.StatusBadGateway, "bot-role lookup failed")
	default:
		log.Printf("bot-role lookup: caller_repo=%s actor_login=%s outcome=%s role=%s",
			claims.Repository, req.ActorLogin, botRoleOutcomeRecognized, role)
		writeBotRoleResponse(w, botRoleResponse{Outcome: botRoleOutcomeRecognized, Role: role})
	}
}

// validBotRoleRepo reports whether repo is a valid "owner/name" reference.
func validBotRoleRepo(repo string) bool {
	owner, name, found := strings.Cut(repo, "/")
	return found && ValidateOrgName(owner) == nil &&
		RepoNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

// resolveBotRole maps a validated bot login to the registered role whose
// GitHub App is installed on owner/name. It returns errBotRoleNoMatch for a
// completed lookup with no match; any other error is a lookup failure.
func (h *Handler) resolveBotRole(ctx context.Context, actorLogin, owner, name string) (string, error) {
	slug := strings.TrimSuffix(strings.ToLower(actorLogin), "[bot]")

	// GET /apps/{slug} is public, but anonymous calls share GitHub's
	// per-IP rate limit, which the mint's shared egress addresses exhaust.
	// Authenticate it as one of the mint's own Apps when possible so it is
	// counted against that App instead. A failure to do so, or a rejection of
	// that credential by GitHub, only degrades to the anonymous call.
	var appsJWT, appsJWTRole string
	if authRole := h.firstAllowedRole(); authRole != "" {
		jwt, err := h.appJWT(ctx, authRole)
		if err != nil {
			log.Printf("bot-role lookup: authenticating /apps lookup as role %q failed, using anonymous request: %v", authRole, err)
		} else {
			appsJWT, appsJWTRole = jwt, authRole
		}
	}

	appID, err := h.lookupGitHubAppID(ctx, slug, appsJWT)
	if errors.Is(err, errAppsAuthRejected) {
		// A parseable key that GitHub rejects (rotated, revoked, wrong App)
		// must not gate every lookup. Retry anonymously and drop the
		// credential so the installation check below uses the matched
		// role's own.
		log.Printf("bot-role lookup: /apps lookup authenticated as role %q was rejected, using anonymous request: %v", appsJWTRole, err)
		appsJWT, appsJWTRole = "", ""
		appID, err = h.lookupGitHubAppID(ctx, slug, "")
	}
	if err != nil {
		return "", err
	}

	role := h.roleForAppID(appID)
	if role == "" {
		return "", errBotRoleNoMatch
	}

	// Target scoping: the role's App must be installed on the target repo.
	jwt := appsJWT
	if role != appsJWTRole {
		jwt, err = h.appJWT(ctx, role)
		if err != nil {
			return "", err
		}
	}
	if _, err := FindInstallation(ctx, h.githubBaseURL, jwt, owner, name); err != nil {
		if errors.Is(err, ErrInstallationNotFound) {
			return "", errBotRoleNoMatch
		}
		return "", fmt.Errorf("finding installation for role %q: %v", role, err)
	}
	return role, nil
}

// appJWT returns a signed GitHub App JWT for role.
func (h *Handler) appJWT(ctx context.Context, role string) (string, error) {
	roleAppID, err := h.lookupRoleAppID(role)
	if err != nil {
		return "", fmt.Errorf("looking up app ID for role %q: %v", role, err)
	}
	pemData, err := h.pemAccessor.AccessPEM(ctx, role)
	if err != nil {
		return "", fmt.Errorf("reading PEM secret for role %q: %v", role, err)
	}
	defer func() {
		for i := range pemData {
			pemData[i] = 0
		}
	}()
	jwt, err := GenerateAppJWT(roleAppID, pemData)
	if err != nil {
		return "", fmt.Errorf("generating app JWT for role %q: %v", role, err)
	}
	return jwt, nil
}

// firstAllowedRole returns the lexicographically first allowed role with a
// configured App ID, or "" when there is none.
func (h *Handler) firstAllowedRole() string {
	first := ""
	for role := range h.roleAppIDs {
		if !h.checkAllowedRole(role) {
			continue
		}
		if _, err := h.lookupRoleAppID(role); err != nil {
			continue
		}
		if first == "" || role < first {
			first = role
		}
	}
	return first
}

// roleForAppID returns the allowed role whose registered App ID equals appID
// (compared as canonical decimal integers when the registered value is
// numeric, so "00300" matches 300), or "" when none does. App IDs are
// resolved with lookupRoleAppID, the same mapping /v1/token uses. When several
// allowed roles share the App ID (for example fix reuses the coder App), the
// lexicographically first role name wins so the answer is deterministic.
func (h *Handler) roleForAppID(appID string) string {
	match := ""
	for role := range h.roleAppIDs {
		if !h.checkAllowedRole(role) {
			continue
		}
		id, err := h.lookupRoleAppID(role)
		if err != nil || canonicalAppID(id) != appID {
			continue
		}
		if match == "" || role < match {
			match = role
		}
	}
	return match
}

// canonicalAppID returns id as a canonical decimal integer when it parses as
// a positive one, so a registered "00300" compares equal to GitHub's 300. Any
// other value is returned unchanged and therefore never equals GitHub's ID.
func canonicalAppID(id string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if err != nil || n <= 0 {
		return id
	}
	return strconv.FormatInt(n, 10)
}

// lookupGitHubAppID resolves an App slug to its numeric App ID via GitHub's
// GET /apps/{slug} endpoint. A non-empty jwt authenticates the request as a
// GitHub App; it never changes the answer. A 404 is a completed no-match.
func (h *Handler) lookupGitHubAppID(ctx context.Context, slug, jwt string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.githubBaseURL+"/apps/"+slug, nil)
	if err != nil {
		return "", fmt.Errorf("creating app request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", githubUserAgent())
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	resp, err := mintHTTP(req)
	if err != nil {
		return "", fmt.Errorf("getting app %q: %w", slug, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", errBotRoleNoMatch
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if jwt != "" && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return "", fmt.Errorf("getting app %q returned status %d: %w", slug, resp.StatusCode, errAppsAuthRejected)
		}
		return "", fmt.Errorf("getting app %q returned status %d", slug, resp.StatusCode)
	}

	var app githubAppResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBotRoleBodyBytes)).Decode(&app); err != nil {
		return "", fmt.Errorf("decoding app %q: %w", slug, err)
	}
	if app.ID == nil || *app.ID <= 0 {
		return "", fmt.Errorf("app %q response has no id", slug)
	}
	return strconv.FormatInt(*app.ID, 10), nil
}

func writeBotRoleResponse(w http.ResponseWriter, resp botRoleResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
