package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wangyaodreams-lab/underflow/crypto"
	"github.com/wangyaodreams-lab/underflow/internal/config"
	"github.com/wangyaodreams-lab/underflow/internal/server"
	"github.com/wangyaodreams-lab/underflow/internal/store/sqlite"
)

const (
	testPassword = "Password123!"
	testSecret   = "S3cr3t-Canary"
	alg          = crypto.AlgXChaCha20Poly1305
)

func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "underflow.db")
	st, err := sqlite.Open(context.Background(), sqlite.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Config{
		ListenAddr:      "127.0.0.1:0",
		DBDriver:        "sqlite",
		DBDSN:           dbPath,
		ServerPepper:    bytes.Repeat([]byte{0x42}, 32),
		Registration:    config.RegistrationOpen,
		Argon2Profile:   "interactive",
		SessionTTL:      12 * time.Hour,
		LogLevel:        "error",
		MaxRequestBytes: 8 << 20,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, st, log)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, dir
}

// --- a minimal test client that performs real client-side crypto ---

type account struct {
	email    string
	password string
	kdf      crypto.KDFParams
	vaultID  string
	vaultKey [32]byte
	alg      uint8
}

type client struct {
	t     *testing.T
	base  string
	http  *http.Client
	token string
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

func (c *client) do(method, path string, body any, headers map[string]string, out any) *http.Response {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-UF-Client", "cli")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("do %s %s: %v", method, path, err)
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			c.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
	return resp
}

func (c *client) closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func newAccount(t *testing.T) account {
	t.Helper()
	var salt [16]byte
	copy(salt[:], bytes.Repeat([]byte{0x13}, 16))
	kdf, err := crypto.ParamsForProfile(crypto.ProfileInteractive, salt)
	if err != nil {
		t.Fatal(err)
	}
	// Low cost for tests, still within validation bounds.
	kdf.M, kdf.T, kdf.P = 8192, 1, 1
	vk, err := crypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	return account{
		email:    "user-" + uuid.NewString() + "@example.com",
		password: testPassword,
		kdf:      kdf,
		vaultID:  uuid.NewString(),
		vaultKey: vk,
		alg:      alg,
	}
}

func (a account) masterKey(t *testing.T) [32]byte {
	t.Helper()
	mk, err := crypto.DeriveMasterKeyFromString(a.password, a.kdf)
	if err != nil {
		t.Fatalf("derive master key: %v", err)
	}
	return mk
}

func (a account) authKey(t *testing.T) [32]byte {
	t.Helper()
	ak, err := crypto.DeriveAuthKey(a.masterKey(t), a.kdf.Salt[:])
	if err != nil {
		t.Fatal(err)
	}
	return ak
}

func (a account) kek(t *testing.T) [32]byte {
	t.Helper()
	kek, err := crypto.DeriveKEK(a.masterKey(t), a.kdf.Salt[:])
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (a account) authKeyB64(t *testing.T) string {
	t.Helper()
	ak := a.authKey(t)
	return b64(ak[:])
}

func kdfJSON(k crypto.KDFParams) map[string]any {
	return map[string]any{"id": k.ID, "m": k.M, "t": k.T, "p": k.P, "salt": b64(k.Salt[:])}
}

func register(t *testing.T, c *client, a account) {
	t.Helper()
	kek := a.kek(t)
	protKey, err := crypto.WrapVaultKey(kek, a.alg, a.kdf, a.vaultID, a.vaultKey)
	if err != nil {
		t.Fatal(err)
	}
	nameEnc, err := crypto.SealVaultName(a.alg, a.vaultKey, a.vaultID, "Default")
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Token string `json:"token"`
	}
	r := c.do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":             a.email,
		"kdf":               kdfJSON(a.kdf),
		"authKey":           a.authKeyB64(t),
		"vaultId":           a.vaultID,
		"alg":               a.alg,
		"vaultNameEnc":      b64(nameEnc),
		"protectedVaultKey": b64(protKey),
	}, nil, &resp)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("register status %d", r.StatusCode)
	}
	c.token = resp.Token
}

func login(t *testing.T, c *client, a account) {
	t.Helper()
	var resp struct {
		Token string `json:"token"`
	}
	r := c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":   a.email,
		"authKey": a.authKeyB64(t),
	}, nil, &resp)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", r.StatusCode)
	}
	c.token = resp.Token
}

func TestEndToEndZeroKnowledge(t *testing.T) {
	ts, dir := newTestServer(t)
	c := newClient(t, ts.URL)
	a := newAccount(t)
	register(t, c, a)

	// Create an item with a canary secret.
	itemID := uuid.NewString()
	plaintext := []byte(`{"name":"example.com","username":"alice","password":"` + testSecret + `"}`)
	blob, err := crypto.SealItemWithVaultKey(a.alg, a.vaultKey, a.vaultID, itemID, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		Revision int64 `json:"revision"`
	}
	r := c.do(http.MethodPost, "/api/v1/vaults/"+a.vaultID+"/items", map[string]any{
		"id": itemID, "blob": b64(blob),
	}, nil, &created)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create item status %d", r.StatusCode)
	}
	if created.Revision == 0 {
		t.Fatal("server did not assign a revision")
	}

	// Sync from revision 0 and decrypt the item.
	var sync struct {
		Items []struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
			Blob     string `json:"blob"`
			Deleted  bool   `json:"deleted"`
		} `json:"items"`
		Revision int64 `json:"revision"`
	}
	r = c.do(http.MethodGet, "/api/v1/sync?since=0", nil, nil, &sync)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("sync status %d", r.StatusCode)
	}
	if len(sync.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(sync.Items))
	}
	env, err := base64.StdEncoding.DecodeString(sync.Items[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.OpenItemWithVaultKey(a.vaultKey, a.vaultID, itemID, env)
	if err != nil {
		t.Fatalf("decrypt item: %v", err)
	}
	if !bytes.Contains(got, []byte(testSecret)) {
		t.Fatalf("decrypted item missing secret: %s", got)
	}

	// Conflict handling: stale base revision.
	r = c.do(http.MethodPut, "/api/v1/vaults/"+a.vaultID+"/items/"+itemID, map[string]any{
		"blob": b64(blob), "baseRevision": created.Revision + 99,
	}, nil, nil)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("stale update: want 409 got %d", r.StatusCode)
	}
	c.closeBody(r)

	// The server database must never contain the plaintext, the password or
	// the vault key.
	assertNoPlaintextOnDisk(t, dir, testSecret, testPassword)

	// A second client (fresh login) must be able to decrypt the same item.
	c2 := newClient(t, ts.URL)
	login(t, c2, a)
	var sync2 struct {
		Items []struct {
			Blob string `json:"blob"`
		} `json:"items"`
	}
	r = c2.do(http.MethodGet, "/api/v1/sync?since=0", nil, nil, &sync2)
	if r.StatusCode != http.StatusOK || len(sync2.Items) != 1 {
		t.Fatalf("second sync failed: %d items=%d", r.StatusCode, len(sync2.Items))
	}
	env2, _ := base64.StdEncoding.DecodeString(sync2.Items[0].Blob)
	got2, err := crypto.OpenItemWithVaultKey(a.vaultKey, a.vaultID, itemID, env2)
	if err != nil || !bytes.Equal(got2, plaintext) {
		t.Fatalf("second client could not decrypt: %v", err)
	}
}

func TestUnauthorizedAndCrossTenant(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t, ts.URL)

	// Unauthenticated access is rejected.
	r := c.do(http.MethodGet, "/api/v1/vaults", nil, nil, nil)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth vaults: want 401 got %d", r.StatusCode)
	}
	c.closeBody(r)

	// First user.
	a := newAccount(t)
	register(t, c, a)
	itemID := uuid.NewString()
	blob, _ := crypto.SealItemWithVaultKey(a.alg, a.vaultKey, a.vaultID, itemID, []byte("secret"))
	r = c.do(http.MethodPost, "/api/v1/vaults/"+a.vaultID+"/items", map[string]any{"id": itemID, "blob": b64(blob)}, nil, nil)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create item: %d", r.StatusCode)
	}
	c.closeBody(r)

	// Second user must not see or touch the first user's vault.
	c2 := newClient(t, ts.URL)
	b := newAccount(t)
	register(t, c2, b)
	r = c2.do(http.MethodGet, "/api/v1/vaults/"+a.vaultID, nil, nil, nil)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant get vault: want 404 got %d", r.StatusCode)
	}
	c2.closeBody(r)
	r = c2.do(http.MethodGet, "/api/v1/vaults/"+a.vaultID+"/items/"+itemID, nil, nil, nil)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant get item: want 404 got %d", r.StatusCode)
	}
	c2.closeBody(r)
	r = c2.do(http.MethodPost, "/api/v1/vaults/"+a.vaultID+"/items", map[string]any{"id": uuid.NewString(), "blob": b64(blob)}, nil, nil)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant create item: want 404 got %d", r.StatusCode)
	}
	c2.closeBody(r)
}

func TestCookieSessionRequiresCSRF(t *testing.T) {
	ts, _ := newTestServer(t)

	// Web-style client (cookie auth, no X-UF-Client header).
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	a := newAccount(t)

	// Register over the API to create the account using a CLI client.
	cli := newClient(t, ts.URL)
	register(t, cli, a)

	// Log in as web (cookie).
	body, _ := json.Marshal(map[string]any{"email": a.email, "authKey": a.authKeyB64(t)})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := web.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("web login: %d", resp.StatusCode)
	}

	// Logout without the CSRF header must be rejected.
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/logout", nil)
	resp, err = web.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF: want 403 got %d", resp.StatusCode)
	}

	// With the CSRF cookie value in the header it succeeds.
	var csrf string
	baseURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range jar.Cookies(baseURL) {
		if ck.Name == "uf_csrf" {
			csrf = ck.Value
		}
	}
	if csrf == "" {
		t.Fatal("csrf cookie not set")
	}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("X-UF-CSRF", csrf)
	resp, err = web.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout with CSRF: want 200 got %d", resp.StatusCode)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	ts, _ := newTestServer(t)
	cli := newClient(t, ts.URL)
	a := newAccount(t)
	register(t, cli, a)

	wrong := a
	wrong.password = "definitely-wrong"
	c := newClient(t, ts.URL)
	r := c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":   a.email,
		"authKey": wrong.authKeyB64(t),
	}, nil, nil)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: want 401 got %d", r.StatusCode)
	}
	c.closeBody(r)
}

func TestKDFPreloginHidesEnumeration(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t, ts.URL)
	known := newAccount(t)
	register(t, c, known)

	get := func(email string) map[string]any {
		var out struct {
			KDF kdfDTO `json:"kdf"`
		}
		r := c.do(http.MethodGet, "/api/v1/auth/kdf?email="+email, nil, nil, &out)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("kdf status %d", r.StatusCode)
		}
		return map[string]any{"m": out.KDF.M, "t": out.KDF.T, "p": out.KDF.P, "salt": out.KDF.Salt}
	}
	if _, ok := get(known.email)["salt"]; !ok {
		t.Fatal("known email missing salt")
	}
	// Unknown email still returns a well-formed response with a decoy salt.
	unknown := get("nobody-" + uuid.NewString() + "@example.com")
	if unknown["salt"] == "" {
		t.Fatal("unknown email returned empty salt")
	}
}

type kdfDTO struct {
	ID   uint8  `json:"id"`
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"`
}

func assertNoPlaintextOnDisk(t *testing.T, dir string, secrets ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if bytes.Contains(data, []byte(s)) {
				t.Fatalf("plaintext %q found in %s", s, e.Name())
			}
		}
	}
}
