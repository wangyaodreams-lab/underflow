// Package client is the HTTP client used by the CLI (and tests) to talk to an
// Underflow server. It transports only ciphertext and public parameters.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wangyaodreams-lab/underflow/crypto"
)

// Client is a thin JSON client for the Underflow API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a client with a default timeout.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is a structured error returned by the server.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("http %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// KDFParams mirrors the server's KDF descriptor.
type KDFParams struct {
	ID   uint8  `json:"id"`
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt string `json:"salt"`
}

// ToCrypto converts the wire form to crypto.KDFParams.
func (k KDFParams) ToCrypto() (crypto.KDFParams, error) {
	var p crypto.KDFParams
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil {
		return p, fmt.Errorf("client: bad salt: %w", err)
	}
	if len(salt) != 16 {
		return p, fmt.Errorf("client: salt must be 16 bytes")
	}
	p.ID, p.M, p.T, p.P = k.ID, k.M, k.T, k.P
	copy(p.Salt[:], salt)
	return p, nil
}

// Session is returned by register/login.
type Session struct {
	UserID string    `json:"userId"`
	Email  string    `json:"email"`
	KDF    KDFParams `json:"kdf"`
	Token  string    `json:"token"`
	CSRF   string    `json:"csrf"`
}

// UserInfo is returned by Me.
type UserInfo struct {
	UserID string    `json:"userId"`
	Email  string    `json:"email"`
	KDF    KDFParams `json:"kdf"`
}

// Vault is an encrypted vault descriptor.
type Vault struct {
	ID                string `json:"id"`
	Alg               uint8  `json:"alg"`
	NameEnc           string `json:"nameEnc"`
	ProtectedVaultKey string `json:"protectedVaultKey"`
	Revision          int64  `json:"revision"`
	UpdatedAt         int64  `json:"updatedAt"`
}

// Item is an encrypted item as stored server-side.
type Item struct {
	ID        string `json:"id"`
	VaultID   string `json:"vaultId"`
	Revision  int64  `json:"revision"`
	Blob      string `json:"blob"`
	Deleted   bool   `json:"deleted"`
	UpdatedAt int64  `json:"updatedAt"`
}

// SyncResult is the response of Sync.
type SyncResult struct {
	Items    []Item `json:"items"`
	Revision int64  `json:"revision"`
}

// RegisterInput is the payload for Register.
type RegisterInput struct {
	Email             string
	KDF               crypto.KDFParams
	AuthKey           [32]byte
	VaultID           string
	Alg               uint8
	VaultNameEnc      []byte
	ProtectedVaultKey []byte
	InviteCode        string
}

// Register creates an account.
func (c *Client) Register(ctx context.Context, in RegisterInput) (Session, error) {
	body := map[string]any{
		"email":             strings.ToLower(strings.TrimSpace(in.Email)),
		"kdf":               kdfWire(in.KDF),
		"authKey":           b64(in.AuthKey[:]),
		"vaultId":           in.VaultID,
		"alg":               in.Alg,
		"vaultNameEnc":      b64(in.VaultNameEnc),
		"protectedVaultKey": b64(in.ProtectedVaultKey),
	}
	headers := map[string]string{}
	if in.InviteCode != "" {
		headers["X-UF-Invite"] = in.InviteCode
	}
	var out Session
	if err := c.call(ctx, http.MethodPost, "/api/v1/auth/register", body, headers, &out); err != nil {
		return out, err
	}
	c.Token = out.Token
	return out, nil
}

// Login authenticates with a derived AuthKey.
func (c *Client) Login(ctx context.Context, email string, authKey [32]byte) (Session, error) {
	var out Session
	body := map[string]any{
		"email":   strings.ToLower(strings.TrimSpace(email)),
		"authKey": b64(authKey[:]),
	}
	if err := c.call(ctx, http.MethodPost, "/api/v1/auth/login", body, nil, &out); err != nil {
		return out, err
	}
	c.Token = out.Token
	return out, nil
}

// Logout revokes the current session.
func (c *Client) Logout(ctx context.Context) error {
	return c.call(ctx, http.MethodPost, "/api/v1/auth/logout", nil, nil, nil)
}

// KDF fetches the KDF parameters for an email (pre-login).
func (c *Client) KDF(ctx context.Context, email string) (KDFParams, error) {
	var out struct {
		KDF KDFParams `json:"kdf"`
	}
	q := "/api/v1/auth/kdf?email=" + url.QueryEscape(strings.ToLower(strings.TrimSpace(email)))
	if err := c.call(ctx, http.MethodGet, q, nil, nil, &out); err != nil {
		return out.KDF, err
	}
	return out.KDF, nil
}

// Me returns the authenticated account info.
func (c *Client) Me(ctx context.Context) (UserInfo, error) {
	var out UserInfo
	err := c.call(ctx, http.MethodGet, "/api/v1/user", nil, nil, &out)
	return out, err
}

// ListVaults returns the user's vaults.
func (c *Client) ListVaults(ctx context.Context) ([]Vault, error) {
	var out struct {
		Vaults []Vault `json:"vaults"`
	}
	if err := c.call(ctx, http.MethodGet, "/api/v1/vaults", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Vaults, nil
}

// CreateItem uploads a new encrypted item.
func (c *Client) CreateItem(ctx context.Context, vaultID, itemID string, blob []byte) (Item, error) {
	var out Item
	body := map[string]any{"id": itemID, "blob": b64(blob)}
	err := c.call(ctx, http.MethodPost, "/api/v1/vaults/"+vaultID+"/items", body, nil, &out)
	return out, err
}

// UpdateItem replaces an item's ciphertext using optimistic concurrency.
func (c *Client) UpdateItem(ctx context.Context, vaultID, itemID string, blob []byte, baseRev int64) (Item, error) {
	var out Item
	body := map[string]any{"blob": b64(blob), "baseRevision": baseRev}
	err := c.call(ctx, http.MethodPut, "/api/v1/vaults/"+vaultID+"/items/"+itemID, body, nil, &out)
	return out, err
}

// DeleteItem tombstones an item.
func (c *Client) DeleteItem(ctx context.Context, vaultID, itemID string, baseRev int64) (Item, error) {
	var out Item
	path := fmt.Sprintf("/api/v1/vaults/%s/items/%s?revision=%d", vaultID, itemID, baseRev)
	err := c.call(ctx, http.MethodDelete, path, nil, nil, &out)
	return out, err
}

// Sync fetches items changed after since.
func (c *Client) Sync(ctx context.Context, since int64) (SyncResult, error) {
	var out SyncResult
	err := c.call(ctx, http.MethodGet, fmt.Sprintf("/api/v1/sync?since=%d", since), nil, nil, &out)
	return out, err
}

// ChangePassword rotates the master key material.
func (c *Client) ChangePassword(ctx context.Context, kdf crypto.KDFParams, authKey [32]byte, vaults []VaultKeyInput) error {
	body := map[string]any{
		"kdf":     kdfWire(kdf),
		"authKey": b64(authKey[:]),
		"vaults":  vaults,
	}
	return c.call(ctx, http.MethodPost, "/api/v1/auth/password", body, nil, nil)
}

// VaultKeyInput carries a re-wrapped vault key.
type VaultKeyInput struct {
	ID                string `json:"id"`
	Alg               uint8  `json:"alg"`
	ProtectedVaultKey string `json:"protectedVaultKey"`
}

func (c *Client) call(ctx context.Context, method, path string, body any, headers map[string]string, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-UF-Client", "cli")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		apiErr := &APIError{Status: resp.StatusCode}
		var eb struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &eb) == nil {
			apiErr.Code, apiErr.Message = eb.Error.Code, eb.Error.Message
		}
		if apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(string(data))
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("client: decode response: %w", err)
		}
	}
	return nil
}

func kdfWire(k crypto.KDFParams) map[string]any {
	return map[string]any{"id": k.ID, "m": k.M, "t": k.T, "p": k.P, "salt": b64(k.Salt[:])}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
