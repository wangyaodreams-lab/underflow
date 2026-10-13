// Package vault defines the plaintext item schema. Values of these types are
// encrypted client-side before they ever reach the server.
package vault

import (
	"encoding/json"
	"time"
)

// Item types.
const (
	TypeLogin    = "login"
	TypeNote     = "note"
	TypeCard     = "card"
	TypeIdentity = "identity"
)

// Field is a custom (user-defined) field.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type,omitempty"` // text | hidden | bool
}

// PasswordEntry records a previous password.
type PasswordEntry struct {
	Password  string    `json:"password"`
	ChangedAt time.Time `json:"changedAt"`
}

// Item is the plaintext payload stored (encrypted) inside an item blob.
type Item struct {
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Name            string          `json:"name"`
	Username        string          `json:"username,omitempty"`
	Password        string          `json:"password,omitempty"`
	URLs            []string        `json:"urls,omitempty"`
	TOTP            string          `json:"totp,omitempty"`
	Notes           string          `json:"notes,omitempty"`
	Tags            []string        `json:"tags,omitempty"`
	Folder          string          `json:"folder,omitempty"`
	Fields          []Field         `json:"fields,omitempty"`
	PasswordHistory []PasswordEntry `json:"passwordHistory,omitempty"`
	Favorite        bool            `json:"favorite,omitempty"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

// Marshal serializes an item to its plaintext JSON representation.
// The caller encrypts the result before it leaves the client.
func (i Item) Marshal() ([]byte, error) {
	return json.Marshal(i) // #nosec G117 -- encrypted immediately after marshaling.
}

// Unmarshal parses a decrypted item payload.
func Unmarshal(b []byte) (Item, error) {
	var it Item
	if err := json.Unmarshal(b, &it); err != nil {
		return it, err
	}
	if it.Type == "" {
		it.Type = TypeLogin
	}
	return it, nil
}

// PrimaryURL returns the first URL, if any.
func (i Item) PrimaryURL() string {
	if len(i.URLs) == 0 {
		return ""
	}
	return i.URLs[0]
}
