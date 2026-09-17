package service

import "golang.org/x/crypto/bcrypt"

// PasswordHasher hashes and verifies passwords. The PRD allows either
// Argon2id or bcrypt (§6); bcrypt is used for the walking skeleton since
// golang.org/x/crypto is already a dependency, with Argon2id evaluated as a
// fast-follow once the password-policy stage lands.
type PasswordHasher struct {
	cost int
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{cost: bcrypt.DefaultCost}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (h *PasswordHasher) Verify(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
