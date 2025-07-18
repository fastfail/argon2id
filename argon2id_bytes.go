package argon2id

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

func CreateHashBytes(password []byte, params *Params) ([]byte, []byte, error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return nil, nil, err
	}

	hashed := argon2.IDKey(password, salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return hashed, salt, nil
}

func ComparePasswordAndHashBytes(passwordInput, hashed, salt []byte) (match bool, err error) {
	hashedInput := argon2.IDKey(passwordInput, salt, DefaultParams.Iterations, DefaultParams.Memory, DefaultParams.Parallelism, DefaultParams.KeyLength)

	keyLen := int32(len(hashed))
	hashedInputLen := int32(len(hashedInput))

	if subtle.ConstantTimeEq(keyLen, hashedInputLen) == 0 {
		return false, nil
	}
	if subtle.ConstantTimeCompare(hashed, hashedInput) == 1 {
		return true, nil
	}
	return false, nil
}
