package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

var (
	// ErrInvalidHash in returned by ComparePasswordAndHash if the provided
	// hash isn't in the expected format.
	InvalidHashError = errors.New("argon2id: incorrect_hash_format")

	// ErrIncompatibleVersion in returned by ComparePasswordAndHash if the
	// provided hash was created using a different version of Argon2.
	IncompatibleVersionError = errors.New("argon2id: incompatible_version")
)

type Config struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// GetPasswordConfig Returns the configurations
var DefaultConfig = &Config{
	memory:      64 * 1024,
	iterations:  1,
	parallelism: 4,
	saltLength:  16,
	keyLength:   32,
}

// GeneratePasswordHash takes plaintext password and generate hash
// The hashed string can be used to be saved in Database
func GeneratePasswordHash(password string, c *Config) (string, error) {
	salt, err := generateRandomBytes(c.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, c.iterations, c.memory, c.parallelism, c.keyLength)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	hashedPassword := fmt.Sprintf(format, argon2.Version, c.memory, c.iterations, c.parallelism, b64Salt, b64Hash)
	return hashedPassword, nil

}

// ComparePasswordHash take password and hash to compare them both
// And determine if the password is valid or not.
func ComparePasswordHash(password string, hash string) (bool, error) {
	config, salt, decodedHash, err := decodeHash(hash)

	if err != nil {
		return false, err
	}

	comparisonHash := argon2.IDKey([]byte(password), salt, config.iterations, config.memory, config.parallelism, config.keyLength)

	hashLength := int32(len(decodedHash))
	comparisonHashLength := int32(len(decodedHash))

	if subtle.ConstantTimeEq(hashLength, comparisonHashLength) == 0 {
		return false, nil
	}

	match := subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1

	return match, nil
}

func generateRandomBytes(len uint32) ([]byte, error) {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func decodeHash(hash string) (config *Config, salt, decodedHash []byte, err error) {
	vals := strings.Split(hash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, InvalidHashError
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, IncompatibleVersionError
	}

	config = &Config{}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &config.memory, &config.iterations, &config.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	config.saltLength = uint32(len(salt))

	decodedHash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	config.keyLength = uint32(len(decodedHash))

	return config, salt, decodedHash, nil
}
