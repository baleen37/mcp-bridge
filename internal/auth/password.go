package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonVersion = 19
	argonMemory  = 32 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	saltLength   = 16
)

func HashPassword(password []byte) ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encoded := fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	return []byte(encoded), nil
}

func VerifyPassword(encoded, password []byte) bool {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	params := map[string]uint32{}
	for item := range strings.SplitSeq(parts[2], ",") {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return false
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return false
		}
		params[key] = uint32(parsed)
	}
	memory, okMemory := params["m"]
	timeCost, okTime := params["t"]
	threads, okThreads := params["p"]
	// argon2 takes the thread count as a uint8, so reject anything that would
	// silently wrap on conversion rather than deriving a key with the wrong
	// parallelism.
	if !okMemory || !okTime || !okThreads || memory == 0 || timeCost == 0 || threads == 0 || threads > math.MaxUint8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	// The key length is echoed back into IDKey, so bound it to what HashPassword
	// produces rather than trusting the encoded value.
	if err != nil || len(want) != argonKeyLen {
		return false
	}
	got := argon2.IDKey(password, salt, timeCost, memory, uint8(threads), argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}
