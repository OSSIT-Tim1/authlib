package authlib

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var JWTError = errors.New("error generating JWT")
var InvalidJwtClaims = errors.New("Invalid claims")
var InvalidSigningMethod = errors.New("Invalid signing method, expected HS512")

/* tnjitterClaims is a struct of JWT claims used for authorization
in TnjitterClone App.
Role is the role of principal.
IsVerified is true if user has a verified email
*/
type tnjitterClaims struct {
	Role       string `json:"role"`
	IsVerified bool   `json:"isVerified"`
	jwt.RegisteredClaims
}

func (c tnjitterClaims) Valid() error {
	if c.Role != User && c.Role != Business {
		return InvalidJwtClaims
	}
	return nil
}

/* GenerateJWT generates a json web token (JWT) signed with HS512 method.
username is the username of the principal
role is role of the principal, must be USER or BUSINESS
isVerified should be true if user has verified email, false otherwise
returns the signed token if successful.
JWTError is returned if token couldn't be created
*/
func GenerateJWT(username, role string, isVerified bool) (string, error) {
	key := os.Getenv("JWT_SECRET")

	claims := tnjitterClaims{
		Role:       role,
		IsVerified: isVerified,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return "", JWTError
	}
	return tokenString, nil
}

func keyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, InvalidSigningMethod
	}

	return []byte(os.Getenv("JWT_SECRET")), nil
}

// ParseJwt parses a signed json web token (JWT) string and returns the parsed token
func parseJwt(token string) (tnjitterClaims, error) {
	t, err := jwt.ParseWithClaims(token, &tnjitterClaims{}, keyFunc)
	if err != nil {
		return tnjitterClaims{}, err
	}

	if claims, ok := t.Claims.(*tnjitterClaims); ok {
		return *claims, nil
	}

	return tnjitterClaims{}, InvalidJwtClaims
}

/*IsAuthorized verifies that user has one of roles in the passed allowedRoles
 */
func IsAuthorized(next http.HandlerFunc, allowedRoles []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		claims, _ := parseJwt(token)
		// If token is invalid return 403 immediately
		if claims.Valid() != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Token is invalid"))
			return
		}

		for _, role := range allowedRoles {
			if role == claims.Role {
				next(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("You don't have permission for this task"))
		return

	}
}

func GetPrincipal(token string) (string, error) {
	claims, err := parseJwt(token)
	return claims.Subject, err
}

const (
	User     = "USER"
	Business = "BUSINESS"
)
