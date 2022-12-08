package authlib

import (
	"os"
	"testing"
)

func TestGenerateJWT(t *testing.T) {
	key := os.Getenv("JWT_SECRET")
	t.Logf("Secret is: %q\n", key)
	username := "pera123"

	token, err := GenerateJWT(username, Business, true)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	t.Logf("token is: %q\n", token)

	parsedToken, err := parseJwt(token)
	if err != nil {
		t.Errorf(err.Error())
		t.Error(token)
	}

	t.Logf("Is valid: %q", parsedToken.Valid())

	if parsedToken.Subject != "pera123" {
		t.Errorf("Error in sub: expected %q, got %q", username, parsedToken.Subject)
	}

	if parsedToken.Role != Business {
		t.Errorf("Error in role: expected %q, got %q", Business, parsedToken.Role)
	}

	if !parsedToken.IsVerified {
		t.Errorf("Error in isVerified: expected %v, got %v", true, false)
	}
}

func TestGetPrincipal(t *testing.T) {
	username := "pera123"
	token, err := GenerateJWT(username, Business, true)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	principal, err := GetPrincipal(token)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}
	if principal != username {
		t.Errorf("Error in sub: expected %q, got %q", username, principal)
	}
}
