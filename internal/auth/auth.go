package auth

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret []byte

func init() {
	secretPath := "jwt.secret"
	data, err := os.ReadFile(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			secret := make([]byte, 64)
			_, err := rand.Read(secret)
			if err != nil {
				log.Fatalf("[-] Failed to generate JWT secret: %v", err)
			}
			err = os.WriteFile(secretPath, secret, 0600)
			if err != nil {
				log.Fatalf("[-] Failed to write JWT secret: %v", err)
			}
			jwtSecret = secret
			log.Println("[+] Generated new JWT secret")
		} else {
			log.Fatalf("[-] Failed to read JWT secret: %v", err)
		}
	} else {
		jwtSecret = data
	}
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
