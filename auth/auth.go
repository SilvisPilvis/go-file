// Package auth contains custom gin JWT functions and related functions and structs as well as a gin auth middleware
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"main/consts"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Role int

const (
	ADMIN Role = iota
	USER
)

type TokenHeader struct {
	Alg string
	Typ string
}

type TokenPayload struct {
	ID       int64
	Username string
	Exp      time.Time
	Role     Role
}

type TokenSignature struct {
	tokenHeader  string
	tokenPayload string
	secret256bit string
}

type Token struct {
	Header  TokenHeader
	Payload TokenPayload
	// _ TokenSignature
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the cookie from the request
		cookie, err := c.Cookie("token")
		// If cookie is empty or not hound/present, redirect to login page
		if cookie == "" {
			c.Redirect(http.StatusFound, "/login")
		}

		// If we get an error when getting cookie
		if err != nil {
			// Check if the error message indicates token expiration
			if strings.Contains(err.Error(), "token has expired") {
				// Redirect to login if the token has expired
				c.Redirect(http.StatusFound, "/login")
				return
			} else {
				// Return unauthorized for other errors
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": err.Error(),
				})
				return
			}
		}

		// Proceed to the next handler if no error
		c.Next()
	}
}

func RedirectExpired(c *gin.Context) bool {
	token, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return false
	}

	_, err = DecodeToken(token)
	if err != nil {
		if strings.Contains(err.Error(), "token has expired") {
			c.Redirect(http.StatusFound, "/login")
			return true
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return false
	}
	return false
}

func IsAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		token, err := DecodeToken(authHeader)
		if err != nil {
			if strings.Contains(err.Error(), "token has expired") {
				c.Redirect(http.StatusFound, "/login")
				return
			}

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Failed to decode token",
			})
			return
		}

		if token.Payload.Role != ADMIN {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Not authorized",
			})
		}

		c.Next()
	}
}

func EncodeStaticToken(header TokenHeader, payload TokenPayload) *string {
	tokenHeader := header
	tokenPayload := payload

	headerBytes, err := json.Marshal(tokenHeader)
	if err != nil {
		return nil
	}

	payloadBytes, err := json.Marshal(tokenPayload)
	if err != nil {
		return nil
	}

	base64Header := base64.URLEncoding.EncodeToString(headerBytes)
	base64Payload := base64.URLEncoding.EncodeToString(payloadBytes)

	signature := fmt.Sprintf("%s.%s", base64Header, base64Payload)

	tokenSignature := hmac.New(sha256.New, []byte(consts.SECRET))
	tokenSignature.Write([]byte(signature))

	base64Signature := base64.URLEncoding.EncodeToString(tokenSignature.Sum(nil))

	res := fmt.Sprintf("%s.%s.%s", base64Header, base64Payload, base64Signature)

	return &res
}

func DecodeToken(token string) (*Token, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("token is empty when decoding")
	}

	// Strip the "Bearer " prefix from the token if it exists
	token = strings.TrimPrefix(token, "Bearer  ")
	token = strings.TrimPrefix(token, "Bearer ")

	// return nil, fmt.Errorf("Token %v", token)

	// Split the token into its three parts: header, payload, and signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	// Decode the header
	tokenHeaderString, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	// Decode the payload
	tokenPayloadString, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// Unmarshal the header and payload
	var tokenHeader TokenHeader
	var tokenPayload TokenPayload

	err = json.Unmarshal(tokenHeaderString, &tokenHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %v", err)
	}

	err = json.Unmarshal(tokenPayloadString, &tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	// Check if the token has expired
	if tokenPayload.Exp.Before(time.Now()) {
		return nil, fmt.Errorf("token has expired")
	}

	// Re-encode the header and payload to verify the signature
	headerBytes, err := json.Marshal(tokenHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %v", err)
	}

	payloadBytes, err := json.Marshal(tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	base64Header := base64.URLEncoding.EncodeToString(headerBytes)
	base64Payload := base64.URLEncoding.EncodeToString(payloadBytes)

	// Recreate the signature
	signature := fmt.Sprintf("%s.%s", base64Header, base64Payload)

	tokenSignature := hmac.New(sha256.New, []byte(consts.SECRET))
	tokenSignature.Write([]byte(signature))

	base64Signature := base64.URLEncoding.EncodeToString(tokenSignature.Sum(nil))

	// Verify the signature
	if base64Signature != parts[2] {
		return nil, fmt.Errorf("token signatures don't match")
	}

	// Return the decoded token
	return &Token{
		Header:  tokenHeader,
		Payload: tokenPayload,
	}, nil
}
