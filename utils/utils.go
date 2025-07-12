package utils

import (
	"archive/zip"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"main/auth"
	"main/consts"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/argon2"
	"golang.org/x/image/draw"
)

func FileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	// If there's an error, check if it's "file does not exist"
	if err != nil {
		// If the error is "file does not exist" then return false and no error
		if os.IsNotExist(err) {
			return false, nil
		}
		// For other errors (e.g., permission issues), log or handle them appropriately
		return false, err
	}

	// Ensure the path is not a directory
	// if info.IsDir() {
	// 	return false, errors.New("path is a directory")
	// }

	// Return true if the file exists and is a directory
	if info.IsDir() {
		return true, nil
	}

	// If no errors and not a directory, the file exists
	return true, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

func NewNanoID(length int) string {
	return RandomString(length)
}

func InitDBSchema(conn *sql.Conn, schemaPath string) error {
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}

	queries := strings.Split(string(schema), ";")

	for i, query := range queries {
		query = strings.TrimSpace(query) + ";"

		// log.Println("Executing migration [", i+1, "/", len(queries), "]: ", query)
		log.Println("Executing migration [", i+1, "/", len(queries), "]")

		_, err = conn.ExecContext(context.Background(), string(query))
		if err != nil && !strings.Contains(err.Error(), "not an error") {
			// log.Println("Failed to execute migration [", i+1, "/", len(queries), "]: ", query)
			log.Println("Failed to execute migration [", i+1, "/", len(queries), "]")
			return err
		} else {
			log.Println("Migration [", i+1, "/", len(queries), "] executed successfully")
		}
	}

	return nil
}

func HashPassword(password string) (string, error) {
	decodedSecret, err := hex.DecodeString(consts.SECRET)
	if err != nil {
		return "", fmt.Errorf("Failed to hex decode secret: %w", err)
	}

	// key := argon2.IDKey([]byte(password), []byte(consts.SECRET), 1, 64*1024, 4, 32)
	key := argon2.IDKey([]byte(password), []byte(decodedSecret), 1, 64*1024, 4, 32)
	if key == nil {
		return "", fmt.Errorf("Failed to hash password")
	}
	return hex.EncodeToString(key), nil
}

// CheckPassword verifies if the provided password matches the stored hashed password.
func CheckPassword(providedPassword string, storedHash string) (bool, error) {
	decodedSecret, err := hex.DecodeString(consts.SECRET)
	if err != nil {
		return false, fmt.Errorf("Failed to hex decode secret: %w", err)
	}

	// Decode the stored hash from hexadecimal back to binary
	storedKey, err := hex.DecodeString(storedHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode stored hash: %w", err)
	}

	// Generate a new hash for the provided password using the same parameters
	newKey := argon2.IDKey([]byte(providedPassword), []byte(decodedSecret), 1, 64*1024, 4, 32)

	// Compare the two hashes securely
	return constantTimeCompare(newKey, storedKey), nil
}

// constantTimeCompare performs a constant-time comparison of two byte slices.
func constantTimeCompare(hash1, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}

	// Perform a constant-time comparison
	result := 0
	for i := range len(hash1) {
		result |= int(hash1[i] ^ hash2[i])
	}
	// for i := 0; i < len(hash1); i++ {
	// 	result |= int(hash1[i] ^ hash2[i])
	// }

	return result == 0
}

func GetFileHash(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to get file hash: %v", err)
	}
	md5Hash := md5.Sum(data)
	return hex.EncodeToString(md5Hash[:])
}

func InitUploadsDir() error {
	// Check if uploads dir exists
	uploadsDirExixts, err := FileExists(consts.UPLOADS_DIR)
	// If error then return it
	if err != nil {
		return err
	}

	// If uploads dir doesn't exist then create it
	if !uploadsDirExixts {
		os.Mkdir(consts.UPLOADS_DIR, 0755)
	}

	// Check if thumbnails dir exists
	thumbnailsDirExixts, err := FileExists(consts.THUMBNAILS_DIR)
	// If error then return it
	if err != nil {
		return err
	}

	// If uploads dir doesn't exist then create it
	if !thumbnailsDirExixts {
		os.Mkdir(consts.THUMBNAILS_DIR, 0755)
	}

	// Return no error
	return nil
}

func GetTokenFromCookie(c *gin.Context) (*auth.Token, error) {
	cookieToken, err := c.Cookie("token")
	if err != nil {
		msg := errors.New("Failed to get token from middleware")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg.Error()})
		return nil, msg
	}

	token, err := auth.DecodeToken(cookieToken)
	if err != nil {

		needsRedirect := auth.RedirectExpired(c)
		if needsRedirect {
			return nil, err
		}

		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to decode token: " + err.Error(),
		})
		return nil, err
	}

	return token, nil
}

// GetImageAspectRatio calculates the aspect ratio of an image as a string (e.g., "16:9").
func GetImageAspectRatio(filePath string) (string, error) {
	// Open the image file
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Decode the image
	img, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	// Get the image bounds (width and height)
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Simplify the aspect ratio using the greatest common divisor (GCD)
	gcd := greatestCommonDivisor(width, height)
	simplifiedWidth := width / gcd
	simplifiedHeight := height / gcd

	// Return the aspect ratio as a string (e.g., "16:9")
	return fmt.Sprintf("%d:%d", simplifiedWidth, simplifiedHeight), nil
}

// greatestCommonDivisor calculates the greatest common divisor (GCD) of two integers.
func greatestCommonDivisor(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// DetectImageOrientation detects whether an image is landscape or portrait based on its dimensions.
func DetectImageOrientation(filePath string) (string, error) {
	// Open the image file
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Decode the image
	img, _, err := image.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	// Get the image bounds (width and height)
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Determine orientation based on width and height
	if width > height {
		return "landscape", nil
	} else if height > width {
		return "portrait", nil
	} else {
		return "square", nil
	}
}

// func CreateThumbnail(original string) (bool, error) {
// 	// Open the image file
// 	file, err := os.Open(original)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to open file: %w", err)
// 	}
// 	defer file.Close()
//
//     var src image.Image
//     var err error
//
// 	// img,_, err := image.Decode(file)
// 	// img.Resize(consts.THUMBNAILS_SIZE, consts.THUMBNAILS_SIZE, image.Lanczos3)
//     dst := image.NewRGBA(image.Rect(0, 0, width, height))
//
//     ratio := (float64)(src.Bounds().Max.Y) / (float64)(src.Bounds().Max.X)
//     height := int(math.Round(float64(width) * ratio))
//
//     draw.NearestNeighbor.Scale(dst, dst.Rect, src, src.Bounds(), draw.Over, nil)
//
//     err = jpeg.Encode(w, dst, nil)
//     if err != nil {
//         return err
//     }
//
//     return nil
// }

func CreateThumbnail(srcImagePath, dstImagePath string, maxSize int) error {
	input, err := os.Open(srcImagePath)
	if err != nil {
		return err
	}
	defer input.Close()

	src, _, err := image.Decode(input)
	if err != nil {
		// failed to decode image
		return err
	}

	originalWidth := src.Bounds().Max.X
	originalHeight := src.Bounds().Max.Y

	// Calculate the new dimensions while preserving the aspect ratio
	var newWidth, newHeight int
	if originalWidth > originalHeight {
		newWidth = maxSize
		newHeight = int(math.Round(float64(maxSize) * float64(originalHeight) / float64(originalWidth)))
	} else {
		newHeight = maxSize
		newWidth = int(math.Round(float64(maxSize) * float64(originalWidth) / float64(originalHeight)))
	}

	dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	draw.NearestNeighbor.Scale(dst, dst.Rect, src, src.Bounds(), draw.Over, nil)

	output, err := os.Create(dstImagePath)
	if err != nil {
		return err
	}
	defer output.Close()

	err = jpeg.Encode(output, dst, nil)
	if err != nil {
		return err
	}

	return nil
}

type WriteToDiskResult struct {
	Name   string
	NanoID string
	Ext    string
}

func DecompressAndExtract(src, dst string) ([]WriteToDiskResult, error) {
	// Open the ZIP file
	zipReader, err := zip.OpenReader(src)
	if err != nil {
		return nil, err
	}
	defer zipReader.Close()

	var result []WriteToDiskResult

	// Extract each file from the ZIP archive
	for _, file := range zipReader.File {
		// Skip directories (since we're flattening the structure)
		if file.FileInfo().IsDir() {
			continue
		}

		// Create the target file path using only the base name of the file
		ext := filepath.Ext(file.Name) // Get extension
		// original_name := strings.TrimSuffix(file.Name, ext) // Get original file name without extension
		originalName := file.Name // Get original file name
		nanoID := NewNanoID(6)
		newFileName := nanoID + ext // Get randomized file name with extension
		target := filepath.Join(dst, newFileName)
		thumbName := filepath.Join(consts.THUMBNAILS_DIR, "thumb_"+nanoID+ext)

		// Open the file inside the ZIP archive
		zipFile, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer zipFile.Close()

		// Create the target file
		targetFile, err := os.Create(target)
		if err != nil {
			return nil, err
		}
		defer targetFile.Close()

		// Write the file contents
		if _, err := io.Copy(targetFile, zipFile); err != nil {
			return nil, err
		}

		err = CreateThumbnail(target, thumbName, consts.THUMBNAILS_SIZE)
		if err != nil {
			return nil, err
		}

		result = append(result, WriteToDiskResult{
			Name:   originalName,
			NanoID: nanoID,
			Ext:    ext,
		})
	}

	return result, nil
}
