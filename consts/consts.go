package consts

import (
	// "crypto/rand"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

const (
	MAX_FILE_UPLOAD = 1000 << 20 // 1024 MB or 1 GB
	EXPIRY_TIME     = time.Minute * 10
)

var (
	// DB_URL string = "postgres://postgres:postgres@localhost:5432/postgres"
	DB_URL          string
	SECRET          string
	PORT            string = "6500"
	UPLOADS_DIR            = "./uploads/"
	THUMBNAILS_DIR         = "./uploads/thumbnails/"
	THUMBNAILS_SIZE        = 256
	// SECRET        = make([]byte, 32)
	// _, err        = rand.Read(SECRET)
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Set environment variables
	DB_URL = os.Getenv("DB_URL")
	SECRET = os.Getenv("SECRET")
	PORT = os.Getenv("PORT")
	UPLOADS_DIR = os.Getenv("UPLOADS_DIR")
	THUMBNAILS_DIR = os.Getenv("THUMBNAILS_DIR")
	THUMBNAILS_SIZE, _ = strconv.Atoi(os.Getenv("THUMBNAILS_SIZE"))

	// Optionally, validate if required environment variables are set
	// if DB_URL == "" || SECRET == "" || PORT == "" {
	// 	log.Fatal("Environment variables are not set")
	// }
}
