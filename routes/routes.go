// Package routes contains all the route handlers for the API
package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"main/auth"
	"main/components"
	"main/consts"
	"main/internal/repository"
	"main/utils"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/tursodatabase/go-libsql"
)

var (
	ctx = context.Background()
	// conn, connErr = InitPgDBConnection(consts.DB_URL)
	conn, connErr = InitSqlite(consts.DB_URL)
	repo          = repository.New(conn)
)

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	// Exp      int    `json:"exp"`
}

type LoginUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Repeat   string `json:"repeat"`
}

type ResetPassword struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	RepeatPassword string `json:"repeat"`
}

type CreateStore struct {
	StoreName  string `json:"store_name"`
	StoreCover int    `json:"store_cover"`
}

// func sanitizeUTF8(s string) string {
// 	if !utf8.ValidString(s) {
// 		v := make([]rune, 0, len(s))
// 		for i, r := range s {
// 			if r == utf8.RuneError {
// 				_, size := utf8.DecodeRuneInString(s[i:])
// 				if size == 1 {
// 					continue
// 				}
// 			}
// 			v = append(v, r)
// 		}
// 		s = string(v)
// 	}
// 	return s
// }

// func isValidUTF8(s string) bool {
// 	return utf8.ValidString(s)
// }

func InitPgDBConnection(dbURL string) (*pgxpool.Pool, error) {
	ctx := context.Background()
	// Create the connection pool
	conn, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Validate the connection by attempting to ping the database
	if err := conn.Ping(ctx); err != nil {
		conn.Close() // Ensure the connection pool is closed if validation fails
		log.Fatal(errors.New("Failed to ping the database: " + err.Error()))
		return nil, fmt.Errorf("failed to connect to the database: %w", err)
	}

	return conn, nil
}

func InitSqlite(dbPath string) (*sql.Conn, error) {
	// Embeded Replica: read-only local replica of cloud db
	// Local Only: local sqlite db

	dbPath = "file:" + dbPath
	log.Println("Opening sqlite db in: ", dbPath)

	// --- Embedded Replica ---
	// primaryURL := "file:" + dbPath + "?cache=shared&mode=memory&_fk=1"
	// primaryURL := "libsql://" + dbPath + "?_fk=1&busy_timeout=30000"
	// connector, err := libsql.NewEmbeddedReplicaConnector(dbPath, primaryURL)
	// if err != nil {
	// 	log.Fatal("Failed to make libSql sqlite connector")
	// 	return nil, err
	// }

	// db := sql.OpenDB(connector)
	// defer db.Close()

	// --- Local Only ---
	db, err := sql.Open("libsql", dbPath)
	if err != nil {
		log.Fatal("Failed to open sqlite db")
		return nil, err
	}
	defer db.Close()

	// Configure the database connection pool
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pingErr := db.Ping()

	if pingErr != nil {
		log.Fatal("Failed to ping sqlite db")
	}

	conn, err := db.Conn(context.Background())
	if err != nil {
		log.Fatal("Failed to get connection from sqlite db")
		return nil, err
	}

	err = utils.InitDBSchema(conn, "migrations/schema.sql")
	if err != nil {
		log.Fatal("Failed to init db schema: ", err)
		return nil, err
	} else {
		log.Println("DB schema initialized successfully")
	}

	// return db, nil
	return conn, nil
}

func RedirectLoggedIn(c *gin.Context) {
	auth.AuthRequired()

	c.Redirect(http.StatusFound, "/auth/stores")
}

func Login(c *gin.Context) {
	if connErr != nil {
		msg := errors.New("Failed to connect to database: " + connErr.Error())

		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	var user LoginUser
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Failed to ShouldBindJSON user: " + err.Error(),
		})
		return
	}

	dbUser, err := repo.LoginUser(context.Background(), user.Username)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to login user"})
		return
	}

	header := auth.TokenHeader{
		Alg: "HS256",
		Typ: "JWT",
	}

	id, err := repo.GetIdByUsername(context.Background(), user.Username)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get id by username: " + err.Error(),
		})
		return
	}

	match, err := utils.CheckPassword(user.Password, dbUser.Password)
	if err != nil {
		c.Error(errors.New("Invalid password"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid username or password"})
		return
	}

	if !match {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	var payload auth.TokenPayload

	if id == 1 {
		payload = auth.TokenPayload{
			ID:       id,
			Username: user.Username,
			Exp:      time.Now().Add(consts.EXPIRY_TIME),
			Role:     auth.ADMIN,
		}
	} else {
		payload = auth.TokenPayload{
			ID:       id,
			Username: user.Username,
			Exp:      time.Now().Add(consts.EXPIRY_TIME),
			Role:     auth.USER,
		}
	}

	token := auth.EncodeStaticToken(header, payload)
	if token == nil {
		msg := errors.New("Failed to encode token")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg,
		})
		return
	}

	res := fmt.Sprintf("%s %s", "Bearer ", *token)

	// c.Set("token", res)
	c.SetCookie("token", res, 0, "/", "", false, true)
	// c.JSON(http.StatusOK, gin.H{
	// 	"token": res,
	// })
	c.Redirect(http.StatusFound, "/auth/stores")
}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}

func Register(c *gin.Context) {
	var data RegisterUser
	err := c.ShouldBindJSON(&data)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Failed to ShouldBindJSON data: " + err.Error(),
		})
		c.Error(err)
		return
	}

	if data.Password != data.Repeat {
		msg := errors.New("Passwords don't match")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg,
		})
		return
	}

	hash, err := utils.HashPassword(data.Password)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		c.Error(err)
		return
	}

	user, err := repo.CreateUser(context.Background(), repository.CreateUserParams{
		Username: data.Username,
		Password: hash,
	})
	if err != nil {
		c.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to create user %s : %v", data.Username, err.Error()),
		})
		c.Error(err)
		return
	}

	if user.ID > 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("User %s created successfully", data.Username),
		})
		c.Redirect(http.StatusFound, "/login")
		return
	}
}

func ShowRegister(c *gin.Context) {
	// c.HTML(http.StatusOK, "login.templ", gin.H{})
	c.Status(http.StatusOK)
	// components.LoginPage(c.Writer, c.Request.Context()).Render()
	components.RegisterPage().Render(c.Request.Context(), c.Writer)
}

func ShowLogin(c *gin.Context) {
	// c.HTML(http.StatusOK, "login.templ", gin.H{})
	c.Status(http.StatusOK)
	// components.LoginPage(c.Writer, c.Request.Context()).Render()
	components.LoginPage().Render(c.Request.Context(), c.Writer)
}

func ServeUploadedFile(c *gin.Context) {
	fileNanoid := c.Param("fileid")

	if _, err := strconv.Atoi(fileNanoid); err == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": errors.New("File Id is a number, must be a NanoId instead"),
		})
		return
	}

	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	isOwner, err := repo.IsOwner(context.Background(), repository.IsOwnerParams{
		Username: token.Payload.Username,
		Name:     fileNanoid,
	})
	if err != nil {
		c.Error(errors.New("Failed to get file owner"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get file owner",
		})
		return
	}

	if !isOwner {
		c.Error(errors.New("User doesn't own this file"))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "User doesn't own this file",
		})
		return
	}

	originalFileName, err := repo.GetFileOriginalNameByNanoId(context.Background(), fileNanoid)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	ext := filepath.Ext(originalFileName.OriginalName)

	c.File(fmt.Sprintf("%s/%s%s", consts.UPLOADS_DIR, fileNanoid, ext))
}

func ServeFavicon(c *gin.Context) {
	c.File("./favicon/favicon.ico")
}

func CreateUserStore(c *gin.Context) {
	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	var data CreateStore
	err = c.ShouldBindJSON(&data)
	if err != nil {
		msg := errors.New("Failed to ShouldBindJSON data: " + err.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to ShouldBindJSON data: " + err.Error(),
		})
		return
	}

	if data.StoreCover <= 0 {
		data.StoreCover = 1
	}

	store, err := repo.CreateStore(ctx, repository.CreateStoreParams{
		Name:  c.Query("name"),
		Cover: int64(data.StoreCover),
	})
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create a new store"})
		return
	}

	userStore := repo.AddStoreToUser(ctx, repository.AddStoreToUserParams{
		Storeid: store.ID,
		Userid:  token.Payload.ID,
	})
	if userStore != nil {
		msg := errors.New("Failed to add store to user")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": msg.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Store created successfully"})
}

func ShowCreateStore(c *gin.Context) {
	c.Status(http.StatusOK)
	components.NewStorePage().Render(c.Request.Context(), c.Writer)
}

func GetUserStores(c *gin.Context) {
	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	stores, getUserStoresErr := repo.GetUserStores(context.Background(), token.Payload.ID)
	if getUserStoresErr != nil {
		msg := errors.New("Failed to get user stores: " + getUserStoresErr.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	components.UserStoresPage(stores).Render(c.Request.Context(), c.Writer)
}

func ShowStoreFiles(c *gin.Context) {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The page id is not a number" + err.Error()})
		return
	}

	pageItems := int64(25)

	// Get store id from url param
	storeID, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	totalPages, err := repo.CalculatePages(context.Background(), repository.CalculatePagesParams{
		Fileid:  pageItems,
		Userid:  token.Payload.ID,
		Storeid: int64(storeID),
	})
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate pages"})
		return
	}

	files, err := repo.GetFilesPaginated(context.Background(), repository.GetFilesPaginatedParams{
		Limit:  25,
		Offset: int64(page) * 25,
		ID:     token.Payload.ID, // user id
		ID_2:   int64(storeID),   // store id
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get store files",
		})
		return
	}

	c.Status(http.StatusOK)
	components.StoreFilesPage(files, int32(storeID), int32(totalPages), int32(page)).Render(c.Request.Context(), c.Writer)
}

func UploadFile(c *gin.Context) {
	// Get store id from url param
	storeID, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	// Set upload file limit
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, consts.MAX_FILE_UPLOAD) // 1GB

	// Get files from form
	form, err := c.MultipartForm()
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Get files from form
	files := form.File["archive"]

	var savedFiles []utils.WriteToDiskResult

	// Decompress and Extract files
	for _, file := range files {
		// log.Println(file.Filename)
		ext := filepath.Ext(file.Filename)

		c.Error(errors.New("Archive: " + file.Filename))

		// Check if file is a .zip file
		if ext != ".zip" {
			msg := errors.New("Invalid file type expected .zip got " + file.Filename)
			c.Error(msg)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": msg.Error(),
			})
			return
		} else {
			// Create a random temporary directory to store the uploaded archive file
			tmpDir := filepath.Join("/tmp", utils.RandomString(6))

			c.Error(errors.New("Temp dir: " + tmpDir))

			// Saves the uploaded archive file to the temporary directory
			if err = c.SaveUploadedFile(file, tmpDir); err != nil {
				c.Error(err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to save file",
				})
				return
			}
			defer os.Remove(tmpDir)

			savedFiles, err = utils.DecompressAndExtract(tmpDir, consts.UPLOADS_DIR)
			// Extracts the file to the uploads directory from the archive file in temporary directory
			if err != nil {
				msg := errors.New("Failed to decompress and extract file" + err.Error())
				c.Error(msg)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": msg.Error(),
				})
				return
			}

			c.Error(errors.New("Number of files in archive: " + strconv.Itoa(len(savedFiles))))

			if len(savedFiles) == 0 {
				c.Error(errors.New("No files found in archive"))
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "No files found in archive",
				})
				return
			}

			for k := range savedFiles {
				fileID, err := repo.CreateFile(ctx, repository.CreateFileParams{
					Name:         savedFiles[k].NanoID,
					OriginalName: savedFiles[k].Name,
					ContentType:  "image/jpeg",
					Md5:          utils.GetFileHash(fmt.Sprintf("%s%s%s", consts.UPLOADS_DIR, savedFiles[k].NanoID, savedFiles[k].Ext)),
				})
				if err != nil {
					msg := errors.New("Failed add file to DB: " + err.Error())
					c.Error(msg)
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": msg.Error(),
					})
					return
				}

				c.Error(errors.New("File added to DB with id: " + strconv.Itoa(int(fileID.ID))))

				addToUserStroreFailure := repo.AddFileToStore(ctx, repository.AddFileToStoreParams{
					Fileid:  fileID.ID,
					Storeid: int64(storeID),
				})

				c.Error(errors.New("File added to store with id: " + strconv.Itoa(storeID)))

				if addToUserStroreFailure != nil {
					msg := errors.New("Failed to add file to store: " + addToUserStroreFailure.Error())
					c.Error(msg)
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": msg.Error(),
					})
					return
				}
			}

			c.Error(errors.New("Uploaded " + strconv.Itoa(len(savedFiles)) + " file(s)"))

			c.JSON(http.StatusOK, gin.H{
				"message": fmt.Sprintf("Uploaded %d file(s) successfully", len(savedFiles)),
			})
			return

		}

	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Uploaded %d file(s) successfully", len(savedFiles)),
	})
}

func ShowUpload(c *gin.Context) {
	storeID, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	c.Status(http.StatusOK)
	components.FileUploadPage(int32(storeID)).Render(c.Request.Context(), c.Writer)
}

func DeleteFile(c *gin.Context) {
	fileNanoid := c.Param("fileid")

	if _, err := strconv.Atoi(fileNanoid); err == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": errors.New("File Id is a number, must be a NanoId instead"),
		})
		return
	}

	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	fileID, err := repo.GetFileOriginalNameByNanoId(context.Background(), fileNanoid)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	storeID, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	removeFromStoreErr := repo.RemoveFileFromStore(context.Background(), repository.RemoveFileFromStoreParams{
		Fileid:  fileID.ID,
		Storeid: int64(storeID),
	})
	if removeFromStoreErr != nil {
		msg := errors.New("Failed to remove file from store: " + removeFromStoreErr.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error,
		})
		return
	}

	removeFromDBErr := repo.DeleteFileByNanoId(ctx, fileNanoid)
	if removeFromDBErr != nil {
		msg := errors.New("Failed to remove file from db: " + removeFromDBErr.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The page id is not a number" + err.Error()})
		return
	}

	pageItems := int64(25)

	totalPages, err := repo.CalculatePages(context.Background(), repository.CalculatePagesParams{
		Fileid:  pageItems,
		Userid:  token.Payload.ID,
		Storeid: int64(storeID),
	})
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate pages"})
		return
	}

	files, err := repo.GetFilesPaginated(context.Background(), repository.GetFilesPaginatedParams{
		Limit:  25,
		Offset: 0,
		ID:     token.Payload.ID, // user id
		ID_2:   int64(storeID),   // store id
	})
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get store files",
		})
		return
	}

	c.Status(http.StatusOK)
	components.StoreFilesPage(files, int32(storeID), int32(totalPages), int32(page)).Render(c.Request.Context(), c.Writer)
}

func ResetPasswordRoute(c *gin.Context) {
	var data ResetPassword
	err := c.ShouldBindJSON(data)
	if err != nil {
		msg := errors.New("Failed to ShouldBindJSON data: " + err.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	user, err := repo.ResetPassword(context.Background(), repository.ResetPasswordParams{
		Username: data.Username,
		Password: data.Password,
	})
	if err != nil {
		msg := errors.New("Failed to reset password: " + err.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("User %s reset password", user.Username),
	})
}

func GetFilesFromUserStore(c *gin.Context) {
	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	files, getFilesErr := repo.GetFilesPaginated(context.Background(), repository.GetFilesPaginatedParams{
		Limit:  20,
		Offset: 0,
		ID:     token.Payload.ID,
	})

	if getFilesErr != nil {
		msg := errors.New("Failed to get files from db: " + getFilesErr.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Returned %d files", len(files)),
	})
}

func DeleteStore(c *gin.Context) {
	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(errors.New("Failed to get token from cookie"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	storeID, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	// c.Error(errors.New("Before get files"))
	// c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
	// 	"error": "Before get files",
	// })
	// return

	files, getFilesErr := repo.GetFileIdsFromUserStore(context.Background(), repository.GetFileIdsFromUserStoreParams{
		Storeid: int64(storeID),
		Userid:  token.Payload.ID,
	})

	c.Error(errors.New("Before delete store"))

	err = repo.RemoveStoreFromUser(context.Background(), repository.RemoveStoreFromUserParams{
		Userid:  token.Payload.ID,
		Storeid: int64(storeID),
	})
	if err != nil {
		c.Error(errors.New("Failed to delete user store: " + err.Error()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user store: " + err.Error(),
		})
		return
	}

	if getFilesErr != nil {
		msg := errors.New("Failed to get files from db: " + getFilesErr.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	c.Error(errors.New("Before loop"))

	// add RemoveFileFromStore or this will fail
	for i := range files {
		err = repo.RemoveFileFromStore(context.Background(), repository.RemoveFileFromStoreParams{
			Fileid:  files[i],
			Storeid: int64(storeID),
		})
		if err != nil {
			c.Error(errors.New("Failed to remove file from store: " + err.Error()))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to remove file from store: " + err.Error(),
			})
			return
		}

		err = repo.DeleteFileById(context.Background(), files[i])
		if err != nil {
			c.Error(errors.New("Failed to delete file: " + err.Error()))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete file: " + err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Store deleted successfully",
	})
}
