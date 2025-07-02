package routes

import (
	"context"
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
)

// func RegisterRoute() {
//
// }

var (
	ctx            = context.Background()
	conn, conn_err = InitDBConnection(consts.DB_URL)
	repo           = repository.New(conn)
)

type User struct {
	Id       int32  `json:"id"`
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

func InitDBConnection(dbURL string) (*pgxpool.Pool, error) {
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

func Login(c *gin.Context) {
	if conn_err != nil {
		msg := errors.New("Failed to connect to database: " + conn_err.Error())

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

	db_user, err := repo.LoginUser(context.Background(), user.Username)

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

	match, err := utils.CheckPassword(user.Password, db_user.Password)
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
			Id:       id,
			Username: user.Username,
			Exp:      time.Now().Add(consts.EXPIRY_TIME),
			Role:     auth.ADMIN,
		}
	} else {
		payload = auth.TokenPayload{
			Id:       id,
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

	// c.Error(errors.New(data.Username))
	// c.AbortWithStatusJSON(int(http.StatusBadRequest), gin.H{
	// 	"error": data.Username,
	// })
	// return

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
	file_nanoid := c.Param("fileid")

	if _, err := strconv.Atoi(file_nanoid); err == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": errors.New("File Id is a number, must be a NanoId instead"),
		})
	}

	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	is_owner, err := repo.IsOwner(context.Background(), repository.IsOwnerParams{
		Username: token.Payload.Username,
		Name:     file_nanoid,
	})
	if err != nil {
		c.Error(errors.New("Failed to get file owner"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get file owner",
		})
		return
	}

	if !is_owner {
		c.Error(errors.New("User doesn't own this file"))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "User doesn't own this file",
		})
		return
	}

	original_file_name, err := repo.GetFileOriginalNameByNanoId(context.Background(), file_nanoid)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	ext := filepath.Ext(original_file_name.OriginalName)

	c.File(fmt.Sprintf("%s/%s%s", consts.UPLOADS_DIR, file_nanoid, ext))
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
		Cover: int32(data.StoreCover),
	})
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create a new store"})
		return
	}

	user_store := repo.AddStoreToUser(ctx, repository.AddStoreToUserParams{
		Storeid: store.ID,
		Userid:  token.Payload.Id,
	})
	if user_store != nil {
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

	stores, get_user_stores_err := repo.GetUserStores(context.Background(), int32(token.Payload.Id))
	if get_user_stores_err != nil {
		msg := errors.New("Failed to get user stores")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
	}

	components.UserStoresPage(stores).Render(c.Request.Context(), c.Writer)
}

func ShowStoreFiles(c *gin.Context) {
	page, err := strconv.Atoi(c.Query("page"))

	page_items := int32(25)

	// Get store id from url param
	store_id, err := strconv.Atoi(c.Param("storeid"))
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

	total_pages, err := repo.CalculatePages(context.Background(), repository.CalculatePagesParams{
		Fileid:  page_items,
		Userid:  token.Payload.Id,
		Storeid: int32(store_id),
	})

	files, err := repo.GetFilesPaginated(context.Background(), repository.GetFilesPaginatedParams{
		Limit:  25,
		Offset: int32(page) * 25,
		ID:     token.Payload.Id, // user id
		ID_2:   int32(store_id),  // store id
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get store files",
		})
		return
	}

	c.Status(http.StatusOK)
	components.StoreFilesPage(files, int32(store_id), int32(total_pages), int32(page)).Render(c.Request.Context(), c.Writer)
}

func UploadFile(c *gin.Context) {
	// Get store id from url param
	store_id, err := strconv.Atoi(c.Param("storeid"))
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

	var saved_files []utils.WriteToDiskResult

	// Decompress and Extract files
	for _, file := range files {
		// log.Println(file.Filename)
		ext := filepath.Ext(file.Filename)

		c.Error(errors.New("Archive: " + file.Filename))

		// Check if file is a .tar.zst file
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

			saved_files, err = utils.DecompressAndExtract(tmpDir, consts.UPLOADS_DIR)
			// Extracts the file to the uploads directory from the archive file in temporary directory
			if err != nil {
				msg := errors.New("Failed to decompress and extract file" + err.Error())
				c.Error(msg)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": msg.Error(),
				})
				return
			}

			c.Error(errors.New("Number of files in archive: " + strconv.Itoa(len(saved_files))))

			if len(saved_files) == 0 {
				c.Error(errors.New("No files found in archive"))
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "No files found in archive",
				})
				return
			}

			for k := range saved_files {
				file_id, err := repo.CreateFile(ctx, repository.CreateFileParams{
					Name:         saved_files[k].NanoId,
					OriginalName: saved_files[k].Name,
					ContentType:  "image/jpeg",
					Md5:          utils.GetFileHash(fmt.Sprintf("%s%s%s", consts.UPLOADS_DIR, saved_files[k].NanoId, saved_files[k].Ext)),
				})
				if err != nil {
					msg := errors.New("Failed add file to DB: " + err.Error())
					c.Error(msg)
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": msg.Error(),
					})
					return
				}

				c.Error(errors.New("File added to DB with id: " + strconv.Itoa(int(file_id.ID))))

				add_to_user_strore_failure := repo.AddFileToStore(ctx, repository.AddFileToStoreParams{
					Fileid:  file_id.ID,
					Storeid: int32(store_id),
				})

				c.Error(errors.New("File added to store with id: " + strconv.Itoa(store_id)))

				if add_to_user_strore_failure != nil {
					msg := errors.New("Failed to add file to store: " + add_to_user_strore_failure.Error())
					c.Error(msg)
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error": msg.Error(),
					})
					return
				}
			}

			c.Error(errors.New("Uploaded " + strconv.Itoa(len(saved_files)) + " file(s)"))

			c.JSON(http.StatusOK, gin.H{
				"message": fmt.Sprintf("Uploaded %d file(s) successfully", len(saved_files)),
			})
			return

		}

	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Uploaded %d file(s) successfully", len(saved_files)),
	})
}

func ShowUpload(c *gin.Context) {
	store_id, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	c.Status(http.StatusOK)
	components.FileUploadPage(int32(store_id)).Render(c.Request.Context(), c.Writer)
}

func DeleteFile(c *gin.Context) {
	file_nanoid := c.Param("fileid")

	if _, err := strconv.Atoi(file_nanoid); err == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": errors.New("File Id is a number, must be a NanoId instead"),
		})
	}

	token, err := utils.GetTokenFromCookie(c)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get token from cookie",
		})
		return
	}

	file_id, err := repo.GetFileOriginalNameByNanoId(context.Background(), file_nanoid)
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	store_id, err := strconv.Atoi(c.Param("storeid"))
	if err != nil {
		msg := errors.New("Failed to convert storeid to int")
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": msg.Error(),
		})
		return
	}

	remove_from_store_err := repo.RemoveFileFromStore(context.Background(), repository.RemoveFileFromStoreParams{
		Fileid:  file_id.ID,
		Storeid: int32(store_id),
	})
	if remove_from_store_err != nil {
		msg := errors.New("Failed to remove file from store: " + remove_from_store_err.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error,
		})
		return
	}

	remove_from_db_err := repo.DeleteFileByNanoId(ctx, file_nanoid)
	if remove_from_db_err != nil {
		msg := errors.New("Failed to remove file from db: " + remove_from_db_err.Error())
		c.Error(msg)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": msg.Error(),
		})
		return
	}

	// c.JSON(http.StatusOK, gin.H{
	// 	"message": "File deleted successfully",
	// })

	page, err := strconv.Atoi(c.Query("page"))

	page_items := int32(25)

	total_pages, err := repo.CalculatePages(context.Background(), repository.CalculatePagesParams{
		Fileid:  page_items,
		Userid:  token.Payload.Id,
		Storeid: int32(store_id),
	})

	files, err := repo.GetFilesPaginated(context.Background(), repository.GetFilesPaginatedParams{
		Limit:  25,
		Offset: 0,
		ID:     token.Payload.Id, // user id
		ID_2:   int32(store_id),  // store id
	})
	if err != nil {
		c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get store files",
		})
		return
	}

	c.Status(http.StatusOK)
	components.StoreFilesPage(files, int32(store_id), int32(total_pages), int32(page)).Render(c.Request.Context(), c.Writer)
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

	files, get_files_err := repo.GetFilesPaginated(context.Background(), repository.GetFilesPaginatedParams{
		Limit:  20,
		Offset: 0,
		ID:     token.Payload.Id,
	})

	if get_files_err != nil {
		msg := errors.New("Failed to get files from db: " + get_files_err.Error())
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

	// c.Error(errors.New("Before get files"))
	// c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
	// 	"error": "Before get files",
	// })
	// return

	store_id, err := strconv.Atoi(c.Param("storeid"))
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

	files, get_files_err := repo.GetFileIdsFromUserStore(context.Background(), repository.GetFileIdsFromUserStoreParams{
		Storeid: int32(store_id),
		Userid:  token.Payload.Id,
	})

	c.Error(errors.New("Before delete store"))

	err = repo.RemoveStoreFromUser(context.Background(), repository.RemoveStoreFromUserParams{
		Userid:  token.Payload.Id,
		Storeid: int32(store_id),
	})
	if err != nil {
		c.Error(errors.New("Failed to delete user store: " + err.Error()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user store: " + err.Error(),
		})
		return
	}

	if get_files_err != nil {
		msg := errors.New("Failed to get files from db: " + get_files_err.Error())
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
			Storeid: int32(store_id),
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
