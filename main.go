package main

import (
	"fmt"
	"log"
	"main/auth"
	"main/consts"
	"main/routes"
	"main/utils"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if consts.PORT == "" {
		// log.Fatal("PORT is not set in .env file")
		consts.PORT = "6500"
	}

	var trustedProxies []string = []string{"127.0.0.1", "::1"}

	r.SetTrustedProxies(trustedProxies)

	r.GET("/", routes.RedirectLoggedIn)

	r.GET("/favicon", routes.ServeFavicon)

	r.Static("/static", "./favicon")

	r.POST("/login", routes.Login)

	r.GET("/login", routes.ShowLogin)

	r.GET("/register", routes.ShowRegister)

	r.POST("/register", routes.Register)

	r.GET("/logout", routes.Logout)

	authorized := r.Group("/auth")

	authorized.Use(auth.AuthRequired())

	authorized.GET("/stores", routes.GetUserStores)

	authorized.GET("/stores/create", routes.ShowCreateStore)

	authorized.POST("/stores/create", routes.CreateUserStore)

	authorized.GET("/stores/:storeid", routes.ShowStoreFiles)

	authorized.GET("/stores/:storeid/upload", routes.ShowUpload)

	authorized.POST("/stores/:storeid/upload", routes.UploadFile)

	authorized.GET("/files/:fileid", routes.ServeUploadedFile)

	authorized.DELETE("/stores/:storeid/:fileid", routes.DeleteFile)

	authorized.DELETE("/stores/:storeid/delete", routes.DeleteStore)

	err := utils.InitUploadsDir()
	if err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf("%s:%s", "127.0.0.1", consts.PORT)

	r.Run(addr)
}
