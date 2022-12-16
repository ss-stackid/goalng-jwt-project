package routes

import (
	controller "github.com/ss-stackid/golang-jwt-project/controllers"
	"github.com/ss-stackid/golang-jwt-project/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:email", controller.GetUser())
}
