package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func CheckUserType(c *gin.Context, role string) (err error) {
	userType := c.GetString("user_type")
	if userType != role {
		err = errors.New("unauthorized to access this resource")
	}
	return err
}

func MatchUserTypeToUid(c *gin.Context, userId string) error {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	if userType == "USER" && uid != userId {
		return errors.New("Unauthorized to access this resource")
	}

	err := CheckUserType(c, userType)
	return err
}
