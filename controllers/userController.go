package controllers

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"github.com/ss-stackid/golang-jwt-project/database"
	helper "github.com/ss-stackid/golang-jwt-project/helpers"
	"github.com/ss-stackid/golang-jwt-project/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
	validate                         = validator.New()
)

func HashPassword(password string) *string {
	encrypt, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	passwd := string(encrypt)
	return &passwd
}

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	var isPasswordVerified = true
	var msg = ""
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	if err != nil {
		isPasswordVerified = false
		msg = "Email or Password is invalid"
	}
	return isPasswordVerified, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var count int64
		var err error
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		}
		count, err = userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error Occured while checking the email"})
			log.Panic(err)

		}
		password := HashPassword(*user.Password)
		user.Password = password
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error Occured while checking the phone"})
			log.Panic(err)

		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "The email or phone number is already exist"})
		}

		user.CreatedAt, _ = time.Parse(time.RFC822, time.Now().Format(time.RFC822))
		user.UpdatedAt, _ = time.Parse(time.RFC822, time.Now().Format(time.RFC822))
		user.ID = primitive.NewObjectID()
		user.UserID = user.ID.Hex()
		token, refreshToken, err := helper.GenerateAllToken(
			*user.Email,
			*user.FirstName,
			*user.LastName,
			user.UserID,
			*user.UserType,
		)
		if err != nil {
			log.Fatal("Problem creating JWT tokens")
		}
		user.Token = &token
		user.RefreshToken = &refreshToken

		resultInsertionNo, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertionNo)
	}

}

func Login() *gin.HandlerFunc {
	return func(c *gin.Context) {
		//	1. set a context for 100 seconds
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User
		//	2. Bind the http body with user model
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		//	3. get the user from usercollections
		err := userCollection.FindOne(ctx, bson.M{"email": *user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "The email or password is incorrect"})
			return
		}
		//	4. Check whether the password is valid or not
		isPasswordValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
	}
}

func GetUsers()

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")
		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
