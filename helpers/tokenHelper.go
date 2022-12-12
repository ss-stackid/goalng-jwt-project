package helpers

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ss-stackid/golang-jwt-project/database"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"os"
	"time"
)

type SignedDetails struct {
	Email     string
	FirstName string
	LastName  string
	Uid       string
	UserType  string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var SECRET_KEY = os.Getenv("SECRET_KEY")

func GenerateAllToken(email, firstName, lastName, uid, userType string) (token, refreshToken string, err error) {
	//	1. create newSignedClaim with 24 hour
	//	2. Create refreshSingedClaim with 136 hour
	//	3. Create newWithClaims for first object
	//	4. Create newWithClaims for second object
	//	5. return both

	claim := &SignedDetails{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Uid:       uid,
		UserType:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}
	refreshClaim := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}
	token, err = jwt.NewWithClaims(jwt.SigningMethodES256, claim).SignedString([]byte(SECRET_KEY))
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaim).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return "", "", err
	}
	return token, refreshToken, err
}
