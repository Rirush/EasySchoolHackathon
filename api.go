package main

import (
	"database/sql"
	"github.com/Rirush/EasySchoolHackathon/database"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type RegisterForm struct {
	Email string
	Password string
}

var EmailRegex = regexp.MustCompile("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])")

type RegisterResult struct {
	Token string `json:"token"`
}

func Register(ctx *gin.Context) {
	form := RegisterForm{}
	err := ctx.BindJSON(&form)
	if err != nil {
		log.Println("Failed to bind JSON:", err)
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		return
	}
	if !EmailRegex.MatchString(form.Email) {
		ctx.JSON(http.StatusBadRequest, EmailFormatInvalid)
		return
	}
	form.Email = strings.ToLower(form.Email)
	_, err = database.FindCredentialsByEmail(form.Email)
	if err == nil {
		ctx.JSON(http.StatusBadRequest, EmailAlreadyTaken)
		return
	}
	if err != sql.ErrNoRows {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't make request to database:", err)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't hash password:", err)
		return
	}
	creds := database.Credentials{
		Email: form.Email,
		Password: string(hash),
	}
	err = creds.Insert()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't insert credentials into database:", err)
		return
	}
	token, err := database.GenerateSession(creds.UUID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't generate new session token:", err)
		return
	}
	ctx.JSON(http.StatusOK, RegisterResult{
		Token: token.Token,
	})
}

func Authorize(ctx *gin.Context) {
	form := RegisterForm{}
	err := ctx.BindJSON(&form)
	if err != nil {
		log.Println("Failed to bind JSON:", err)
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		return
	}
	form.Email = strings.ToLower(form.Email)
	creds, err := database.FindCredentialsByEmail(form.Email)
	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusBadRequest, InvalidPassword)
		return
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't make request to database:", err)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(creds.Password), []byte(form.Password)); err != nil {
		ctx.JSON(http.StatusBadRequest, InvalidPassword)
		return
	}
	token, err := database.GenerateSession(creds.UUID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't generate new session token:", err)
		return
	}
	ctx.JSON(http.StatusOK, RegisterResult{
		Token: token.Token,
	})
}

type PictureID struct {
	ID uuid.UUID
	IsPrimary bool
}

type Profile struct {
	FirstName string
	LastName string
	Age int
	Pictures []PictureID
	Tags []string
}

func GetMyProfile(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	profile, err := database.FindProfileByID(user)
	if err == nil {
		age := GetAge(profile.BirthDate)
		if age < 0 {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("User", user, "has invalid birthdate")
			return
		}

		resultProfile := Profile{
			FirstName: profile.FirstName,
			LastName: profile.LastName,
			Age: age,
			Pictures: []PictureID{},
			Tags: []string{},
		}

		pictures, err := database.GetPicturesForUser(user)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Failed to request profile pictures from database:", err)
			return
		}
		for _, v := range pictures {
			resultProfile.Pictures = append(resultProfile.Pictures, PictureID{
				ID: v.UUID,
				IsPrimary: v.IsPrimary,
			})
		}

		tags, err := database.GetTagsForUser(user)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Failed to request tags from database:", err)
			return
		}
		for _, v := range tags {
			resultProfile.Tags = append(resultProfile.Tags, v.Tag)
		}

		ctx.JSON(http.StatusOK, resultProfile)
	} else if err == sql.ErrNoRows {
		ctx.JSON(http.StatusBadRequest, ProfileNotReady)
		return
	} else {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't request profile from database:", err)
		return
	}
}

type ProfileUpdate struct {
	FirstName string
	LastName string
	BirthDate string
}

func PostProfile(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	form := ProfileUpdate{}
	err := ctx.BindJSON(&form)
	if err != nil {
		log.Println("Failed to bind JSON:", err)
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		return
	}
	age := GetAge(form.BirthDate)
	if age < 0 {
		ctx.JSON(http.StatusBadRequest, InvalidBirthdate)
		return
	}
	profile, err := database.FindProfileByID(user)
	if err == nil {
		profile.FirstName = form.FirstName
		profile.LastName = form.LastName
		profile.BirthDate = form.BirthDate
		err = profile.Update()
		if err != nil {
			log.Println("Failed to update profile in database:", err)
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		ctx.Status(http.StatusOK)
	} else if err == sql.ErrNoRows {
		profile := database.Profile{
			User: user,
			FirstName: form.FirstName,
			LastName: form.LastName,
			BirthDate: form.BirthDate,
		}
		err := profile.Insert()
		if err != nil {
			log.Println("Failed to insert profile into database:", err)
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		ctx.Status(http.StatusOK)
	} else {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't request profile from database:", err)
		return
	}
}

func PostTags(ctx *gin.Context) {

}

func PostImage(ctx *gin.Context) {

}

func DeleteImage(ctx *gin.Context) {

}

func SetImageAsPrimary(ctx *gin.Context) {

}

func QueryProfilesByTag(ctx *gin.Context) {

}

func QueryProfileByID(ctx *gin.Context) {

}

func GetMatches(ctx *gin.Context) {

}

func DiscardMatch(ctx *gin.Context) {

}

func AcceptMatch(ctx *gin.Context) {

}

func GetTags(ctx *gin.Context) {

}

func GetTagDetails(ctx *gin.Context) {

}

func GetCommunityPosts(ctx *gin.Context) {

}

func PostToCommunity(ctx *gin.Context) {

}

func QueryDirectMessages(ctx *gin.Context) {

}

func SendDirectMessage(ctx *gin.Context) {

}

func OpenWebsocket(ctx *gin.Context) {

}

func GetImage(ctx *gin.Context) {

}