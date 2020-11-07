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
	ID uuid.UUID
	FirstName string
	LastName string
	Age int
	Bio string
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
			ID: profile.User,
			FirstName: profile.FirstName,
			LastName: profile.LastName,
			Age: age,
			Bio: profile.Bio,
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
	Bio string
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
		profile.Bio = form.Bio
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
			Bio: form.Bio,
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

type NewTags struct {
	Tags []string
}

func PostTags(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	form := NewTags{}
	err := ctx.BindJSON(&form)
	if err != nil {
		log.Println("Failed to bind JSON:", err)
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		return
	}
	err = database.SetTagsForUser(user, form.Tags)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't set tags for user:", err)
		return
	}
	ctx.Status(http.StatusOK)
}

type Image struct {
	Data []byte
}

type ImageSuccess struct {
	ID uuid.UUID
}

func PostImage(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	form := Image{}
	err := ctx.BindJSON(&form)
	if err != nil {
		log.Println("Failed to bind JSON:", err)
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		return
	}
	if len(form.Data) > 10 * 1024 * 1024 {
		ctx.JSON(http.StatusBadRequest, ImageTooBig)
		return
	}
	p, err := database.GetPicturesForUser(user)
	image := database.ProfilePicture{
		User:      user,
		Data:      form.Data,
		IsPrimary: false,
	}
	// it must return as error
	// yet it doesn't. how
	if len(p) == 0 && (err == nil || err == sql.ErrNoRows) {
		image.IsPrimary = true
	} else if err != nil && err != sql.ErrNoRows {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't obtain images from database:", err)
		return
	}
	err = image.Insert()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't insert image into database:", err)
		return
	}
	ctx.JSON(http.StatusOK, ImageSuccess{
		ID: image.UUID,
	})
}

func DeleteImage(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	pic, err := database.GetPictureByID(id)
	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusBadRequest, InvalidID)
		return
	} else if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't query image from database:", err)
		return
	}
	if pic.User != user {
		ctx.JSON(http.StatusBadRequest, InvalidID)
		return
	}
	err = pic.Delete()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't delete image from database:", err)
		return
	}
	if pic.IsPrimary {
		pics, err := database.GetPicturesForUser(user)
		if err == sql.ErrNoRows {
			ctx.Status(http.StatusOK)
			return
		} else if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Couldn't get images from database:", err)
			return
		}
		err = pics[0].SetPrimary()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Couldn't set image as primary in database:", err)
			return
		}
	}
	ctx.Status(http.StatusOK)
}

func SetImageAsPrimary(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	pic, err := database.GetPictureByID(id)
	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusBadRequest, InvalidID)
		return
	} else if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't query image from database:", err)
		return
	}
	if pic.User != user {
		ctx.JSON(http.StatusBadRequest, InvalidID)
		return
	}
	err = pic.SetPrimary()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't set image as primary in database:", err)
		return
	}
	ctx.Status(http.StatusOK)
}

type Users struct {
	Users []Profile
}

func QueryProfilesByTag(ctx *gin.Context) {
	tag := ctx.Param("tag")
	uuids, err := database.FindUsersForTag(tag)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't query users by tag from database:", err)
		return
	}
	users := Users{Users: []Profile{}}
	for _, v := range uuids {
		profile, err := database.FindProfileByID(v)
		if err == nil {
			age := GetAge(profile.BirthDate)
			if age < 0 {
				ctx.JSON(http.StatusInternalServerError, InternalServerError)
				log.Println("User", v, "has invalid birthdate")
				return
			}

			resultProfile := Profile{
				ID: profile.User,
				FirstName: profile.FirstName,
				LastName:  profile.LastName,
				Age:       age,
				Bio:       profile.Bio,
				Pictures:  []PictureID{},
				Tags:      []string{},
			}

			pictures, err := database.GetPicturesForUser(v)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, InternalServerError)
				log.Println("Failed to request profile pictures from database:", err)
				return
			}
			for _, v := range pictures {
				resultProfile.Pictures = append(resultProfile.Pictures, PictureID{
					ID:        v.UUID,
					IsPrimary: v.IsPrimary,
				})
			}

			tags, err := database.GetTagsForUser(v)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, InternalServerError)
				log.Println("Failed to request tags from database:", err)
				return
			}
			for _, v := range tags {
				resultProfile.Tags = append(resultProfile.Tags, v.Tag)
			}
			users.Users = append(users.Users, resultProfile)
		} else if err == sql.ErrNoRows {
			log.Println("User", v, "doesn't have a profile, yet has tags")
		} else {
			log.Println("Cannot obtain profile from database:", err)
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			return
		}
	}
	ctx.JSON(http.StatusOK, users)
}

func QueryProfileByID(ctx *gin.Context) {
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	profile, err := database.FindProfileByID(id)
	if err == nil {
		age := GetAge(profile.BirthDate)
		if age < 0 {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("User", id, "has invalid birthdate")
			return
		}

		resultProfile := Profile{
			ID: profile.User,
			FirstName: profile.FirstName,
			LastName:  profile.LastName,
			Age:       age,
			Bio:       profile.Bio,
			Pictures:  []PictureID{},
			Tags:      []string{},
		}

		pictures, err := database.GetPicturesForUser(id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Failed to request profile pictures from database:", err)
			return
		}
		for _, v := range pictures {
			resultProfile.Pictures = append(resultProfile.Pictures, PictureID{
				ID:        v.UUID,
				IsPrimary: v.IsPrimary,
			})
		}

		tags, err := database.GetTagsForUser(id)
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
		ctx.JSON(http.StatusNotFound, InvalidID)
	} else {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't request user profile from database:", err)
	}
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
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	pic, err := database.GetPictureByID(id)
	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusNotFound, InvalidID)
		return
	} else if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Couldn't query image from database:", err)
		return
	}
	ctx.JSON(http.StatusOK, Image{Data: pic.Data})
}