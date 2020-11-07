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
	"sort"
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

type Recommendation struct {
	ID uuid.UUID
	Overlaps uint
}

func GetMatches(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	tags, err := database.GetTagsForUser(user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Failed to request tags from database:", err)
		return
	}
	usersMap := make(map[uuid.UUID]uint)
	for _, v := range tags {
		users, err := database.FindUsersForTag(v.Tag)
		if err == sql.ErrNoRows {
			continue
		} else if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Couldn't request users from database:", err)
			return
		}
		for _, u := range users {
			_, err := database.FindMatch(user, u)
			if err == sql.ErrNoRows {
				if u == user {
					continue
				}
				usersMap[u]++
			} else if err != nil {
				ctx.JSON(http.StatusInternalServerError, InternalServerError)
				log.Println("Failed obtaining match from database:", err)
				return
			}
		}
	}
	var recommendations []Recommendation
	for k, v := range usersMap {
		recommendations = append(recommendations, Recommendation{
			ID: k,
			Overlaps: v,
		})
	}
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].Overlaps > recommendations[j].Overlaps
	})
	users := Users{Users: []Profile{}}
	for _, v := range recommendations {
		profile, err := database.FindProfileByID(v.ID)
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

			pictures, err := database.GetPicturesForUser(v.ID)
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

			tags, err := database.GetTagsForUser(v.ID)
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

func DiscardMatch(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	match := database.Match{
		Matcher: user,
		Matchee: id,
		Likes: false,
	}
	err = match.Insert()
	if err != nil {
		log.Println("Cannot insert match into database:", err)
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		return
	}
	ctx.Status(http.StatusOK)
}

type Matched struct {
	Matched bool
}

func AcceptMatch(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	match := database.Match{
		Matcher: user,
		Matchee: id,
		Likes: true,
	}
	err = match.Insert()
	if err != nil {
		log.Println("Cannot insert match into database:", err)
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		return
	}
	m, err := database.FindMatch(id, user)
	if err == sql.ErrNoRows {
		ctx.JSON(http.StatusOK, Matched{false})
	} else if err != nil {
		log.Println("Cannot find match in database:", err)
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		return
	} else {
		if m.Likes {
			ctx.JSON(http.StatusOK, Matched{true})
		} else {
			ctx.JSON(http.StatusOK, Matched{false})
		}
	}
}

type Matches struct {
	Mutual []Profile
	Incoming []Profile
}

func GetMatched(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	matches, err := database.FindMatchesForMatchee(user)
	if err != nil {
		log.Println("Cannot find matches in database:", err)
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		return
	}
	res := Matches{
		Mutual: []Profile{},
		Incoming: []Profile{},
	}
	for _, v := range matches {
		if v.Matcher == v.Matchee {
			continue
		}
		matchBack, err := database.FindMatch(user, v.Matcher)
		if err != nil && err != sql.ErrNoRows {
			log.Println("Cannot find match in database:", err)
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		notMatched := err == sql.ErrNoRows
		profile, err := database.FindProfileByID(v.Matcher)
		if err == sql.ErrNoRows {
			continue
		} else if err != nil {
			log.Println("Cannot find profile in database:", err)
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			return
		}
		age := GetAge(profile.BirthDate)
		if age < 0 {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("User", v, "has invalid birthdate")
			return
		}

		resultProfile := Profile{
			ID:        profile.User,
			FirstName: profile.FirstName,
			LastName:  profile.LastName,
			Age:       age,
			Bio:       profile.Bio,
			Pictures:  []PictureID{},
			Tags:      []string{},
		}

		pictures, err := database.GetPicturesForUser(v.Matcher)
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

		tags, err := database.GetTagsForUser(v.Matcher)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, InternalServerError)
			log.Println("Failed to request tags from database:", err)
			return
		}
		for _, v := range tags {
			resultProfile.Tags = append(resultProfile.Tags, v.Tag)
		}
		if notMatched {
			res.Incoming = append(res.Incoming, resultProfile)
		} else if matchBack.Likes {
			res.Mutual = append(res.Mutual, resultProfile)
		}
	}
	ctx.JSON(http.StatusOK, res)
}

func GetTags(ctx *gin.Context) {

}

func GetTagDetails(ctx *gin.Context) {

}

type Post struct {
	Sender uuid.UUID
	Text string
}

type Posts struct {
	Posts []Post
}

func GetCommunityPosts(ctx *gin.Context) {
	tag := ctx.Param("tag")
	posts, err := database.GetPostsForTag(tag)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Failed to request posts from database:", err)
		return
	}
	res := &Posts{}
	for _, v := range posts {
		res.Posts = append(res.Posts, Post{
			Sender: v.Sender,
			Text:   v.Contents,
		})
	}
	ctx.JSON(http.StatusOK, res)
}

type NewPost struct {
	Contents string
}

func PostToCommunity(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	tag := ctx.Param("tag")
	form := &NewPost{}
	err := ctx.BindJSON(form)
	if err != nil {
		log.Println("Failed to bind JSON:", err)
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		return
	}
	post := &database.Post{
		Tag: tag,
		Sender: user,
		Contents: form.Contents,
	}
	err = post.Insert()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Failed to insert post into database:", err)
		return
	}
	ctx.Status(http.StatusOK)
}

type Message struct {
	Sender uuid.UUID
	Target uuid.UUID
	Text string
}

type Messages struct {
	Messages []Message
}

func QueryDirectMessages(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	messages, err := database.GetMessagesInConversation(user, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Failed to get messages from database:", err)
		return
	}
	res := Messages{}
	for _, v := range messages {
		res.Messages = append(res.Messages, Message{
			Sender: v.Sender,
			Target: v.Target,
			Text:   v.Contents,
		})
	}
	ctx.JSON(http.StatusOK, res)
}

type MessageText struct {
	Text string
}

func SendDirectMessage(ctx *gin.Context) {
	_user, _ := ctx.Get("UserID")
	user := _user.(uuid.UUID)
	_id := ctx.Param("id")
	id, err := uuid.Parse(_id)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, InvalidID)
		return
	}
	form := &MessageText{}
	err = ctx.BindJSON(form)
	if err != nil {
		ctx.JSON(http.StatusUnprocessableEntity, BodyParseFailed)
		log.Println("Body parse failed:", err)
		return
	}
	message := database.Message{
		Sender:   user,
		Target:   id,
		Contents: form.Text,
	}
	err = message.Insert()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Failed to insert message into database:", err)
		return
	}
	ctx.Status(http.StatusOK)
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