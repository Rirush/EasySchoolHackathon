package main

import (
	"database/sql"
	"github.com/Rirush/EasySchoolHackathon/database"
	"github.com/gin-gonic/gin"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	BodyParseFailed = Error{
		Code: "BODY_PARSE_FAILED",
		Description: "Couldn't parse request body as JSON",
	}
	EmailFormatInvalid = Error{
		Code: "INVALID_EMAIL",
		Description: "Provided email is invalid",
	}
	EmailAlreadyTaken = Error{
		Code: "EMAIL_TAKEN",
		Description: "Provided email has already been taken",
	}
	InternalServerError = Error{
		Code: "INTERNAL_SERVER_ERROR",
		Description: "Internal server error has occurred",
	}
	InvalidPassword = Error{
		Code: "INVALID_PASSWORD",
		Description: "Provided password is invalid",
	}
	InvalidToken = Error{
		Code: "INVALID_TOKEN",
		Description: "Provided token is invalid",
	}
	ProfileNotReady = Error{
		Code: "PROFILE_NOT_READY",
		Description: "This profile wasn't completed",
	}
	InvalidBirthdate = Error{
		Code: "INVALID_BIRTHDATE",
		Description: "Provided birthdate is invalid",
	}
)

type Error struct {
	Code string
	Description string
}

func GetAge(date string) int {
	splitBirthday := strings.Split(date, ".")
	if len(splitBirthday) != 3 {
		return -1
	}
	_day, _month, _year := splitBirthday[0], splitBirthday[1], splitBirthday[2]
	nyear, nmonth, nday := time.Now().Date()
	day, err := strconv.ParseUint(_day, 10, 64)
	if err != nil || day > 31 {
		return -1
	}
	month, err := strconv.ParseUint(_month, 10, 64)
	if err != nil || month > 12 {
		return -1
	}
	year, err := strconv.ParseUint(_year, 10, 64)
	if err != nil {
		return -1
	}
	if int(year) > nyear || (int(year) == nyear && time.Month(month) > nmonth) || (int(year) == nyear && time.Month(month) == nmonth && int(day) > nday) {
		return -1
	}
	birthday := time.Date(int(year), time.Month(month), int(day), 0, 0, 0, 0, time.UTC)
	today := time.Date(nyear, nmonth, nday, 0, 0, 0, 0, time.UTC)

	return int(math.Floor(today.Sub(birthday).Hours() / 24 / 365))
}

func Secure(ctx *gin.Context) {
	token := ctx.GetHeader("X-Auth-Token")
	user, err := database.ValidateSession(token)
	if err == nil {
		ctx.Set("UserID", user)
		ctx.Next()
	} else if err == sql.ErrNoRows {
		ctx.JSON(http.StatusUnauthorized, InvalidToken)
		ctx.Abort()
	} else {
		ctx.JSON(http.StatusInternalServerError, InternalServerError)
		log.Println("Token validation request failed:", err)
		ctx.Abort()
	}
}
