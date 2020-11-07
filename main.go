package main

import (
	"github.com/Rirush/EasySchoolHackathon/database"
	"github.com/gin-gonic/gin"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	err := database.LoadDatabase("test.db")
	if err != nil {
		log.Println("Failed to load database:", err)
		return
	}

	r := gin.Default()

	// Authentication:
	r.POST("/register", Register) // done
	r.POST("/authorize", Authorize) // done

	// Current profile management:
	r.GET("/profile/me", Secure, GetMyProfile)
	r.POST("/profile/me", Secure, PostProfile)
	r.POST("/profile/me/tags", Secure, PostTags)
	r.POST("/profile/me/picture", Secure, PostImage)
	r.DELETE("/profile/me/picture/:id", Secure, DeleteImage)
	r.POST("/profile/me/picture/:id/primary", Secure, SetImageAsPrimary)

	// Profile queries:
	r.GET("/profiles/tag/:tag", Secure, QueryProfilesByTag)
	r.GET("/profile/id/:id", Secure, QueryProfileByID)

	// Tinder-like functionality:
	r.GET("/matches", Secure, GetMatches)
	r.POST("/match/discard/:id", Secure, DiscardMatch)
	r.POST("/match/accept/:id", Secure, AcceptMatch)

	// Tag discovery:
	r.GET("/tags", Secure, GetTags)
	r.GET("/tag/:tag", Secure, GetTagDetails)

	// Community actions:
	r.GET("/community/:tag", Secure, GetCommunityPosts)
	r.POST("/community/:tag", Secure, PostToCommunity)

	// Direct messages:
	r.GET("/dm/:id", Secure, QueryDirectMessages)
	r.POST("/dm/:id", Secure, SendDirectMessage)

	// Server-side notification channel:
	r.GET("/ws", Secure, OpenWebsocket)

	// Image requesting:
	r.GET("/image/:id", Secure, GetImage)

	go r.Run()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Exiting...")
	database.Close()
}
