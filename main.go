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
	r.GET("/profile/me", Secure, GetMyProfile) // done
	r.POST("/profile/me", Secure, PostProfile) // done
	r.POST("/profile/me/tags", Secure, PostTags) // done
	r.POST("/profile/me/picture", Secure, PostImage) // done
	r.DELETE("/profile/me/picture/:id", Secure, DeleteImage) // done
	r.POST("/profile/me/picture/:id/primary", Secure, SetImageAsPrimary) // done

	// Profile queries:
	r.GET("/profiles/tag/:tag", Secure, QueryProfilesByTag) // done
	r.GET("/profile/id/:id", Secure, QueryProfileByID) // done

	// Tinder-like functionality:
	r.GET("/matches", Secure, GetMatches) // done
	r.POST("/match/discard/:id", Secure, DiscardMatch) // done
	r.POST("/match/accept/:id", Secure, AcceptMatch) // done
	r.GET("/matched", Secure, GetMatched) // done

	// Tag discovery:
	r.GET("/tags", Secure, GetTags) // ???
	r.GET("/tag/:tag", Secure, GetTagDetails) // ???

	// Community actions:
	r.GET("/community/:tag", Secure, GetCommunityPosts) // done
	r.POST("/community/:tag", Secure, PostToCommunity) // done

	// Direct messages:
	r.GET("/dm/:id", Secure, QueryDirectMessages) // done
	r.POST("/dm/:id", Secure, SendDirectMessage) // done

	// Server-side notification channel:
	r.GET("/ws", Secure, OpenWebsocket) // no

	// Image requesting:
	r.GET("/image/:id", Secure, GetImage)  // done

	go r.Run()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Exiting...")
	database.Close()
}
