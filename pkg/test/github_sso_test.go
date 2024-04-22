package test

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log"
	"testing"
)

func TestGithubSso(t *testing.T) {
	githubConfig := &oauth2.Config{
		ClientID:     "a89380772432d652a35b",
		ClientSecret: "032f16487a0d9866a9de4ebe0a6a22932ac8e404",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"user"},
		Endpoint:     github.Endpoint,
	}

	url := githubConfig.AuthCodeURL("state-token")

	log.Println(url)
}
