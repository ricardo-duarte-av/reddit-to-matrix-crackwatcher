package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	reddit "github.com/vartanbeno/go-reddit/v2/reddit"
	mautrix "maunium.net/go/mautrix"
)

// Config holds API keys and secrets
type Config struct {
	RedditClientID     string `json:"reddit_client_id"`
	RedditClientSecret string `json:"reddit_client_secret"`
	RedditUserAgent    string `json:"reddit_user_agent"`
	RedditUsername     string `json:"reddit_username"`
	RedditPassword     string `json:"reddit_password"`
	SubredditName      string `json:"subreddit_name"`
	IGDBClientID       string `json:"igdb_client_id"`
	IGDBClientSecret   string `json:"igdb_client_secret"`
	MatrixHomeserver   string `json:"matrix_homeserver"`
	MatrixUser         string `json:"matrix_user"`
	MatrixPassword     string `json:"matrix_password"`
	MatrixAccessToken  string `json:"matrix_access_token"`
	MatrixRoomID       string `json:"matrix_room_id"`
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}

func getMatrixClient(cfg *Config, configPath string) (*mautrix.Client, error) {
	var client *mautrix.Client
	var err error
	if cfg.MatrixAccessToken != "" {
		client, err = mautrix.NewClient(cfg.MatrixHomeserver, "", cfg.MatrixAccessToken)
		if err != nil {
			return nil, err
		}
	} else if cfg.MatrixUser != "" && cfg.MatrixPassword != "" {
		client, err = mautrix.NewClient(cfg.MatrixHomeserver, "", "")
		if err != nil {
			return nil, err
		}
		resp, err := client.Login(context.Background(), &mautrix.ReqLogin{
			Type:       "m.login.password",
			Identifier: mautrix.UserIdentifier{User: cfg.MatrixUser},
			Password:   cfg.MatrixPassword,
		})
		if err != nil {
			return nil, err
		}
		cfg.MatrixAccessToken = resp.AccessToken
		saveErr := saveConfig(configPath, cfg)
		if saveErr != nil {
			log.Printf("Warning: failed to save new access token to config: %v", saveErr)
		}
	} else {
		return nil, fmt.Errorf("no Matrix access token or user/pass provided")
	}
	return client, nil
}

// GameEntry represents a single game row from the Daily Releases table
type GameEntry struct {
	Name   string
	Group  string
	Stores string
	Review string
}

// extractGamesFromTable parses the Daily Releases table and returns game entries
func extractGamesFromTable(table string) []GameEntry {
	var games []GameEntry
	lines := strings.Split(table, "\n")
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		// Ignore update rows (first column contains 'Update')
		if strings.HasPrefix(fields[0], "Update") {
			continue
		}
		games = append(games, GameEntry{
			Name:   fields[0],
			Group:  fields[1],
			Stores: fields[2],
			Review: fields[3],
		})
	}
	return games
}

func monitorReddit(cfg *Config) {
	client, err := reddit.NewClient(reddit.Credentials{
		ID:       cfg.RedditClientID,
		Secret:   cfg.RedditClientSecret,
		Username: cfg.RedditUsername,
		Password: cfg.RedditPassword,
	}, reddit.WithUserAgent(cfg.RedditUserAgent))
	if err != nil {
		log.Fatalf("Failed to create Reddit client: %v", err)
	}

	seen := make(map[string]bool)
	for {
		posts, _, err := client.Subreddit.NewPosts(context.Background(), cfg.SubredditName, &reddit.ListOptions{Limit: 10})
		if err != nil {
			log.Printf("Error fetching posts: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		for _, post := range posts {
			if seen[post.ID] {
				continue
			}
			if strings.HasPrefix(post.Title, "Daily Releases ") {
				fmt.Printf("Found Daily Releases post: %s\n", post.Title)
				games := extractGamesFromTable(post.Body)
				for _, game := range games {
					fmt.Printf("Game: %+v\n", game)
				}
			}
			seen[post.ID] = true
		}
		time.Sleep(60 * time.Second)
	}
}

func main() {
	cfg, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	fmt.Println("Config loaded. Ready to start Reddit/IGDB/Matrix logic.")

	// Example: Initialize Matrix client and store token if needed
	_, err = getMatrixClient(cfg, "config.json")
	if err != nil {
		log.Fatalf("Failed to initialize Matrix client: %v", err)
	}

	// Start Reddit monitoring
	monitorReddit(cfg)
}
