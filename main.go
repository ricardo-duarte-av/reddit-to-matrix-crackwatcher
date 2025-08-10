package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"bytes"
	"database/sql"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"
	
	igdb "github.com/Henry-Sarabia/igdb/v2"
	"github.com/buckket/go-blurhash"
	"github.com/disintegration/imaging"
	_ "github.com/mattn/go-sqlite3"
	reddit "github.com/vartanbeno/go-reddit/v2/reddit"
	_ "golang.org/x/image/webp"
	mautrix "maunium.net/go/mautrix"
	mautrixEvent "maunium.net/go/mautrix/event"
	mautrixID "maunium.net/go/mautrix/id"
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
	return os.WriteFile(path, data, 0600)
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

// extractGamesFromTable parses the Daily Releases Markdown table and returns game entries
func extractGamesFromTable(body string) []GameEntry {
	var games []GameEntry
	lines := strings.Split(body, "\n")
	inTable := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inTable {
			if strings.Contains(trimmed, "| Game | Group | Stores | Review |") {
				inTable = true
				continue // skip header
			}
			continue
		}
		// End of table: next header, empty line, or start of updates
		if trimmed == "" || strings.Contains(trimmed, "| Update | Group | Stores | Reviews |") {
			break
		}
		if strings.HasPrefix(trimmed, "| :") || strings.HasPrefix(trimmed, "|:--") || strings.HasPrefix(trimmed, "| ---") {
			continue // skip markdown separator
		}
		if !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
			continue // skip non-table lines
		}
		fields := strings.Split(trimmed, "|")
		if len(fields) < 6 { // because of leading/trailing pipes, expect at least 6 fields
			continue
		}
		// fields[0] and fields[len-1] are empty due to leading/trailing pipe
		name := strings.TrimSpace(fields[1])
		group := strings.TrimSpace(fields[2])
		stores := strings.TrimSpace(fields[3])
		review := strings.TrimSpace(fields[4])
		games = append(games, GameEntry{
			Name:   name,
			Group:  group,
			Stores: stores,
			Review: review,
		})
	}
	return games
}

func monitorReddit(cfg *Config, db *sql.DB, matrixClient *mautrix.Client) {
	client, err := reddit.NewClient(reddit.Credentials{
		ID:       cfg.RedditClientID,
		Secret:   cfg.RedditClientSecret,
		Username: cfg.RedditUsername,
		Password: cfg.RedditPassword,
	}, reddit.WithUserAgent(cfg.RedditUserAgent))
	if err != nil {
		log.Fatalf("Failed to create Reddit client: %v", err)
	}

    igdbClient, err := getIGDBClient(cfg)
    if err != nil {
        log.Printf("Failed to initialize IGDB client: %v", err)
        return
    }

	for {
		log.Println("Fetching new posts from Reddit...")
		posts, _, err := client.Subreddit.NewPosts(context.Background(), cfg.SubredditName, &reddit.ListOptions{Limit: 10})
		if err != nil {
			log.Printf("Error fetching posts: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		for _, post := range posts {
			if !strings.HasPrefix(strings.ToLower(post.Title), "daily release") {
				continue
			}
			log.Printf("Found candidate post: %s (ID: %s)", post.Title, post.ID)
			processed, err := isPostProcessed(db, post.ID)
			if err != nil {
				log.Printf("DB error: %v", err)
				continue
			}
			if processed {
				log.Printf("Post already processed: %s", post.ID)
				continue
			}
			log.Printf("Processing new post: %s", post.ID)
			// Extract and send game table
			games := extractGamesFromTable(post.Body)
			if len(games) == 0 {
				log.Printf("No games found in post: %s", post.Title)
				fmt.Println("--- Post Body Debug ---\n" + post.Body + "\n--- End Post Body ---")
				markPostProcessed(db, post.ID)
				continue
			}
			// Format table for Matrix
			tableMsg := "[b]Daily Releases[/b]\n\nGame | Group | Stores | Review\n--- | --- | --- | ---\n"
			for _, game := range games {
				tableMsg += fmt.Sprintf("%s | %s | %s | %s\n", game.Name, game.Group, game.Stores, game.Review)
			}
			log.Printf("Sending game table to Matrix for post: %s", post.ID)
			err = sendMatrixText(matrixClient, cfg.MatrixRoomID, tableMsg)
			if err != nil {
				log.Printf("Matrix send error: %v", err)
			}
			// For each game, query IGDB and send info/screenshots
			for _, game := range games {
				log.Printf("Querying IGDB for game: %s", game.Name)
				igdbInfo, err := fetchIGDBInfo(igdbClient, game.Name)
				if err != nil {
					log.Printf("IGDB lookup failed for %s: %v", game.Name, err)
					continue
				}
				// Send game info
				msg := fmt.Sprintf("[b]%s[/b]\n[URL=%s]IGDB Link[/URL]\nDate: %d\n\n%s\n\n%s", igdbInfo.Title, igdbInfo.IGDBURL, igdbInfo.Date, igdbInfo.Summary, igdbInfo.Storyline)
				log.Printf("Sending IGDB info to Matrix for game: %s", igdbInfo.Title)
				err = sendMatrixText(matrixClient, cfg.MatrixRoomID, msg)
				if err != nil {
					log.Printf("Matrix send error: %v", err)
				}
				// Send cover
				if igdbInfo.CoverURL != "" {
					log.Printf("Sending cover image to Matrix for game: %s", igdbInfo.Title)
					postIGDBImageToMatrix(matrixClient, cfg.MatrixRoomID, igdbInfo.CoverURL, fmt.Sprintf("%s cover", igdbInfo.Title))
				}
				// Send screenshots
				for _, screenshot := range igdbInfo.Screenshots {
					log.Printf("Sending screenshot to Matrix for game: %s", igdbInfo.Title)
					postIGDBImageToMatrix(matrixClient, cfg.MatrixRoomID, screenshot, fmt.Sprintf("%s screenshot", igdbInfo.Title))
				}
			}
			// Mark post as processed
			log.Printf("Marking post as processed: %s", post.ID)
			markPostProcessed(db, post.ID)
		}
		log.Println("Reddit monitoring cycle complete. Sleeping...")
		time.Sleep(60 * time.Second)
	}
}

// IGDBGameInfo holds the info we want from IGDB
type IGDBGameInfo struct {
	Title       string
	Date        int64
	Summary     string
	Storyline   string
	IGDBURL     string
	CoverURL    string
	Screenshots []string
}

func fetchIGDBInfo(client *igdb.Client, name string) (*IGDBGameInfo, error) {
	games, err := client.Games.Search(name, igdb.SetFields("name,first_release_date,summary,storyline,slug,cover,screenshots"), igdb.SetLimit(1))
	if err != nil || len(games) == 0 {
		return nil, fmt.Errorf("game not found or error: %v", err)
	}
	g := games[0]
	info := &IGDBGameInfo{
		Title:     g.Name,
		Date:      int64(g.FirstReleaseDate),
		Summary:   g.Summary,
		Storyline: g.Storyline,
		IGDBURL:   fmt.Sprintf("https://www.igdb.com/games/%s", g.Slug),
	}
	// Fetch cover if present
	if g.Cover != 0 {
		cover, err := client.Covers.Get(g.Cover)
		if err == nil && cover != nil {
			info.CoverURL = "https://images.igdb.com/igdb/image/upload/t_cover_big/" + cover.ImageID + ".jpg"
		}
	}
	// Fetch screenshots if present
	for _, id := range g.Screenshots {
		sc, err := client.Screenshots.Get(id)
		if err == nil && sc != nil {
			info.Screenshots = append(info.Screenshots, "https://images.igdb.com/igdb/image/upload/t_screenshot_big/"+sc.ImageID+".jpg")
		}
	}
	return info, nil
}

type IGDBAuthTransport struct {
    Token     string
    ClientID  string
    Transport http.RoundTripper
}

func (t *IGDBAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    req.Header.Set("Authorization", "Bearer "+t.Token)
    req.Header.Set("Client-ID", t.ClientID)
    return t.Transport.RoundTrip(req)
}

func getIGDBClient(cfg *Config) (*igdb.Client, error) {
    token, err := getIGDBAccessToken(cfg.IGDBClientID, cfg.IGDBClientSecret)
    if err != nil {
        return nil, err
    }
    httpClient := &http.Client{
        Transport: &IGDBAuthTransport{
            Token:    token,
            ClientID: cfg.IGDBClientID,
            Transport: http.DefaultTransport,
        },
    }
    return igdb.NewClient(cfg.IGDBClientID, "", httpClient), nil
}

func getIGDBAccessToken(clientID, clientSecret string) (string, error) {
    url := "https://id.twitch.tv/oauth2/token"
    data := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials", clientID, clientSecret)
    resp, err := http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data))
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    var res struct {
        AccessToken string `json:"access_token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return "", err
    }
    return res.AccessToken, nil
}



// Example usage in monitorReddit (for each game):
// igdbClient, _ := getIGDBClient(cfg)
// info, err := fetchIGDBInfo(igdbClient, game.Name)
// if err == nil { fmt.Printf("IGDB: %+v\n", info) }

// downloadImage downloads an image from a URL and returns the image.Image and its bytes
// downloadImage downloads an image from a URL and returns the image.Image and its bytes and format
func downloadImage(url string) (image.Image, []byte, string, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, nil, "", err
    }
    defer resp.Body.Close()
    imgBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, nil, "", err
    }

    // Try to decode using standard image.Decode
    img, format, err := image.Decode(bytes.NewReader(imgBytes))
    if err == nil {
        return img, imgBytes, format, nil
    }

    // Try decoding as WebP
    img, errWebp := webp.Decode(bytes.NewReader(imgBytes))
    if errWebp == nil {
        return img, imgBytes, "webp", nil
    }

    // Try JPEG explicitly
    img, errJpeg := jpeg.Decode(bytes.NewReader(imgBytes))
    if errJpeg == nil {
        return img, imgBytes, "jpeg", nil
    }

    // Try PNG explicitly
    img, errPng := png.Decode(bytes.NewReader(imgBytes))
    if errPng == nil {
        return img, imgBytes, "png", nil
    }

    // If all decoders fail, return the error from image.Decode
    return nil, nil, "", err
}

// generateThumbnail resizes the image to the given width and height
func generateThumbnail(img image.Image, width, height int) image.Image {
	return imaging.Resize(img, width, height, imaging.Lanczos)
}

// encodeImage encodes an image.Image to bytes in the given format
func encodeImage(img image.Image, format string) ([]byte, error) {
	buf := new(bytes.Buffer)
	switch format {
	case "jpeg":
		if err := jpeg.Encode(buf, img, nil); err != nil {
			return nil, err
		}
	case "png":
		if err := png.Encode(buf, img); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
	return buf.Bytes(), nil
}

// calcBlurhash calculates the blurhash for an image.Image
func calcBlurhash(img image.Image) (string, error) {
	return blurhash.Encode(4, 3, img)
}

// MatrixImageInfo is a struct for Matrix image info
type MatrixImageInfo struct {
	Mimetype      string                 `json:"mimetype,omitempty"`
	Size          int                    `json:"size,omitempty"`
	W             int                    `json:"w,omitempty"`
	H             int                    `json:"h,omitempty"`
	ThumbnailURL  string                 `json:"thumbnail_url,omitempty"`
	ThumbnailInfo *MatrixImageInfo       `json:"thumbnail_info,omitempty"`
	Additional    map[string]interface{} `json:"-"`
}

// uploadToMatrix uploads an image to Matrix and returns the MXC URL and info
func uploadToMatrix(client *mautrix.Client, filename string, imgBytes []byte, mimetype string, width, height int) (string, *MatrixImageInfo, error) {
	req := mautrix.ReqUploadMedia{
		ContentBytes: imgBytes,
		ContentType:  mimetype,
		FileName:     filename,
	}
	uploadResp, err := client.UploadMedia(context.Background(), req)
	if err != nil {
		return "", nil, err
	}
	info := &MatrixImageInfo{
		Mimetype: mimetype,
		Size:     len(imgBytes),
		W:        width,
		H:        height,
	}
	return uploadResp.ContentURI.String(), info, nil
}

// sendMatrixImage sends an m.image event to the Matrix room
func sendMatrixImage(client *mautrix.Client, roomID, caption, filename string, imgURL, thumbURL string, imgInfo, thumbInfo *MatrixImageInfo, blurhash string) error {
	imgInfo.ThumbnailURL = thumbURL
	imgInfo.ThumbnailInfo = thumbInfo
	if blurhash != "" {
		if imgInfo.Additional == nil {
			imgInfo.Additional = map[string]interface{}{}
		}
		imgInfo.Additional["xyz.amorgan.blurhash"] = blurhash
	}
	content := map[string]interface{}{
		"msgtype":  "m.image",
		"body":     caption,
		"url":      imgURL,
		"info":     imgInfo,
		"filename": filename,
	}
	for k, v := range imgInfo.Additional {
		content[k] = v
	}
	_, err := client.SendMessageEvent(context.Background(), mautrixID.RoomID(roomID), mautrixEvent.EventMessage, content)
	return err
}

// sendMatrixText sends a plain text message to Matrix
func sendMatrixText(client *mautrix.Client, roomID, msg string) error {
	content := map[string]interface{}{
		"msgtype": "m.text",
		"body":    msg,
	}
	_, err := client.SendMessageEvent(context.Background(), mautrixID.RoomID(roomID), mautrixEvent.EventMessage, content)
	return err
}

// postIGDBImageToMatrix downloads, thumbs, blurhashes, uploads, and posts an image to Matrix
func postIGDBImageToMatrix(client *mautrix.Client, roomID, imgURL, caption string) {
	img, imgBytes, format, err := downloadImage(imgURL)
	if err != nil {
		log.Printf("Failed to download image: %v", err)
		return
	}
	thumb := generateThumbnail(img, 225, 300)
	thumbBytes, _ := encodeImage(thumb, format)
	blur, _ := calcBlurhash(thumb)
	imgMimetype := "image/" + format
	thumbMimetype := imgMimetype
	imgURLMXC, imgInfo, err := uploadToMatrix(client, caption+".webp", imgBytes, imgMimetype, img.Bounds().Dx(), img.Bounds().Dy())
	if err != nil {
		log.Printf("Failed to upload image: %v", err)
		return
	}
	thumbURLMXC, thumbInfo, err := uploadToMatrix(client, caption+"_thumb.webp", thumbBytes, thumbMimetype, thumb.Bounds().Dx(), thumb.Bounds().Dy())
	if err != nil {
		log.Printf("Failed to upload thumbnail: %v", err)
		return
	}
	err = sendMatrixImage(client, roomID, caption, caption+".webp", imgURLMXC, thumbURLMXC, imgInfo, thumbInfo, blur)
	if err != nil {
		log.Printf("Failed to send image event: %v", err)
	}
}

// DB schema: processed_posts(post_id TEXT PRIMARY KEY)
func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS processed_posts (post_id TEXT PRIMARY KEY)`)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func isPostProcessed(db *sql.DB, postID string) (bool, error) {
	var id string
	err := db.QueryRow(`SELECT post_id FROM processed_posts WHERE post_id = ?`, postID).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func markPostProcessed(db *sql.DB, postID string) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO processed_posts (post_id) VALUES (?)`, postID)
	return err
}

func main() {
	log.Println("Starting reddit-to-matrix-crackwatcher...")
	cfg, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Println("Config loaded.")

	// Example: Initialize Matrix client and store token if needed
	_, err = getMatrixClient(cfg, "config.json")
	if err != nil {
		log.Fatalf("Failed to initialize Matrix client: %v", err)
	}

	// Initialize DB
	db, err := initDB("processed_posts.db")
	if err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}
	log.Println("SQLite DB initialized.")
	defer db.Close()

	// Start Reddit monitoring
	matrixClient, err := getMatrixClient(cfg, "config.json")
	if err != nil {
		log.Fatalf("Failed to get Matrix client for monitoring: %v", err)
	}
	log.Println("Matrix client initialized.")
	monitorReddit(cfg, db, matrixClient)
}
