package main

import (
	"fmt"
	"regexp"
	"strings"
        "html"
        "time"
)

// markdownTableToHTML converts a Markdown-like table into an HTML table
func markdownTableToHTML(md string) string {
	lines := strings.Split(md, "\n")
	var html strings.Builder

	html.WriteString("<table>\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip the separator row
		if strings.HasPrefix(line, "---") || strings.Contains(line, "| ---") {
			continue
		}

		// Detect and skip bold title lines (like [b]Daily Releases[/b])
		if strings.HasPrefix(line, "[b]") && strings.HasSuffix(line, "[/b]") {
			html.WriteString(fmt.Sprintf("<caption>%s</caption>\n", strings.TrimSuffix(strings.TrimPrefix(line, "[b]"), "[/b]")))
			continue
		}

		// Split by | into cells
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
			parts[i] = convertLinks(parts[i])
		}

		// Header row
		if strings.Contains(strings.ToLower(parts[0]), "game") &&
			strings.Contains(strings.ToLower(parts[len(parts)-1]), "review") {
			html.WriteString("  <tr>")
			for _, cell := range parts {
				html.WriteString("<th>" + cell + "</th>")
			}
			html.WriteString("</tr>\n")
			continue
		}

		// Normal row
		html.WriteString("  <tr>")
		for _, cell := range parts {
			html.WriteString("<td>" + cell + "</td>")
		}
		html.WriteString("</tr>\n")
	}

	html.WriteString("</table>")
	return html.String()
}

// convertLinks turns [text](url) into <a href="url">text</a>
func convertLinks(s string) string {
	re := regexp.MustCompile(`\[(.*?)\]\((.*?)\)`)
	return re.ReplaceAllString(s, `<a href="$2">$1</a>`)
}

// format IGDB info to a Matrix message
func formatIGDBToHTML(info *IGDBGameInfo) (plainBody string, htmlBody string) {
    // Format date
    date := time.Unix(info.Date, 0).Format("2006-01-02") // YYYY-MM-DD

    // Escape all user-provided text for safety
    title := html.EscapeString(info.Title)
    url := html.EscapeString(info.IGDBURL)
    summary := html.EscapeString(info.Summary)
    storyline := html.EscapeString(info.Storyline)

    // Plain text fallback
    plainBody = fmt.Sprintf("%s\n%s\nDate: %s", title, url, date)
    if summary != "" {
        plainBody += "\n\nSummary: " + summary
    }
    if storyline != "" {
        plainBody += "\n\nStoryline: " + storyline
    }

    // HTML version
    htmlBody = fmt.Sprintf(`<a href="%s">%s</a><br>Date: %s`, url, title, date)
    if summary != "" {
        htmlBody += fmt.Sprintf(`<br><br><b>Summary:</b> %s`, summary)
    }
    if storyline != "" {
        htmlBody += fmt.Sprintf(`<br><br><b>Storyline:</b> %s`, storyline)
    }

    return plainBody, htmlBody
}
