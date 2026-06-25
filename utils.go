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

var (
	mdLinkRe  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	mdEmphRe  = regexp.MustCompile(`(\*\*|\*|__|_|~~|` + "`" + `)`)
	mdSpaceRe = regexp.MustCompile(`\s+`)

	// editionSuffixRe matches a single trailing edition/version/release
	// qualifier. It is applied repeatedly so stacked suffixes like
	// "Deluxe Edition Hypervisor" are removed one token at a time.
	//
	// Only a fixed whitelist of qualifiers is stripped — arbitrary trailing
	// words are left intact so real titles like "Workers and Resources Soviet
	// Republic" and DLC names like "Frostpunk 2 Breach of Trust" survive.
	editionSuffixRe = regexp.MustCompile(`(?i)\s+(` +
		`hypervisor|` +
		`(collector'?s|deluxe|digital deluxe|ultimate|definitive|enhanced|special|gold|premium|anniversary|complete|explorer|standard|game of the year)\s+edition|` +
		`sammleredition|` +
		`director'?s\s+cut|` +
		`game of the year edition|goty|` +
		`remastered|remaster|` +
		`enhanced|complete|` +
		`uhd` +
		`)$`)
)

// cleanGameName strips Markdown formatting (links, bold/italic/strikethrough,
// inline code) and trailing edition/release qualifiers from a game name so it
// can be used as a plain IGDB search query.
func cleanGameName(name string) string {
	// [text](url) -> text
	name = mdLinkRe.ReplaceAllString(name, "$1")
	// remove emphasis/code markers
	name = mdEmphRe.ReplaceAllString(name, "")
	// collapse whitespace
	name = mdSpaceRe.ReplaceAllString(name, " ")
	name = strings.TrimSpace(name)

	// Strip trailing edition/release qualifiers iteratively. Stop if stripping
	// would empty the title (e.g. a game literally named "Complete").
	for {
		stripped := strings.TrimSpace(editionSuffixRe.ReplaceAllString(name, ""))
		if stripped == name || stripped == "" {
			break
		}
		name = stripped
	}
	return name
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
