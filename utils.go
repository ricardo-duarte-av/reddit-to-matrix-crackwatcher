package main

import (
	"fmt"
	"regexp"
	"strings"
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
