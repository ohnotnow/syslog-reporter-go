package reporter

// HTML rendering for the daily digest email (ait srg-kOKT9). The body
// markdown from EmailBody() becomes the text/html alternative; the
// text/plain alternative stays the markdown verbatim, so text-only clients
// keep the pre-HTML experience unchanged.
//
// goldmark is configured deliberately narrowly:
//   - GFM only; NO Typographer, which would smarten hyphens into the
//     dashes this project bans from all output;
//   - no html.WithUnsafe(): the digest embeds LLM-written prose, so any
//     raw HTML in it must be escaped, never passed through.
//
// The shell keeps the management report's palette but styles semantic
// tags via a <style> block rather than inlining: Outlook's Word renderer
// will show it plainer yet still readable (owner accepted the trade-off,
// 2026-08-29; revisit with a per-tag inlining pass only if the team
// actually lives in desktop Outlook).

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"
)

//go:embed templates/email_digest.html
var digestTemplateSrc string

var digestTemplate = template.Must(template.New("digest").Parse(digestTemplateSrc))

// codeCommentRenderer replaces goldmark's code-block renderer so that
// '# comment' lines get a <span class="cmt"> wrapper: the sysadmin
// reads the story of the investigation in the comments, separately from
// the long command strings (owner request, 2026-08-29). Command lines
// keep their whitespace exactly; comment lines are left-trimmed for
// display, since any leading space on them is model padding, not shell.
type codeCommentRenderer struct{}

func (r *codeCommentRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindFencedCodeBlock, r.render)
	reg.Register(ast.KindCodeBlock, r.render)
}

func (r *codeCommentRenderer) render(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	w.WriteString("<pre><code>")
	lines := node.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		line := string(seg.Value(source))
		if display := strings.TrimLeft(line, " \t"); strings.HasPrefix(display, "#") {
			w.WriteString(`<span class="cmt">`)
			w.Write(util.EscapeHTML([]byte(strings.TrimRight(display, "\n"))))
			w.WriteString("</span>\n")
		} else {
			w.Write(util.EscapeHTML([]byte(line)))
		}
	}
	w.WriteString("</code></pre>\n")
	return ast.WalkSkipChildren, nil
}

var digestMarkdown = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(
		renderer.WithNodeRenderers(util.Prioritized(&codeCommentRenderer{}, 500)),
	),
)

type digestView struct {
	Body    template.HTML
	Version string
}

// RenderDigestHTML converts the digest markdown into a self-contained
// HTML document for the email's text/html alternative.
func RenderDigestHTML(markdown, version string) (string, error) {
	var body bytes.Buffer
	if err := digestMarkdown.Convert([]byte(markdown), &body); err != nil {
		return "", err
	}
	var page bytes.Buffer
	err := digestTemplate.Execute(&page, digestView{
		Body:    template.HTML(body.String()),
		Version: version,
	})
	if err != nil {
		return "", err
	}
	return page.String(), nil
}
