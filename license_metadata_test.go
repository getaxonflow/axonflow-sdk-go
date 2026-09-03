// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// The repository distributes under exactly one licence, and says so in exactly
// one way.
//
// # Why this test exists
//
// Seventeen files in this MIT-licensed SDK declared a different licence: four
// carried the platform's source-available identifier and thirteen carried a
// full Apache-2.0 prose block. LICENSE has read "MIT License" since the initial
// commit, so none of them was ever a relicence question -- they were simply
// wrong statements about files that were MIT all along. Nothing failed, nothing
// warned, and each wrong header was copied forward by the next file made from
// it: all thirteen Apache blocks are byte-identical.
//
// # The two rules, and how wide each one really is
//
// The identifier rule is the strong one, because it is closed under the syntax
// rather than over a list of phrasings: every SPDX identifier tag anywhere in
// the tree, in any case, must name MIT, whatever licence a future copy-paste
// brings with it. The prose rule is a backstop and is only as wide as
// forbiddenPhrases -- an enumerated list, therefore incomplete by construction,
// which is why it is not the rule this test leans on.
//
// Both are needed, and a mutant of each proves why: reverting LICENSE alone is
// invisible to the identifier rule because LICENSE carries no tag, and an
// Apache prose block is invisible to it for the same reason. That prose shape
// is exactly what thirteen of the seventeen files here had.
//
// # Two things learned the hard way, portable to the other SDKs
//
// The needles are assembled by concatenation, and the tag is never spelled out
// in this file in any case. A guard whose marker string collides with the prose
// beside it either fails against itself or has to exempt itself, and an
// exemption is a hole. The sibling Java guard caught its own documentation
// three times before this was settled.
//
// Absence of a declaration is deliberately NOT an error. A file with no header
// inside a repository with one LICENSE is unambiguous; a file declaring a
// DIFFERENT licence is the defect. Most .go files here carry no header and are
// left alone. Requiring a declaration to be PRESENT is a stronger and separate
// property from requiring none to CONTRADICT, and only the latter protects the
// licence.

package axonflow

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	licenseName = "MIT License"
	// Split so this file is not a hit for the scan it drives.
	spdxTag = "SPDX" + "-License-Identifier:"
)

// commentTerminators can follow an identifier on the same line. An identifier
// is read from a line of SOURCE and a block or markup comment closes after it.
// Comparing the raw remainder of the line would report a correctly-MIT file as
// a contradiction: a false positive, in the direction that gets a guard deleted
// rather than fixed.
var commentTerminators = []string{"*/", "-->", "#>", "--%>"}

// forbiddenPhrases is licence prose this repository must not be distributing
// under. Assembled piecewise; see the file comment. Enumerated, hence a
// backstop rather than the primary rule.
var forbiddenPhrases = []string{
	"Apache" + " License, Version 2.0",
	// The same licence without the "Version", which is how prose usually names
	// it and which the comma-bearing form does not contain as a substring.
	"Apache" + " License 2.0",
	"Business" + " Source License",
	"GNU" + " General Public License",
	"Mozilla" + " Public License",
}

// notSource are path SEGMENTS that are VCS metadata or dependency trees rather
// than this repository's own source. Matched segment-wise, not as a path
// prefix: this repo has four Go modules, and a prefix test would only ever
// exclude the root one.
//
// `vendor` and `node_modules` are a DELIBERATE, CATEGORICAL EXEMPTION, and
// saying so plainly matters because the rules below would otherwise read as
// covering them. A dependency tree is third-party code that legitimately keeps
// its own licence: measured on this repo, one `go mod vendor` produces 17 files
// of which 7 carry Apache prose and 15 carry a non-AxonFlow copyright notice.
// Scanning them would fail the guard on correct code the first time anyone
// vendored, which is how a guard gets deleted rather than fixed.
var notSource = []string{".git", "vendor", "node_modules"}

// copyrightNotice matches a line ASSERTING copyright ownership -- the word
// followed by an optional (c) and a year. Matching the bare word instead
// matches the MIT text's own "The above copyright notice ..." clause and every
// identifier in this file that contains it, which is how the first version of
// this rule failed against LICENSE and against itself.
var copyrightNotice = regexp.MustCompile(`(?i)copyright\s+(\(c\)\s*)?[0-9]{4}`)

// anchors are files that must appear in the scan. These are not a count -- a
// floor is a number someone tunes until it passes. Each anchor pins one root
// the walk claims to cover, so a walk that silently stopped short of examples/
// or runtime-e2e/ fails here rather than passing over an empty set.
var anchors = []string{
	"LICENSE",
	"README.md",
	"CHANGELOG.md",
	"go.mod",
	"axonflow.go",
	"execution.go",
	"x_client_id_header_test.go",
	"interceptors/anthropic.go",
	"examples/wcp-retry-idempotency/main.go",
	"scripts/lint-no-mocks-in-runtime-e2e.sh",
	"tests/heartbeat-real-stack/go.mod",
	".github/workflows/test.yml",
}

// declaredIdentifiers returns EVERY SPDX identifier declared on a line, in
// order; empty if the line declares none.
//
// Every occurrence, not the first. Reading only the first turns a false
// positive into a false NEGATIVE, which is the worse direction and the one that
// ships: a line reading `<!-- ...: MIT --> <!-- ...: Apache-2.0 -->` truncated
// at the first terminator reports as plain MIT, and the Apache declaration
// beside it passes the guard in silence.
//
// Case-insensitive because the file comment claims this rule is closed under
// the syntax, and a case-sensitive scan makes that claim false: a hand-written
// header spelling the tag in lower case walks straight past a guard whose own
// documentation says nothing gets past it. A guard narrower than its own
// comment is worse than a narrow guard, because the comment is what the next
// person relies on.
func declaredIdentifiers(line string) []string {
	var found []string
	lower := strings.ToLower(line)
	lowerTag := strings.ToLower(spdxTag)
	from := 0
	for {
		at := strings.Index(lower[from:], lowerTag)
		if at < 0 {
			return found
		}
		at += from
		valueStart := at + len(spdxTag)
		end := len(line)
		for _, terminator := range commentTerminators {
			if c := strings.Index(line[valueStart:], terminator); c >= 0 && valueStart+c < end {
				end = valueStart + c
			}
		}
		if n := strings.Index(lower[valueStart:], lowerTag); n >= 0 && valueStart+n < end {
			end = valueStart + n
		}
		found = append(found, strings.TrimSpace(line[valueStart:end]))
		from = valueStart
	}
}

func isNotSource(rel string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(rel), "/") {
		for _, skip := range notSource {
			if segment == skip {
				return true
			}
		}
	}
	return false
}

// tree returns every scannable file, keyed by its repository-relative path.
func tree(t *testing.T) map[string]string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	out := map[string]string{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if isNotSource(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func TestScanReachesEveryRoot(t *testing.T) {
	files := tree(t)
	for _, anchor := range anchors {
		if _, ok := files[anchor]; !ok {
			t.Errorf("the walk missed %s, which would make every rule below vacuous over its root", anchor)
		}
	}
}

func TestLicenseFileIsMIT(t *testing.T) {
	b, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	text := string(b)
	// Strip \r so a CRLF checkout does not fail with the self-denying message
	// `expected "MIT License" but was "MIT License"`.
	first := strings.TrimRight(strings.SplitN(text, "\n", 2)[0], "\r")
	if first != licenseName {
		t.Errorf("LICENSE first line = %q, want %q", first, licenseName)
	}
	if !strings.Contains(text, "Permission is hereby granted, free of charge") {
		t.Error("LICENSE does not carry the MIT permission grant, only a matching first line")
	}
}

func TestEverySPDXIdentifierNamesMIT(t *testing.T) {
	seen := 0
	for path, content := range tree(t) {
		for _, line := range strings.Split(content, "\n") {
			for _, declared := range declaredIdentifiers(line) {
				seen++
				if declared != "MIT" {
					t.Errorf("%s declares %q, which contradicts this repository's LICENSE", path, declared)
				}
			}
		}
	}
	// Without this, a walk that read nothing would satisfy the loop above.
	if seen == 0 {
		t.Error("no SPDX identifier was read at all, so the rule above proved nothing")
	}
}

func TestNoForeignLicenceProse(t *testing.T) {
	for path, content := range tree(t) {
		if path == "LICENSE" {
			continue // it IS the licence text
		}
		for _, phrase := range forbiddenPhrases {
			if strings.Contains(content, phrase) {
				t.Errorf("%s carries the prose of another licence: %q", path, phrase)
			}
		}
	}
}

// TestNoThirdPartyCopyright asserts that every copyright notice in THIS
// REPOSITORY'S OWN SOURCE is AxonFlow's. Scope stated precisely, because an
// earlier version of this comment claimed the guard "has no exemption list at
// all" and that a vendored file "fails and forces the decision" -- both false,
// since notSource skips `vendor/` and `node_modules/` wholesale. R3 proved it
// with a real `go mod vendor` tree: 17 files, 7 Apache-prose, 15 third-party
// copyright notices, and every licence test still green. That was a guard
// narrower than its own comment, which is worse than a narrow guard, because
// the comment is what the next person relies on.
//
// What it does catch is the realistic drift: a third-party helper pasted into
// `internal/` or beside the code that uses it, where nothing marks it as
// someone else's. That file is swept into MIT by any header pass unless
// something objects, and this is what objects.
func TestNoThirdPartyCopyright(t *testing.T) {
	seen := 0
	for path, content := range tree(t) {
		for _, line := range strings.Split(content, "\n") {
			if !copyrightNotice.MatchString(line) {
				continue
			}
			seen++
			if !strings.Contains(line, "AxonFlow") {
				t.Errorf("%s carries a copyright that is not AxonFlow's: %q\n"+
					"If this is vendored third-party code it keeps its own licence and needs "+
					"an explicit exemption here; it must not be swept into MIT.", path, strings.TrimSpace(line))
			}
		}
	}
	if seen == 0 {
		t.Error("no copyright line was read at all, so the rule above proved nothing")
	}
}

// TestBuildDirectivesAreNotRespaced pins the one behaviour a licence sweep can
// actually break here. `//go:build` is a directive only with NO space after the
// slashes; `// go:build` is an ordinary comment, and the constraint silently
// stops applying, so the file compiles into every build.
//
// This is pinned in the guard rather than left to the formatter because of how
// invisible it is: R3 planted the defect and confirmed that `go build`, `go vet`,
// the entire test suite and all eight of this file's other tests pass with the
// constraint disabled. A file that merely starts compiling breaks nothing that
// anyone asserts. `gofmt -l` was the only detector, and a detector that only
// fires when someone remembers to run it is not a guard.
// headerLines returns the header region of a file as (1-based line number,
// text), with lines inside a block comment omitted.
//
// Block-comment awareness is not decoration: a `#!` at column 0 inside a
// /* ... */ block is documentation, not a shebang, and flagging it is a false
// positive on correct code -- the failure mode that gets a guard deleted rather
// than fixed.
//
// Five lines rather than one, because a shebang that is re-spaced AND pushed
// down by an inserted header escapes a three-line window by exactly one line.
func headerLines(content string) [][2]string {
	var out [][2]string
	inBlock := false
	lines := strings.Split(content, "\n")
	if len(lines) > 5 {
		lines = lines[:5]
	}
	for i, line := range lines {
		opened := strings.Contains(line, "/*")
		closed := strings.Contains(line, "*/")
		if !inBlock && !opened {
			out = append(out, [2]string{strconv.Itoa(i + 1), line})
		}
		if opened && !closed {
			inBlock = true
		}
		if inBlock && closed {
			inBlock = false
		}
	}
	return out
}

// TestShebangsAreIntactAndInPlace pins the two ways a licence sweep breaks an
// interpreter line, which conceal each other.
//
// A shebang is only a shebang on line 1, so a sweep that reorders it below an
// inserted header stops it being one. And `# !/usr/bin/env bash` is a comment
// rather than a shebang, which makes it inert AND invisible to the position
// check at the same time, because that check keys on the literal "#!".
//
// SCOPE, stated because the obvious phrasing overclaims: this checks the
// shebang's POSITION and SPELLING, not the executable bit. Asserting the bit
// would fail on correct code here -- this repository has 5 shebang-bearing
// files and only 3 are executable. The harm pinned is "the interpreter line
// stops being read", not "the file stops being executable".
//
// Both siblings carry this rule; Go having gone without it was drift rather
// than a property of the language.
func TestShebangsAreIntactAndInPlace(t *testing.T) {
	respaced := regexp.MustCompile(`^#[ \t]+!`)
	var hits []string
	for path, content := range tree(t) {
		if !strings.HasSuffix(path, ".sh") && !strings.HasSuffix(path, ".go") {
			continue
		}
		for _, row := range headerLines(content) {
			n, line := row[0], row[1]
			if strings.HasPrefix(line, "#!") && n != "1" {
				hits = append(hits, path+":"+n+": shebang not on line 1")
			}
			if respaced.MatchString(line) {
				hits = append(hits, path+":"+n+": shebang re-spaced into an inert comment")
			}
		}
	}
	if len(hits) > 0 {
		t.Errorf("interpreter lines that will not be read: %q", hits)
	}

	// The false-positive direction, with a fixture rather than trusting the tree
	// not to contain one.
	inComment := "/*\n#!/usr/bin/env bash\n*/\nx"
	for _, row := range headerLines(inComment) {
		if strings.HasPrefix(row[1], "#!") {
			t.Error("a shebang inside a block comment was treated as a shebang")
		}
	}
	// ...and its control: outside a comment the same line IS seen, so the
	// exclusion cannot be satisfied by seeing nothing at all.
	seen := false
	for _, row := range headerLines("#!/usr/bin/env bash\nx") {
		if strings.HasPrefix(row[1], "#!") {
			seen = true
		}
	}
	if !seen {
		t.Error("headerLines does not see a real shebang, so the exclusion above proves nothing")
	}
}

func TestBuildDirectivesAreNotRespaced(t *testing.T) {
	// The two forms have OPPOSITE spacing rules, and conflating them flags
	// correct code: `//go:build` is a directive only with NO space, while the
	// legacy `// +build` REQUIRES one. The first version of this test asserted
	// a single pattern for both and failed against two untouched files.
	respaced := regexp.MustCompile("^//[ \t]+go:build\\b|^//\\+build\\b")
	var hits []string
	for path, content := range tree(t) {
		if !strings.HasSuffix(path, ".go") {
			continue
		}
		for n, line := range strings.Split(content, "\n") {
			if respaced.MatchString(line) {
				hits = append(hits, path+":"+strconv.Itoa(n+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if len(hits) > 0 {
		t.Errorf("a build directive has a space after the slashes and is therefore inert: %q", hits)
	}
	// Positive control: the pattern matches text that plainly carries the defect.
	for _, broken := range []string{"// go:build integration", "//+build integration"} {
		if !respaced.MatchString(broken) {
			t.Errorf("the pattern does not match the plainly broken directive %q", broken)
		}
	}
	// ...and does NOT match either form written correctly.
	for _, ok := range []string{"//go:build integration", "// +build integration"} {
		if respaced.MatchString(ok) {
			t.Errorf("the pattern flags the correctly-written directive %q", ok)
		}
	}
}

func TestIdentifierReaderHandlesEveryCommentSyntax(t *testing.T) {
	// A recogniser has two failure directions and needs a case for each. Rows
	// are built from spdxTag rather than written out, so this test's own cases
	// are not hits for the tree scan it describes.
	for _, tc := range []struct {
		name string
		line string
		want []string
	}{
		// ACCEPTS: MIT however the surrounding comment closes.
		{"line comment", "// " + spdxTag + " MIT", []string{"MIT"}},
		{"block body", " * " + spdxTag + " MIT", []string{"MIT"}},
		{"block closed", "/* " + spdxTag + " MIT */", []string{"MIT"}},
		{"markup", "<!-- " + spdxTag + " MIT -->", []string{"MIT"}},
		{"hash", "# " + spdxTag + " MIT", []string{"MIT"}},
		// Every terminator is exercised, so dropping one from the list fails
		// here rather than silently narrowing what the reader understands.
		{"jsp", "<%-- " + spdxTag + " MIT --%>", []string{"MIT"}},
		{"powershell", "<# " + spdxTag + " MIT #>", []string{"MIT"}},
		// CASE: the file comment claims closure under the syntax; a
		// case-sensitive scan makes that false.
		{"lowercase tag", "// " + strings.ToLower(spdxTag) + " Apache-2.0", []string{"Apache-2.0"}},
		{"uppercase tag", "// " + strings.ToUpper(spdxTag) + " BUSL-1.1", []string{"BUSL-1.1"}},
		{"lowercase mit", "// " + strings.ToLower(spdxTag) + " MIT", []string{"MIT"}},
		// STILL CATCHES: a foreign identifier is not laundered.
		{"apache in block", "/* " + spdxTag + " Apache-2.0 */", []string{"Apache-2.0"}},
		{"busl in markup", "<!-- " + spdxTag + " BUSL-1.1 -->", []string{"BUSL-1.1"}},
		{"expression", "// " + spdxTag + " MIT OR GPL-3.0", []string{"MIT OR GPL-3.0"}},
		// THE FALSE-NEGATIVE DIRECTION, which is the one that ships. A foreign
		// declaration sharing a line with a compliant one must not be swallowed
		// by the first value.
		{"two tags markup", "<!-- " + spdxTag + " MIT --> <!-- " + spdxTag + " Apache-2.0 -->",
			[]string{"MIT", "Apache-2.0"}},
		{"two tags block", "/* " + spdxTag + " MIT */ /* " + spdxTag + " BUSL-1.1 */",
			[]string{"MIT", "BUSL-1.1"}},
		{"two tags abutting", spdxTag + " MIT " + spdxTag + " Apache-2.0",
			[]string{"MIT", "Apache-2.0"}},
		// A line that declares nothing yields nothing, so `seen` counts only real ones.
		{"no declaration", "import \"strings\"", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := declaredIdentifiers(tc.line)
			if len(got) != len(tc.want) {
				t.Fatalf("declaredIdentifiers(%q) = %q, want %q", tc.line, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("declaredIdentifiers(%q)[%d] = %q, want %q", tc.line, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestNestedModuleOutputIsNotScanned(t *testing.T) {
	// Segment-wise, not prefix: this repo has four Go modules, so a prefix test
	// would only ever exclude a root-level directory.
	for _, rel := range []string{".git/config", "vendor/x/y.go", "examples/x/vendor/z.go", "node_modules/p/i.js"} {
		if !isNotSource(rel) {
			t.Errorf("isNotSource(%q) = false, want true", rel)
		}
	}
	// ...while a real source path that merely CONTAINS the word is still scanned.
	for _, rel := range []string{"axonflow.go", "internal/vendoring/x.go", "examples/wcp-retry-idempotency/main.go"} {
		if isNotSource(rel) {
			t.Errorf("isNotSource(%q) = true, want false", rel)
		}
	}
}

func TestPhraseRuleCanFire(t *testing.T) {
	// TestNoForeignLicenceProse asserts an ABSENCE across a tree that is
	// currently clean, so on its own it would pass identically if Contains
	// never matched anything. This runs the same predicate over a string that
	// does contain the prose.
	planted := "// Licensed under the " + "Apache" + " License, Version 2.0"
	for _, phrase := range forbiddenPhrases {
		if strings.Contains(planted, phrase) {
			return
		}
	}
	t.Error("the forbidden-phrase predicate does not match text that plainly contains a phrase")
}
