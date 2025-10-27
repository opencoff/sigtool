// buildinfo.go - provides build information utilities for Go programs.
//
// (c) 2016 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.
package main

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
)

// BuildInfo contains information about the build.
type BuildInfo struct {
	*debug.BuildInfo
}

// ReadBuildInfo returns build information for the running binary.
func ReadBuildInfo() (*BuildInfo, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, false
	}
	return &BuildInfo{info}, true
}

// String returns a human-readable representation of build information.
func (bi *BuildInfo) String() string {
	var sb strings.Builder

	m := &bi.Main
	fmt.Fprintf(&sb, "main: %s\n", m.Path)
	fmt.Fprintf(&sb, "Go Toolchain: %s\n", bi.GoVersion)

	var revision, arch, os string
	var cgo, modified bool

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			fmt.Fprintf(&sb, "Build Time: %s\n", s.Value)
		case "vcs.modified":
			modified = s.Value == "true"
		case "vcs":
			fmt.Fprintf(&sb, "VCS: %s\n", s.Value)
		case "GOARCH":
			arch = s.Value
		case "GOOS":
			os = s.Value
		case "CGO_ENABLED":
			cgo = s.Value == "true"

		default:
			//fmt.Fprintf(&sb, "# %s: %s\n", s.Key, s.Value)
		}
	}
	fmt.Fprintf(&sb, "GO: %s-%s", os, arch)
	if cgo {
		sb.WriteString("+CGO")
	}
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "Revision: %s", revision)
	if modified {
		sb.WriteString("+dirty")
	}
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "Version: %s\n", m.Version)

	// Dependencies
	if len(bi.Deps) > 0 {
		fmt.Fprintf(&sb, "Dependencies: %d\n", len(bi.Deps))
		for _, dep := range bi.Deps {
			fmt.Fprintf(&sb, "  %s %s %s", dep.Path, dep.Version, dep.Sum)
			if dep.Replace != nil {
				fmt.Fprintf(&sb, " => %s %s %s", dep.Replace.Path, dep.Replace.Version, dep.Replace.Sum)
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// JSON returns a JSON representation of build information.
func (bi *BuildInfo) JSON() (string, error) {
	type jsonDep struct {
		Path    string `json:"path"`
		Version string `json:"version"`
		Sum     string `json:"sum,omitempty"`
		Replace *struct {
			Path    string `json:"path,omitempty"`
			Version string `json:"version,omitempty"`
			Sum     string `json:"sum,omitempty"`
		} `json:"replace,omitempty"`
	}

	type jsonBuildInfo struct {
		GoVersion    string            `json:"go_version"`
		Path         string            `json:"path,omitempty"`
		Main         string            `json:"main,omitempty"`
		Version      string            `json:"version,omitempty"`
		Revision     string            `json:"revision,omitempty"`
		BuildTime    string            `json:"build_time,omitempty"`
		Modified     bool              `json:"modified,omitempty"`
		GOOS         string            `json:"goos,omitempty"`
		GOARCH       string            `json:"goarch,omitempty"`
		CGO          string            `json:"cgo_enabled,omitempty"`
		VCS          string            `json:"vcs,omitempty"`
		Settings     map[string]string `json:"settings,omitempty"`
		Dependencies []jsonDep         `json:"dependencies,omitempty"`
	}

	result := jsonBuildInfo{
		GoVersion: bi.GoVersion,
		Path:      bi.Path,
		Main:      bi.Main.Path,
		Version:   bi.Main.Version,
		Settings:  make(map[string]string),
	}

	// Extract VCS information from settings
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			result.Revision = setting.Value
		case "vcs.time":
			result.BuildTime = setting.Value
		case "vcs.modified":
			result.Modified = setting.Value == "true"
		case "vcs":
			result.VCS = setting.Value
		case "GOOS":
			result.GOOS = setting.Value
		case "GOARCH":
			result.GOARCH = setting.Value
		case "CGO_ENABLED":
			result.CGO = setting.Value
		default:
			// Store all other settings
			result.Settings[setting.Key] = setting.Value
		}
	}

	// Dependencies
	if len(bi.Deps) > 0 {
		deps := make([]jsonDep, 0, len(bi.Deps))
		for _, dep := range bi.Deps {
			d := jsonDep{
				Path:    dep.Path,
				Version: dep.Version,
				Sum:     dep.Sum,
			}
			if dep.Replace != nil {
				d.Replace = &struct {
					Path    string `json:"path,omitempty"`
					Version string `json:"version,omitempty"`
					Sum     string `json:"sum,omitempty"`
				}{
					Path:    dep.Replace.Path,
					Version: dep.Replace.Version,
					Sum:     dep.Replace.Sum,
				}
			}
			deps = append(deps, d)
		}
		result.Dependencies = deps
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
