// main.go -- CLI benchmark tool for sigtool
//
// (c) 2024 Sudhi Herle <sudhi@herle.net>
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
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"time"

	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool"
)

// buffer wraps bytes.Buffer with a no-op Close for io.WriteCloser.
type buffer struct {
	*bytes.Buffer
}

func newBuf() *buffer {
	return &buffer{Buffer: &bytes.Buffer{}}
}

func newBufFrom(b []byte) *buffer {
	return &buffer{Buffer: bytes.NewBuffer(b)}
}

func (b *buffer) Close() error {
	return nil
}

type benchSize struct {
	name string
	size uint64
}

var defaultSizes = "4k,64k,1M,16M,128M,1G"

type benchResult struct {
	operation  string
	size       string
	sizeBytes  uint64
	chunkSize  string
	elapsedMs  float64
	throughput float64 // MB/s, 0 if size==0
}

func main() {
	var iters int
	var format string
	var opsStr string
	var noAuth bool
	var verbose bool
	var help bool
	var cpuProfile string
	var memProfile string

	fs := flag.NewFlagSet("sigtool-bench", flag.ExitOnError)
	fs.IntVarP(&iters, "iterations", "n", 3, "Number of iterations per test")
	fs.StringVarP(&format, "format", "f", "table", "Output format: \"table\" or \"csv\"")
	fs.StringVarP(&opsStr, "ops", "o", "all", "Operations: sign,verify,encrypt,decrypt or \"all\"")
	fs.BoolVar(&noAuth, "no-auth", false, "Skip sender-authenticated benchmarks")
	fs.BoolVarP(&verbose, "verbose", "v", false, "Show per-iteration timings")
	fs.BoolVarP(&help, "help", "h", false, "Show help and exit")
	fs.StringVar(&cpuProfile, "cpuprofile", "", "Write CPU profile to `file`")
	fs.StringVar(&memProfile, "memprofile", "", "Write memory profile to `file`")

	fs.Parse(os.Args[1:])

	if help {
		usage(fs)
	}

	if iters < 1 {
		Die("iterations must be >= 1")
	}

	szStr := "all"
	args := fs.Args()
	if len(args) > 0 {
		szStr = args[0]
	}

	sizes := parseSizes(szStr)
	ops := parseOps(opsStr)

	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			Die("cpuprofile: %s", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Generate keys
	sender, err := sigtool.NewPrivateKey("bench-sender")
	if err != nil {
		Die("keygen: %s", err)
	}
	rx, err := sigtool.NewPrivateKey("bench-rx")
	if err != nil {
		Die("keygen: %s", err)
	}
	rxPK := rx.PublicKey()
	senderPK := sender.PublicKey()

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "sigtool-bench-*")
	if err != nil {
		Die("tmpdir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	var results []benchResult

	// Sign/Verify benchmarks (file-based, mmap path)
	if ops["sign"] || ops["verify"] {
		fmt.Fprintf(os.Stderr, "Generating test files...\n")
		type fileEntry struct {
			bs benchSize
			fn string
		}
		files := make([]fileEntry, 0, len(sizes))
		for _, sz := range sizes {
			fn := createBenchFile(tmpDir, sz.size)
			files = append(files, fileEntry{sz, fn})
			fmt.Fprintf(os.Stderr, "  %s\n", sz.name)
		}

		if ops["sign"] {
			fmt.Fprintf(os.Stderr, "Benchmarking SignFile...\n")
			for _, fe := range files {
				durations := make([]time.Duration, iters)
				for i := 0; i < iters; i++ {
					start := time.Now()
					_, err := sender.SignFile(fe.fn)
					durations[i] = time.Since(start)
					if err != nil {
						Die("SignFile %s: %s", fe.bs.name, err)
					}
				}
				r := summarize("SignFile", fe.bs, durations)
				results = append(results, r)
				if verbose {
					printIterations("SignFile", fe.bs.name, durations)
				}
			}
		}

		if ops["verify"] {
			fmt.Fprintf(os.Stderr, "Benchmarking VerifyFile...\n")
			for _, fe := range files {
				sig, err := sender.SignFile(fe.fn)
				if err != nil {
					Die("SignFile setup: %s", err)
				}
				durations := make([]time.Duration, iters)
				for i := 0; i < iters; i++ {
					start := time.Now()
					ok, err := senderPK.VerifyFile(fe.fn, sig)
					durations[i] = time.Since(start)
					if err != nil {
						Die("VerifyFile %s: %s", fe.bs.name, err)
					}
					if !ok {
						Die("VerifyFile %s: verification failed", fe.bs.name)
					}
				}
				r := summarize("VerifyFile", fe.bs, durations)
				results = append(results, r)
				if verbose {
					printIterations("VerifyFile", fe.bs.name, durations)
				}
			}
		}
	}

	// Encrypt/Decrypt benchmarks (in-memory streaming)
	if ops["encrypt"] || ops["decrypt"] {
		type ptEntry struct {
			bs      benchSize
			pt      []byte
			chunkSz uint64
		}
		entries := make([]ptEntry, 0, len(sizes))
		for _, sz := range sizes {
			var pt []byte
			if sz.size > 0 {
				pt = make([]byte, sz.size)
				if _, err := io.ReadFull(rand.Reader, pt); err != nil {
					Die("randgen %s: %s", sz.name, err)
				}
			}
			entries = append(entries, ptEntry{sz, pt, chunkSizeFor(sz.size)})
		}

		// Encrypt (no auth)
		if ops["encrypt"] {
			fmt.Fprintf(os.Stderr, "Benchmarking Encrypt...\n")
			for _, e := range entries {
				durations := make([]time.Duration, iters)
				outSize := encOutputSize(e.bs.size, e.chunkSz)
				for i := 0; i < iters; i++ {
					rd := newBufFrom(e.pt)
					wr := newBuf()
					wr.Grow(int(outSize))
					start := time.Now()
					enc, err := sigtool.NewEncryptor(nil, rxPK, rd, wr, e.chunkSz)
					if err != nil {
						Die("Encrypt %s: %s", e.bs.name, err)
					}
					if err = enc.Encrypt(); err != nil {
						Die("Encrypt %s: %s", e.bs.name, err)
					}
					durations[i] = time.Since(start)
				}
				r := summarize("Encrypt", e.bs, durations)
				r.chunkSize = humanSize(e.chunkSz)
				results = append(results, r)
				if verbose {
					printIterations("Encrypt", e.bs.name, durations)
				}
			}
		}

		// Decrypt (no auth)
		if ops["decrypt"] {
			fmt.Fprintf(os.Stderr, "Benchmarking Decrypt...\n")
			for _, e := range entries {
				// encrypt once to get ciphertext
				rd := newBufFrom(e.pt)
				wr := newBuf()
				enc, err := sigtool.NewEncryptor(nil, rxPK, rd, wr, e.chunkSz)
				if err != nil {
					Die("Decrypt setup %s: %s", e.bs.name, err)
				}
				if err = enc.Encrypt(); err != nil {
					Die("Decrypt setup %s: %s", e.bs.name, err)
				}
				ct := wr.Bytes()

				durations := make([]time.Duration, iters)
				for i := 0; i < iters; i++ {
					rd := newBufFrom(ct)
					wr := newBuf()
					wr.Grow(int(e.bs.size))
					start := time.Now()
					dec, err := sigtool.NewDecryptor(rx, nil, rd, wr)
					if err != nil {
						Die("Decrypt %s: %s", e.bs.name, err)
					}
					if err = dec.Decrypt(); err != nil {
						Die("Decrypt %s: %s", e.bs.name, err)
					}
					durations[i] = time.Since(start)
				}
				r := summarize("Decrypt", e.bs, durations)
				r.chunkSize = humanSize(e.chunkSz)
				results = append(results, r)
				if verbose {
					printIterations("Decrypt", e.bs.name, durations)
				}
			}
		}

		// Authenticated encrypt/decrypt
		if !noAuth {
			if ops["encrypt"] {
				fmt.Fprintf(os.Stderr, "Benchmarking EncryptAuth...\n")
				for _, e := range entries {
					durations := make([]time.Duration, iters)
					outSize := encOutputSize(e.bs.size, e.chunkSz)
					for i := 0; i < iters; i++ {
						rd := newBufFrom(e.pt)
						wr := newBuf()
						wr.Grow(int(outSize))
						start := time.Now()
						enc, err := sigtool.NewEncryptor(sender, rxPK, rd, wr, e.chunkSz)
						if err != nil {
							Die("EncryptAuth %s: %s", e.bs.name, err)
						}
						if err = enc.Encrypt(); err != nil {
							Die("EncryptAuth %s: %s", e.bs.name, err)
						}
						durations[i] = time.Since(start)
					}
					r := summarize("EncryptAuth", e.bs, durations)
					r.chunkSize = humanSize(e.chunkSz)
					results = append(results, r)
					if verbose {
						printIterations("EncryptAuth", e.bs.name, durations)
					}
				}
			}

			if ops["decrypt"] {
				fmt.Fprintf(os.Stderr, "Benchmarking DecryptAuth...\n")
				for _, e := range entries {
					// encrypt once with auth
					rd := newBufFrom(e.pt)
					wr := newBuf()
					enc, err := sigtool.NewEncryptor(sender, rxPK, rd, wr, e.chunkSz)
					if err != nil {
						Die("DecryptAuth setup %s: %s", e.bs.name, err)
					}
					if err = enc.Encrypt(); err != nil {
						Die("DecryptAuth setup %s: %s", e.bs.name, err)
					}
					ct := wr.Bytes()

					durations := make([]time.Duration, iters)
					for i := 0; i < iters; i++ {
						rd := newBufFrom(ct)
						wr := newBuf()
						wr.Grow(int(e.bs.size))
						start := time.Now()
						dec, err := sigtool.NewDecryptor(rx, senderPK, rd, wr)
						if err != nil {
							Die("DecryptAuth %s: %s", e.bs.name, err)
						}
						if err = dec.Decrypt(); err != nil {
							Die("DecryptAuth %s: %s", e.bs.name, err)
						}
						durations[i] = time.Since(start)
					}
					r := summarize("DecryptAuth", e.bs, durations)
					r.chunkSize = humanSize(e.chunkSz)
					results = append(results, r)
					if verbose {
						printIterations("DecryptAuth", e.bs.name, durations)
					}
				}
			}
		}
	}

	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			Die("memprofile: %s", err)
		}
		runtime.GC()
		pprof.WriteHeapProfile(f)
		f.Close()
	}

	// Output results
	switch format {
	case "csv":
		formatCSV(results)
	default:
		formatTable(results, noAuth)
	}
}

func parseSizes(s string) []benchSize {
	if strings.ToLower(s) == "all" {
		s = defaultSizes
	}

	parts := strings.Split(s, ",")
	sizes := make([]benchSize, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) == 0 {
			continue
		}
		n, err := utils.ParseSize(p)
		if err != nil {
			Die("invalid size %q: %s", p, err)
		}
		sizes = append(sizes, benchSize{humanSize(n), n})
	}
	if len(sizes) == 0 {
		Die("no valid sizes specified")
	}
	return sizes
}

func parseOps(s string) map[string]bool {
	ops := make(map[string]bool)
	if strings.ToLower(s) == "all" {
		ops["sign"] = true
		ops["verify"] = true
		ops["encrypt"] = true
		ops["decrypt"] = true
		return ops
	}

	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		switch p {
		case "sign", "verify", "encrypt", "decrypt":
			ops[p] = true
		default:
			Die("unknown operation %q; valid: sign,verify,encrypt,decrypt,all", p)
		}
	}
	if len(ops) == 0 {
		Die("no valid operations specified")
	}
	return ops
}

// chunkSizeFor returns an appropriate encryption chunk size
// proportional to the file size.
func chunkSizeFor(fileSize uint64) uint64 {
	switch {
	case fileSize == 0:
		return 128 * 1024 // 128KB default
	case fileSize <= 64*1024: // <= 64KB
		return uint64(fileSize)
	case fileSize <= 1024*1024: // <= 1MB
		return 128 * 1024 // 128KB
	case fileSize <= 16*1024*1024: // <= 16MB
		return 1024 * 1024 // 1MB
	default: // > 16MB
		return 4 * 1024 * 1024 // 4MB
	}
}

// encOutputSize estimates encrypted output size for buffer pre-allocation.
// Intentionally over-estimates slightly for headroom.
func encOutputSize(inputSize uint64, chunkSz uint64) uint64 {
	if inputSize == 0 {
		return 4096 // header + trailer + EOF chunk
	}
	numChunks := (inputSize + chunkSz - 1) / chunkSz
	return inputSize + numChunks*20 + 4096 // 20 = 4 len + 16 GCM tag; 4096 = header+trailer headroom
}

// createBenchFile creates a temp file of the given size filled with
// random data. Writes in 1MB chunks to avoid huge allocations.
func createBenchFile(dir string, size uint64) string {
	fn := filepath.Join(dir, fmt.Sprintf("bench-%d.dat", size))
	fd, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		Die("create bench file: %s", err)
	}
	defer fd.Close()

	const chunk uint64 = 1024 * 1024
	buf := make([]byte, chunk)
	remaining := size
	for remaining > 0 {
		want := remaining
		if want > chunk {
			want = chunk
		}
		if _, err := io.ReadFull(rand.Reader, buf[:want]); err != nil {
			Die("rand fill: %s", err)
		}
		if _, err := fd.Write(buf[:want]); err != nil {
			Die("write bench file: %s", err)
		}
		remaining -= want
	}
	fd.Sync()
	return fn
}

func summarize(op string, bs benchSize, durations []time.Duration) benchResult {
	med := median(durations)
	ms := float64(med.Nanoseconds()) / 1e6
	var tp float64
	if bs.size > 0 && med > 0 {
		tp = float64(bs.size) / med.Seconds() / (1024 * 1024)
	}
	return benchResult{
		operation:  op,
		size:       bs.name,
		sizeBytes:  bs.size,
		elapsedMs:  ms,
		throughput: tp,
	}
}

func median(durations []time.Duration) time.Duration {
	n := len(durations)
	if n == 0 {
		return 0
	}

	sorted := make([]time.Duration, n)
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func printIterations(op, size string, durations []time.Duration) {
	for i, d := range durations {
		fmt.Fprintf(os.Stderr, "  %s %s iter %d: %.3f ms\n",
			op, size, i+1, float64(d.Nanoseconds())/1e6)
	}
}

func humanSize(n uint64) string {
	return utils.HumanizeSize(n)
}

func fmtThroughput(tp float64) string {
	if tp == 0 {
		return "N/A"
	}
	if tp >= 1000 {
		return fmt.Sprintf("%.0f", tp)
	}
	if tp >= 100 {
		return fmt.Sprintf("%.0f", tp)
	}
	if tp >= 10 {
		return fmt.Sprintf("%.1f", tp)
	}
	return fmt.Sprintf("%.2f", tp)
}

func fmtMs(ms float64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.0f", ms)
	}
	if ms >= 100 {
		return fmt.Sprintf("%.0f", ms)
	}
	if ms >= 10 {
		return fmt.Sprintf("%.1f", ms)
	}
	return fmt.Sprintf("%.2f", ms)
}

func formatTable(results []benchResult, noAuth bool) {
	fmt.Println()
	fmt.Println("sigtool-bench: Performance Report")
	fmt.Println("==================================")

	// Group by operation category
	signResults := filterOp(results, "SignFile")
	verifyResults := filterOp(results, "VerifyFile")
	encResults := filterOp(results, "Encrypt")
	decResults := filterOp(results, "Decrypt")
	encAuthResults := filterOp(results, "EncryptAuth")
	decAuthResults := filterOp(results, "DecryptAuth")

	if len(signResults) > 0 || len(verifyResults) > 0 {
		fmt.Println()
		fmt.Println("Sign/Verify (file-based, mmap):")
		fmt.Printf("%-12s %-8s %-10s %-8s %-10s\n", "Size", "Sign", "", "Verify", "")
		fmt.Printf("%-12s %-8s %-10s %-8s %-10s\n", "", "MB/s", "ms", "MB/s", "ms")
		fmt.Printf("%-12s %-8s %-10s %-8s %-10s\n",
			"------------", "--------", "----------", "--------", "----------")

		n := int(math.Max(float64(len(signResults)), float64(len(verifyResults))))
		for i := 0; i < n; i++ {
			var size string
			stp, sms := "N/A", "N/A"
			vtp, vms := "N/A", "N/A"

			if i < len(signResults) {
				size = signResults[i].size
				stp = fmtThroughput(signResults[i].throughput)
				sms = fmtMs(signResults[i].elapsedMs)
			}
			if i < len(verifyResults) {
				if size == "" {
					size = verifyResults[i].size
				}
				vtp = fmtThroughput(verifyResults[i].throughput)
				vms = fmtMs(verifyResults[i].elapsedMs)
			}
			fmt.Printf("%-12s %-8s %-10s %-8s %-10s\n", size, stp, sms, vtp, vms)
		}
	}

	if len(encResults) > 0 || len(decResults) > 0 {
		fmt.Println()
		fmt.Println("Encrypt/Decrypt (no auth):")
		fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n", "Size", "Chunk", "Encrypt", "", "Decrypt", "")
		fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n", "", "", "MB/s", "ms", "MB/s", "ms")
		fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n",
			"------------", "--------", "--------", "----------", "--------", "----------")

		n := int(math.Max(float64(len(encResults)), float64(len(decResults))))
		for i := 0; i < n; i++ {
			var size, chunk string
			etp, ems := "N/A", "N/A"
			dtp, dms := "N/A", "N/A"

			if i < len(encResults) {
				size = encResults[i].size
				chunk = encResults[i].chunkSize
				etp = fmtThroughput(encResults[i].throughput)
				ems = fmtMs(encResults[i].elapsedMs)
			}
			if i < len(decResults) {
				if size == "" {
					size = decResults[i].size
					chunk = decResults[i].chunkSize
				}
				dtp = fmtThroughput(decResults[i].throughput)
				dms = fmtMs(decResults[i].elapsedMs)
			}
			fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n", size, chunk, etp, ems, dtp, dms)
		}
	}

	if !noAuth && (len(encAuthResults) > 0 || len(decAuthResults) > 0) {
		fmt.Println()
		fmt.Println("Encrypt/Decrypt (sender authenticated):")
		fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n", "Size", "Chunk", "Encrypt", "", "Decrypt", "")
		fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n", "", "", "MB/s", "ms", "MB/s", "ms")
		fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n",
			"------------", "--------", "--------", "----------", "--------", "----------")

		n := int(math.Max(float64(len(encAuthResults)), float64(len(decAuthResults))))
		for i := 0; i < n; i++ {
			var size, chunk string
			etp, ems := "N/A", "N/A"
			dtp, dms := "N/A", "N/A"

			if i < len(encAuthResults) {
				size = encAuthResults[i].size
				chunk = encAuthResults[i].chunkSize
				etp = fmtThroughput(encAuthResults[i].throughput)
				ems = fmtMs(encAuthResults[i].elapsedMs)
			}
			if i < len(decAuthResults) {
				if size == "" {
					size = decAuthResults[i].size
					chunk = decAuthResults[i].chunkSize
				}
				dtp = fmtThroughput(decAuthResults[i].throughput)
				dms = fmtMs(decAuthResults[i].elapsedMs)
			}
			fmt.Printf("%-12s %-8s %-8s %-10s %-8s %-10s\n", size, chunk, etp, ems, dtp, dms)
		}
	}

	fmt.Println()
}

func filterOp(results []benchResult, op string) []benchResult {
	var out []benchResult
	for _, r := range results {
		if r.operation == op {
			out = append(out, r)
		}
	}
	return out
}

func formatCSV(results []benchResult) {
	fmt.Println("operation,size,size_bytes,chunk_size,elapsed_ms,throughput_mbps")
	for _, r := range results {
		fmt.Printf("%s,%s,%d,%s,%.3f,%.2f\n",
			r.operation, r.size, r.sizeBytes, r.chunkSize,
			r.elapsedMs, r.throughput)
	}
}

func usage(fs *flag.FlagSet) {
	fmt.Printf(`sigtool-bench - Performance benchmark tool for sigtool

Usage: sigtool-bench [options] [sizes..]

Benchmarks sign/verify/encrypt/decrypt operations at various file sizes.
Sign/verify benchmarks use real temp files (exercises mmap path).
Encrypt/decrypt benchmarks use in-memory buffers.

Sizes are optional and can be comma separated.

Options:
`)
	fs.PrintDefaults()
	fmt.Printf(`
Examples:
  sigtool-bench                           # Run all benchmarks with default sizes
  sigtool-bench -n 5 1KB,1MB,1GB          # Custom sizes, 5 iterations
  sigtool-bench -o encrypt,decrypt        # Only encrypt/decrypt
  sigtool-bench --no-auth -f csv          # No auth benchmarks, CSV output
`)
	os.Exit(0)
}

// Die prints an error message to stderr and exits.
func Die(f string, v ...interface{}) {
	Warn(f, v...)
	os.Exit(1)
}

// Warn prints a warning message to stderr.
func Warn(f string, v ...interface{}) {
	z := fmt.Sprintf("sigtool-bench: %s", f)
	s := fmt.Sprintf(z, v...)
	if n := len(s); s[n-1] != '\n' {
		s += "\n"
	}
	os.Stderr.WriteString(s)
	os.Stderr.Sync()
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
