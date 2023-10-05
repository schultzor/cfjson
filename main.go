// Read newline-delimited cloudlfare json log entries from stdin, filter them according to flags
// then write the results back to stdout as json or csv lines. Uses multiple goroutines to handle
// decoding entries, so output ordering will differ from the input unless '-decoders 1' is set.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"time"

	"golang.org/x/sync/errgroup"
)

const nanosPerSec = 1_000_000_000

type filter func(*cfLog) bool

var filters []filter
var csvFieldIndexes []int
var csvFieldNames []string

// see https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/
type cfLog struct {
	CacheCacheStatus                      string
	CacheResponseBytes                    int
	CacheResponseStatus                   int
	CacheTieredFill                       bool
	ClientASN                             int
	ClientCountry                         string
	ClientDeviceType                      string
	ClientIP                              string
	ClientIPClass                         string
	ClientMTLSAuthCertFingerprint         string
	ClientMTLSAuthStatus                  string
	ClientRequestBytes                    int
	ClientRequestHost                     string
	ClientRequestMethod                   string
	ClientRequestPath                     string
	ClientRequestProtocol                 string
	ClientRequestReferer                  string
	ClientRequestScheme                   string
	ClientRequestSource                   string
	ClientRequestURI                      string
	ClientRequestUserAgent                string
	ClientSSLCipher                       string
	ClientSSLProtocol                     string
	ClientTCPRTTMs                        int
	ClientXRequestedWith                  string
	EdgeCFConnectingO2O                   bool
	EdgeColoCode                          string
	EdgeColoID                            int
	EdgeEndTimestamp                      int64
	EdgePathingOp                         string
	EdgePathingSrc                        string
	EdgePathingStatus                     string
	EdgeRateLimitAction                   string
	EdgeRateLimitID                       int
	EdgeRequestHost                       string
	EdgeResponseBodyBytes                 int
	EdgeResponseBytes                     int
	EdgeResponseCompressionRatio          float32
	EdgeResponseContentType               string
	EdgeResponseStatus                    int
	EdgeServerIP                          string
	EdgeStartTimestamp                    int64
	EdgeTimeToFirstByteMs                 int
	FirewallMatchesActions                []string
	FirewallMatchesRuleIDs                string
	FirewallMatchesSources                string
	OriginDNSResponseTimeMs               int
	OriginIP                              string
	OriginRequestHeaderSendDurationMs     int
	OriginResponseBytes                   int
	OriginResponseDurationMs              int
	OriginResponseHTTPExpires             string
	OriginResponseHTTPLastModified        string
	OriginResponseHeaderReceiveDurationMs int
	OriginResponseStatus                  int
	OriginResponseTime                    int64
	OriginSSLProtocol                     string
	OriginTCPHandshakeDurationMs          int
	OriginTLSHandshakeDurationMs          int
	ParentRayID                           string
	RayID                                 string
	RequestHeaders                        map[string]any
	ResponseHeaders                       map[string]any
	SecurityLevel                         string
	SmartRouteColoID                      int
	UpperTierColoID                       int
	WAFAction                             string
	WAFFlags                              string
	WAFMatchedVar                         string
	WAFProfile                            string
	WAFRuleID                             string
	WAFRuleMessage                        string
	WorkerCPUTime                         int64
	WorkerStatus                          string
	WorkerSubrequest                      bool
	WorkerSubrequestCount                 int
	WorkerWallTimeUs                      int
	ZoneID                                int
	ZoneName                              string

	src *string // string entry was parsed from
}

func (e *cfLog) parse(js string) error {
	if err := json.Unmarshal([]byte(js), e); err != nil {
		return fmt.Errorf("error decoding log %q: %w", js, err)
	}
	e.src = &js
	return nil
}

func (e cfLog) toCsv() []string {
	var ret []string
	sv := reflect.ValueOf(e)
	for _, idx := range csvFieldIndexes {
		fv := sv.Field(idx)
		ret = append(ret, fmt.Sprint(fv.Interface()))
	}
	return ret
}

func init() {
	var tmp cfLog
	st := reflect.TypeOf(tmp)
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if f.IsExported() {
			csvFieldIndexes = append(csvFieldIndexes, i)
			csvFieldNames = append(csvFieldNames, f.Name)
		}
	}
}

type tstamp int64

func (v tstamp) String() string {
	if v > 0 {
		return time.Unix(int64(v)/nanosPerSec, int64(v)%nanosPerSec).UTC().Format(time.RFC3339)
	}
	return ""
}
func (v *tstamp) Set(s string) error {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*v = tstamp(ts.UnixNano())
	return nil
}

func addFilter[T comparable](v T, ff filter) {
	var dval T
	if v != dval {
		filters = append(filters, ff)
	}
}

func checkFilters(entry *cfLog) bool {
	for _, f := range filters {
		if !f(entry) {
			return false
		}
	}
	return true
}

func decode(input <-chan string, output chan<- *cfLog) error {
	for m := range input {
		var entry cfLog
		if err := entry.parse(m); err != nil {
			return err
		}
		if !checkFilters(&entry) {
			continue
		}
		output <- &entry
	}
	return nil
}

func main() {
	log.SetPrefix("cfjson:")
	log.SetFlags(0)

	procStart := time.Now().UTC()
	var start, end tstamp
	doCsv := flag.Bool("csv", false, "emit csv output instead of json")
	edgeResponseStatus := flag.Int("status", 0, "match EdgeResponseStatus")
	clientRequestPath := flag.String("reqpath", "", "match ClientRequestPath")
	clientRequestSource := flag.String("reqsource", "", "match ClientRequestSource")
	clientRequestHost := flag.String("reqhost", "", "optional ClientRequestHost filter")
	rayId := flag.String("ray", "", "match RayID or ParentRayID field")
	cacheStatus := flag.String("cachestatus", "", "match on CacheCacheStatus")
	flag.Var(&start, "start", "optional time range start, e.g. "+procStart.Add(-1*time.Hour).Format(time.RFC3339))
	flag.Var(&end, "end", "optional time range end, e.g. "+procStart.Format(time.RFC3339))
	decoders := flag.Int("decoders", max(1, runtime.NumCPU()/2), "number of decoder goroutines to run")
	flag.Parse()

	var csvOut *csv.Writer
	if *doCsv {
		csvOut = csv.NewWriter(os.Stdout)
		csvOut.Write(csvFieldNames)
		defer csvOut.Flush()
	}
	addFilter(*cacheStatus, func(l *cfLog) bool {
		return l.CacheCacheStatus == *cacheStatus
	})
	addFilter(*rayId, func(l *cfLog) bool {
		return l.RayID == *rayId || l.ParentRayID == *rayId
	})
	addFilter(*edgeResponseStatus, func(l *cfLog) bool {
		return l.EdgeResponseStatus == *edgeResponseStatus
	})
	addFilter(*clientRequestPath, func(l *cfLog) bool {
		return l.ClientRequestPath == *clientRequestPath
	})
	addFilter(*clientRequestSource, func(l *cfLog) bool {
		return l.ClientRequestSource == *clientRequestSource
	})
	addFilter(*clientRequestHost, func(l *cfLog) bool {
		return l.ClientRequestHost == *clientRequestHost
	})
	addFilter(start, func(l *cfLog) bool {
		return l.EdgeStartTimestamp >= int64(start)
	})
	addFilter(end, func(l *cfLog) bool {
		return l.EdgeStartTimestamp <= int64(end)
	})

	input := make(chan string, 100)
	output := make(chan *cfLog, 100)

	log.Printf("running %d decoders", *decoders)
	var decoderGroup errgroup.Group
	for i := 0; i < *decoders; i++ {
		decoderGroup.Go(func() error {
			return decode(input, output)
		})
	}

	var writerGroup errgroup.Group
	writerGroup.Go(func() error {
		for e := range output {
			if csvOut != nil {
				csvOut.Write(e.toCsv())
			} else {
				os.Stdout.WriteString(*e.src)
			}
		}
		return nil
	})
	var count int
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		input <- line
		count++
	}
	close(input)
	decoderGroup.Wait()
	close(output)
	writerGroup.Wait()
	log.Printf("read %d lines in %v", count, time.Since(procStart))
}
