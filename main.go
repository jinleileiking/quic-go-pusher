package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/op/go-logging"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var log = logging.MustGetLogger("example")

var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var serverInfo = flag.String("s", "localhost:6666", "quic server host and port")
var typ = flag.String("t", "server", "quic server or client. Client will send a message and waiting for receiving a message. Server will receive a message and echo back")
var intval = flag.Int("intval", 1000, "[client] send intval ms")
var cnt = flag.Int("c", 1, "[client] send count")
var message = flag.String("m", "hello gquic from client", "[client] send content")
var isRandom = flag.Bool("r", false, "[client] use random string, works with rlen")
var rlen = flag.Int("rlen", 10, "[client] random string len, works with r")
var loop = flag.Bool("loop", false, "[client] forever sends data")
var dump = flag.Bool("d", false, "dump content?")
var echo = flag.Bool("e", true, "echo / check  echo the data?")
var auth = flag.Bool("auth", false, "use mutual auth?")
var con = flag.Int("con", 1, "concurrent clients initiated sessions")
var promPort = flag.Int("port", 8811, "prometheus export port")

func initLog() {

	backend2 := logging.NewLogBackend(os.Stdout, "", 0)
	backend2Formatter := logging.NewBackendFormatter(backend2, format)

	backend1 := logging.NewLogBackend(os.Stdout, "", 0)
	backend1Leveled := logging.AddModuleLevel(backend1)
	backend1Leveled.SetLevel(logging.ERROR, "")

	logging.SetBackend(backend1Leveled, backend2Formatter)
}

func main() {
	initLog()
	flag.Parse()

	col := pushCollect{
		Sendbytes: prometheus.NewDesc(
			"quic_pusher",
			"the total bytes send by the client",
			[]string{"connection"},
			nil,
		),
	}
	prometheus.MustRegister(&col)

	server := http.NewServeMux()
	server.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", *promPort), server)

	var wg sync.WaitGroup
	for i := 0; i < *con; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := client(*serverInfo)
			if err != nil {
				panic(err)
			}
			log.Info("Goroutine Done")
		}()
	}
	wg.Wait()

	log.Info("Exited")
}

var quicBytes map[string]int

func client(serverInfo string) error {

	quicBytes = make(map[string]int)

	pool := x509.NewCertPool()
	caCertPath := "ca.crt"

	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return errors.Wrap(err, "ReadFile failed")
	}
	pool.AppendCertsFromPEM(caCrt)

	log.Info("Dialing....")

	session, err := quic.DialAddr(serverInfo, &tls.Config{RootCAs: pool, InsecureSkipVerify: !*auth}, &quic.Config{IdleTimeout: 50 * time.Minute})
	if err != nil {
		return err
	}
	defer func() {
		log.Info("Session closed...")
		session.Close()
	}()

	log.Info("Dial Ok")

	stream, err := session.OpenStreamSync()
	if err != nil {
		return errors.Wrap(err, "OpenStreamSync failed")
	}

	log.Infof("OpenStreamSync, stream id :%d", stream.StreamID())

	defer func() {
		log.Info("Stream closed...")
		stream.Close()
	}()

	log.Info("OpenStreamSync done...")

	msg := *message

	for c := 0; c < *cnt; c++ {
		if *isRandom {
			msg = RandStringRunes(*rlen)
		}

		if *loop {
			c = 0
		}

		if *dump {
			log.Infof("Client %s: Snd '%s', count : %d\n", session.LocalAddr(), msg, c)
		} else {
			log.Infof("Client %s: Snd count : %d\n", session.LocalAddr(), c)
		}
		// startTime := time.Now()
		var writeBytes int
		writeBytes, err = stream.Write([]byte(msg))
		if err != nil {
			return errors.Wrap(err, "stream.Write failed")
		}
		log.Info("Done, bytes:", writeBytes)

		quicBytes[session.LocalAddr().String()] += writeBytes

		// elapsed := time.Since(startTime)
		// log.Infof("Cost: %s\n", elapsed)

		if *cnt != 1 {
			time.Sleep(time.Duration(*intval) * time.Millisecond)
		}
	}

	return nil
}

func getFile(file string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadFile failed")
	}
	return bytes, nil
}

func getTLSConfig() (tls.Config, error) {

	tlsCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return tls.Config{}, errors.Wrap(err, "LoadX509KeyPair failed")
	}

	return tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}

func init() {
	mrand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}
	return string(b)
}

type pushCollect struct {
	Sendbytes *prometheus.Desc
}

func (c *pushCollect) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.Sendbytes
}

func (c *pushCollect) Collect(ch chan<- prometheus.Metric) {
	for k, v := range quicBytes {
		ch <- prometheus.MustNewConstMetric(
			c.Sendbytes,
			prometheus.GaugeValue,
			float64(v),
			k,
		)
	}
}
