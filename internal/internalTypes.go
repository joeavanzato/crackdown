package internal

import (
	"fmt"
	"github.com/rs/zerolog"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
)

type Detection struct {
	Name      string
	Severity  int
	Tip       string
	Technique string
	Metadata  map[string]interface{}
}

func (d Detection) MarshalZerologObject(e *zerolog.Event) {
	e.Str("name", d.Name).
		Int("severity", d.Severity).
		Str("tip", d.Tip).
		Str("technique", d.Technique).
		Fields(d.Metadata)

}

var suspiciousPatterns = []string{
	"BEGIN {s = \"/inet/tcp/0/",
	"bash -i >& /dev/tcp/",
	"bash -i >& /dev/udp/",
	"sh -i >$ /dev/udp/",
	"sh -i >$ /dev/tcp/",
	"&& while read line 0<&5; do",
	"/bin/bash -c exec 5<>/dev/tcp/",
	"/bin/bash -c exec 5<>/dev/udp/",
	"nc -e /bin/sh ",
	"/bin/sh | nc",
	"rm -f backpipe; mknod /tmp/backpipe p && nc ",
	";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i))))",
	";STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;",
	"/bin/sh -i <&3 >&3 2>&3",
	"uname -a; w; id; /bin/bash -i",
	"([text.encoding]::ASCII).GetBytes",
	"$stream.Flush()",
	"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)",
	"while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print",
	"socat exec:''bash -li'',pty,stderr,setsid,sigint,sane tcp",
	"rm -f /tmp/p; mknod /tmp/p p &&",
	"/bin/bash | telnet",
	"echo=0,raw tcp-listen:",
	"nc -lvvp",
	"xterm -display 1",
}

func (d Detection) String() string {
	// Format the string of a detection to properly iterate over the Metadata when rendering
	// TODO - Ths second loop after sort for some reason is introducing empty keys to the array - not sure why.
	// - I think the above is because we are not trimming /n - now we are doing this properly in each string read from files.
	var base string
	dv := reflect.ValueOf(d)
	typeOfS := dv.Type()
	for i := 0; i < dv.NumField(); i++ {
		k := typeOfS.Field(i).Name
		v := dv.Field(i).Interface()
		if k == "Metadata" {
			base += "Metadata: "

			keys := make([]string, len(d.Metadata))
			for j, _ := range d.Metadata {
				if j != "" {
					keys = append(keys, j)
				}
			}
			sort.Strings(keys)

			for _, jj := range keys {
				if jj != "" {
					base += fmt.Sprintf("%s: %s, ", jj, d.Metadata[jj])
				}
			}

			/*for kk, vv := range d.Metadata {
				base += fmt.Sprintf("%s: %s, ", kk, vv)
			}*/
		} else if k == "Severity" {
			base += fmt.Sprintf("%s: %d, ", k, v)
		} else {
			base += fmt.Sprintf("%s: %s, ", k, v)
		}
	}
	return base
}

type WaitGroupCount struct {
	sync.WaitGroup
	count int64
}

func (wg *WaitGroupCount) Add(delta int) {
	atomic.AddInt64(&wg.count, int64(delta))
	wg.WaitGroup.Add(delta)
}

func (wg *WaitGroupCount) Done() {
	atomic.AddInt64(&wg.count, -1)
	wg.WaitGroup.Done()
}

func (wg *WaitGroupCount) GetCount() int {
	return int(atomic.LoadInt64(&wg.count))
}