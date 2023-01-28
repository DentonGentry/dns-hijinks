package main

import (
	"fmt"
	"math/rand"
	"os"

	"github.com/miekg/dns"
)

var (
	ROOT_NAMESERVERS = []string{
		"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
		"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
		"193.0.14.129", "199.7.83.42", "202.12.27.33",
	}
)

func resolve(name string) ([]dns.RR, error) {
	nameserver := ROOT_NAMESERVERS[rand.Intn(len(ROOT_NAMESERVERS))]
	c := new(dns.Client)

	for {
		// Prepare a message asking for an A record (an IP address) for `name`
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)

		// Send the DNS request to the IP in `nameserver`
		fmt.Printf("Asking %s about %s\n", nameserver, name)
		resp, _, err := c.Exchange(m, fmt.Sprintf("%s:53", nameserver))
		if err != nil {
			return nil, err
		}

		if len(resp.Answer) > 0 {
			// If an ANSWER SECTION exists and contains a CNAME, recurse
			if cname, ok := resp.Answer[0].(*dns.CNAME); ok {
				return resolve(cname.Target)
			}

			// If an ANSWER SECTION exists, we're done
			return resp.Answer, nil
		}

		// If the ADDITIONAL SECTION is empty and the AUTHORITY SECTION is not, resolve
		// one of the names in the AUTHORITY SECTION and have that be the nameserver
		if len(resp.Extra) == 0 && len(resp.Ns) != 0 {
			ns := resp.Ns[0].(*dns.NS)
			nsIP, err := resolve(ns.Ns)
			if err != nil {
				return nil, fmt.Errorf("break in the chain")
			}
			nameserver = nsIP[0].(*dns.A).A.String()
		} else {
			// If an ADDITIONAL SECTION exists, look in it for an A record for the
			// next-level nameserver. If one doesn't exist, we have to error out
			found := false
			for _, rr := range resp.Extra {
				record, ok := rr.(*dns.A)
				if ok {
					nameserver = record.A.String()
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("break in the chain")
			}
		}

		// ... and recurse!
	}

}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: dns <name>\n")
		os.Exit(1)
	}

	name := os.Args[1]
	answer, err := resolve(name)
	if err == nil {
		for _, record := range answer {
			fmt.Println(record)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Failed to resolve %s\n", name)
		os.Exit(1)
	}
}
