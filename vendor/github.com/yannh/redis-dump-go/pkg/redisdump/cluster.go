package redisdump

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mediocregopher/radix/v3"
	"github.com/pkg/errors"
)

func ParseRedisInfo(s string) (map[string]string, error) {
	lines := strings.Split(s, "\n")

	info := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		info[key] = val
	}
	return info, nil
}

type Node struct {
	Host  string
	Port  int
	Slots []Range
}

type Range struct {
	Start, End int
}

func GetMasterNodeAddresses(s string) ([]Node, error) {
	lines := strings.Split(s, "\n")

	var masters []Node
	for _, line := range lines {
		if strings.Contains(line, "master") {
			fields := strings.FieldsFunc(line, func(r rune) bool {
				return r == ' ' || r == '@'
			})

			host, port, err := net.SplitHostPort(fields[1])
			if err != nil {
				return nil, errors.Wrapf(err, "failed to split addr %s", fields[1])
			}
			p, err := strconv.Atoi(port)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse port in addr %s", fields[1])
			}
			m := Node{Host: host, Port: p}

			for i := len(fields) - 1; i >= 0; i-- {
				start, end, found := strings.Cut(fields[i], "-")
				if !found {
					break
				}
				s, err := strconv.Atoi(start)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to parse slot start for redis master %s with slots %s", m.Host, fields[i])
				}
				e, err := strconv.Atoi(end)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to parse slot end for redis master %s with slots %s", m.Host, fields[i])
				}
				m.Slots = append(m.Slots, Range{Start: s, End: e})
			}
			masters = append(masters, m)
		}
	}
	return masters, nil
}

func GetHosts(s Host, nWorkers int) ([]Host, error) {
	client, err := NewClient(s, nil, nWorkers)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var val string
	err = client.Do(radix.Cmd(&val, "INFO"))
	if err != nil {
		return nil, err
	}
	info, err := ParseRedisInfo(val)
	if err != nil {
		return nil, err
	}
	if info["cluster_enabled"] == "0" {
		return []Host{s}, nil
	}

	err = client.Do(radix.Cmd(&val, "CLUSTER", "nodes"))
	if err != nil {
		return nil, err
	}
	masters, err := GetMasterNodeAddresses(val)
	if err != nil {
		panic(err)
	}
	hosts := make([]Host, 0, len(masters))
	for _, m := range masters {
		scopy := s
		scopy.Host = m.Host
		scopy.Port = m.Port
		hosts = append(hosts, scopy)
	}
	return hosts, nil
}

func NewCluster(hosts []Host) (*radix.Cluster, error) {
	addrs := make([]string, 0, len(hosts))
	for _, host := range hosts {
		addrs = append(addrs, fmt.Sprintf("%s:%d", host.Host, host.Port))
	}
	getConnFunc := func(db *uint8) func(network, addr string) (radix.Client, error) {
		return func(network, addr string) (radix.Client, error) {
			dialOpts, err := redisDialOpts(hosts[0].Username, hosts[0].Password, hosts[0].TlsHandler, db)
			if err != nil {
				return nil, err
			}

			return radix.Dial(network, addr, dialOpts...)
		}
	}
	return radix.NewCluster(addrs, radix.ClusterPoolFunc(getConnFunc(nil)))
}
