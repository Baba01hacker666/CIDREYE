package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Parse parses a port string (e.g., "80", "80,443", "1-1000") into a sorted slice of unique port numbers.
func Parse(portsStr string) ([]int, error) {
	if portsStr == "" {
		return nil, fmt.Errorf("empty port string")
	}

	portMap := make(map[int]struct{})
	parts := strings.Split(portsStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %s: %w", part, err)
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %s: %w", part, err)
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range values: %s", part)
			}

			for i := start; i <= end; i++ {
				portMap[i] = struct{}{}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s: %w", part, err)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", port)
			}
			portMap[port] = struct{}{}
		}
	}

	if len(portMap) == 0 {
		return nil, fmt.Errorf("no valid ports found")
	}

	var ports []int
	for port := range portMap {
		ports = append(ports, port)
	}

	sort.Ints(ports)
	return ports, nil
}
