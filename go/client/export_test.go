// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net/http"
)

// GetForTest is a GET below <base>/v1, for the tests of the pipeline before the calls exist.
func (c *Client) GetForTest(ctx context.Context, path string) (int, error) {
	resp, err := c.send(ctx, &call{method: http.MethodGet, path: path, what: "test"}, 1<<20)
	if resp != nil {
		return resp.status, err
	}
	return 0, err
}
