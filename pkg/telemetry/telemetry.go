package telemetry

// Stub for OSS builds - telemetry is a Pro feature.
// This provides no-op implementations to satisfy imports.

type Client struct{}

var GlobalClient *Client = nil

func (c *Client) TrackWithContext(event string, props map[string]interface{}, args ...string) {}
func (c *Client) Track(event string, props map[string]interface{})                            {}
