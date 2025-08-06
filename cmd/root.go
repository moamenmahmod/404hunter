package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the base command
var rootCmd = &cobra.Command{
	Use:   "404hunter",
	Short: "404Hunter is a fast subdomain takeover detection tool",
	Long: `404Hunter is a Go tool that checks subdomains for potential takeover risks 
using fingerprinting techniques, DNS CNAME inspection, HTTP status, and content matching.`,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
