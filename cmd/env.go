package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/docker-infra/aws-okta/lib"
	"github.com/spf13/cobra"
)

var (
	sessionTTL    time.Duration
	assumeRoleTTL time.Duration
)

// envCmd represents the env command
var envCmd = &cobra.Command{
	Use:    "env <profile>",
	Short:  "env will set AWS environment variables in your shell",
	RunE:   envRun,
	PreRun: envPre,
}

func init() {
	RootCmd.AddCommand(envCmd)
	envCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	envCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
}

func loadDurationFlagFromEnv(cmd *cobra.Command, flagName string, envVar string, val *time.Duration) error {
	if cmd.Flags().Lookup(flagName).Changed {
		return nil
	}

	fromEnv, ok := os.LookupEnv(envVar)
	if !ok {
		return nil
	}

	dur, err := time.ParseDuration(fromEnv)
	if err != nil {
		return err
	}

	*val = dur
	return nil
}

func envPre(cmd *cobra.Command, args []string) {
	if err := loadDurationFlagFromEnv(cmd, "session-ttl", "AWS_SESSION_TTL", &sessionTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_SESSION_TTL")
	}

	if err := loadDurationFlagFromEnv(cmd, "assume-role-ttl", "AWS_ASSUME_ROLE_TTL", &assumeRoleTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_ASSUME_ROLE_TTL")
	}
}

func envRun(cmd *cobra.Command, args []string) error {
	dashIx := cmd.ArgsLenAtDash()
	if dashIx == -1 {
		return ErrCommandMissing
	}

	args, commandPart := args[:dashIx], args[dashIx:]
	if len(args) < 1 {
		return ErrTooFewArguments
	}

	if len(commandPart) == 0 {
		return ErrCommandMissing
	}

	profile := args[0]
	command := commandPart[0]

	var commandArgs []string
	if len(commandPart) > 1 {
		commandArgs = commandPart[1:]
	}

	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config", profile)
	}

	opts := lib.ProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("profile", profile).
				Set("command", "env"),
		})
	}

	p, err := lib.NewProvider(kr, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	env := environ(os.Environ())
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")
	env.Unset("AWS_OKTA_PROFILE")

	if region, ok := profiles[profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	env.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	env.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	env.Set("AWS_OKTA_PROFILE", profile)

	if creds.SessionToken != "" {
		env.Set("AWS_SESSION_TOKEN", creds.SessionToken)
		env.Set("AWS_SECURITY_TOKEN", creds.SessionToken)
	}

	return nil
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
