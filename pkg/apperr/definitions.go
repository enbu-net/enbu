package apperr

type definition struct {
	message string
	params  []string
}

var definitions = map[Code]definition{
	CodeImportConflict:      {message: "{count} secrets already have different values: {keys}. Use --overwrite to replace them.", params: []string{"count", "keys"}},
	CodeInternal:            {message: "An unexpected error occurred.", params: []string{}},
	CodeInvalidArgument:     {message: "The input is invalid.", params: []string{}},
	CodeNotAuthenticated:    {message: "Sign in with GitHub to continue.", params: []string{}},
	CodeAccessDenied:        {message: "Access was denied.", params: []string{}},
	CodeAuthExpired:         {message: "The authentication session expired. Try again.", params: []string{}},
	CodeNotInitialized:      {message: "Set up enbu for this repository first.", params: []string{}},
	CodeConfigNotFound:      {message: "enbu.toml was not found.", params: []string{}},
	CodeConfigProtected:     {message: "\"{key}\" in enbu.toml cannot be changed here: it decides which members the workspace trusts or where secrets are stored.", params: []string{"key"}},
	CodeEnvironmentMissing:  {message: "Environment \"{name}\" does not exist.", params: []string{"name"}},
	CodeEnvironmentExists:   {message: "Environment \"{name}\" already exists.", params: []string{"name"}},
	CodeSecretMissing:       {message: "Secret \"{key}\" does not exist.", params: []string{"key"}},
	CodeSecretExists:        {message: "Secret \"{key}\" already exists.", params: []string{"key"}},
	CodeArtifactNotFound:    {message: "The requested secrets were not found.", params: []string{}},
	CodeConflict:            {message: "Secrets changed remotely. Try again.", params: []string{}},
	CodeUnavailable:         {message: "The required service is unavailable.", params: []string{}},
	CodeNotMember:           {message: "This device has not been approved yet. Ask an admin to approve it.", params: []string{}},
	CodeUntrusted:           {message: "Stored data failed signature verification and was not used.", params: []string{}},
	CodeRollback:            {message: "Storage shows less than this device already accepted. It may be a delayed listing; try again.", params: []string{}},
	CodeIncompatibleStorage: {message: "This storage was created without a workspace control. Use an empty location.", params: []string{}},
	CodeSecretConflict:      {message: "Concurrent edits changed the same secret differently. Nothing was lost; choose a value to continue.", params: []string{}},
	CodeControlForked:       {message: "Two admins changed the members at the same time. Nothing else can proceed until an admin of both changes opens enbu, which joins them.", params: []string{}},
	CodeReencryptIncomplete: {message: "Membership changed, but some secrets are not re-encrypted yet. Run sync to finish.", params: []string{}},
	CodeTrustRootChanged:    {message: "enbu.toml names a different trust root (control_genesis) than this device trusts for this workspace. Do not continue unless an admin confirms out of band that they re-created the workspace; then accept the new root ('enbu init --accept-new-genesis').", params: []string{}},
	CodeIdentityUnavailable: {message: "No usable identity backend on this device. Run 'enbu doctor' for details.", params: []string{}},
	CodeKeyringLocked:       {message: "The OS keyring is locked. Unlock it (for example by logging in to the desktop) and try again.", params: []string{}},
	CodeOutputUnreadable:    {message: "{file} is not a dotenv file enbu can read. Pull again and overwrite it to replace its content.", params: []string{"file"}},
}
