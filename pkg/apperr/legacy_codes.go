package apperr

// These codes keep the disconnected legacy packages buildable for this
// cutover boundary. The following cleanup commit removes both the packages and
// these constants; production clients cannot emit them.
const (
	CodeConfigNotFound     Code = "config_not_found"
	CodeEnvironmentMissing Code = "environment_not_found"
	CodeEnvironmentExists  Code = "environment_already_exists"
	CodeSecretMissing      Code = "secret_not_found"
	CodeSecretExists       Code = "secret_already_exists"
	CodeArtifactNotFound   Code = "artifact_not_found"
)
