export function applyPreviewMetadata(document, metadata, ref) {
  const badge = document.getElementById("ref-badge");
  if (!ref) {
    badge.textContent = `PR #${metadata.pullRequest}`;
    badge.href = metadata.pullRequestURL;
  }
  document.getElementById("revision-label").textContent =
    `${metadata.ref} · ${metadata.sha.slice(0, 7)}`;
}
