export type PreviewMetadata = {
  pullRequest: string;
  pullRequestURL: string;
  ref: string;
  sha: string;
};

export function applyPreviewMetadata(
  document: Document,
  metadata: PreviewMetadata,
  ref: string | null,
): void;
