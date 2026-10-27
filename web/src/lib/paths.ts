/** The last element of a local path, on any platform. */
export function folderName(path = "") {
  return (
    path
      .replace(/[\\/]+$/, "")
      .split(/[\\/]/)
      .pop() ?? ""
  );
}
