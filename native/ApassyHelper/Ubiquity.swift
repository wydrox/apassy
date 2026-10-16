// iCloud Drive status of one synced file, for the sync engine
// (docs/operations/sync.md, section 7; src/sync/cloud.rs).
//
// A file that iCloud evicted is easy to see from Rust: it has the dataless
// flag or a `.<name>.icloud` placeholder. A file that is on this Mac can
// still be an old version: iCloud knows of a newer one on the server and has
// not downloaded it. Only Foundation tells that
// (NSURLUbiquitousItemDownloadingStatusKey). The Rust crate forbids unsafe
// code, so this helper reads the key.
//
// `ubiquity_status {path, download}` reads the status of the file at `path`
// and reads no content. With `download: true` and a status other than
// "current", it also asks iCloud for the newest version
// (FileManager.startDownloadingUbiquitousItem). The request returns at once;
// iCloud downloads in the background.

import Foundation

/// Largest path, in bytes. The Rust client has the same limit.
let maxPathBytes = 1024

func handleUbiquityStatus(_ request: Request) throws -> Fields {
    let path = try request.string("path")
    guard path.hasPrefix("/"),
          path.utf8.count <= maxPathBytes,
          !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    else {
        throw HelperError(.invalidRequest, "The field \"path\" must be an absolute path of at most \(maxPathBytes) bytes without control characters.")
    }
    var download = false
    if let value = request.fields["download"] {
        guard let flag = value as? Bool else {
            throw HelperError(.invalidRequest, "The field \"download\" must be true or false.")
        }
        download = flag
    }
    let url = URL(fileURLWithPath: path)
    let keys: Set<URLResourceKey> = [
        .isUbiquitousItemKey,
        .ubiquitousItemDownloadingStatusKey,
        .ubiquitousItemIsDownloadingKey,
        .ubiquitousItemDownloadingErrorKey,
    ]
    guard FileManager.default.fileExists(atPath: path),
          let values = try? url.resourceValues(forKeys: keys)
    else {
        throw HelperError(.notFound, "The file is not there, or its iCloud status cannot be read.")
    }
    guard values.isUbiquitousItem == true else {
        return ["ok": true, "ubiquitous": false]
    }
    let raw = values.ubiquitousItemDownloadingStatus
    let status: String
    if raw == .current {
        status = "current"
    } else if raw == .downloaded {
        status = "downloaded"
    } else if raw == .notDownloaded {
        status = "not_downloaded"
    } else {
        status = "unknown"
    }
    var requested = false
    if download && status != "current" {
        requested = (try? FileManager.default.startDownloadingUbiquitousItem(at: url)) != nil
    }
    return [
        "ok": true,
        "ubiquitous": true,
        "status": status,
        "downloading": values.ubiquitousItemIsDownloading ?? false,
        "download_error": values.ubiquitousItemDownloadingError != nil,
        "download_requested": requested,
    ]
}
