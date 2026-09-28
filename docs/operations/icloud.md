# iCloud sync

Date: 2026-09-28.

iCloud Drive is one of the folders that a vault can sync through. Apassy syncs a vault through any folder that a sync service keeps in step: iCloud Drive (the default when it is on), Dropbox, Google Drive, OneDrive, Syncthing, or a network share. Changes from each Mac merge by credential.

Everything is in [Sync through a folder](sync.md). For iCloud Drive in particular:

- The folder is `~/Library/Mobile Documents/com~apple~CloudDocs/Apassy`. The Seatbelt profile denies it as a whole (`APASSY_CLOUD_DIR`).
- A file that iCloud evicted from the Mac shows "Waiting for iCloud to download"; Apassy asks iCloud for it (`brctl download`).
- iCloud can keep a second file as `<name> 2.apassy` when two Macs push at the same time. Apassy does not use it; the change in it is still on the Mac that pushed it.

Decision: [ADR 0014](../adr/0014-icloud-sync.md).
