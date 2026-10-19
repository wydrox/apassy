/// Scene-owned receipts survive switching between Waiting and History.
enum RequestsLocalReceipt: Equatable {
    case idle
    case sending
    case denied
    case failed(String)
}
