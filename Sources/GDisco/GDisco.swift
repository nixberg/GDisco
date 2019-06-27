import Foundation
import GStrobe

enum GDiscoError : Swift.Error {
    case payloadTooLong
    case messageTooShort
    case badMAC
}

public final class GDisco {
    static let maximumMessageLength = 65535
    
    static let version = 0
    static func protocolName(for pattern: String) -> Data {
        return "GDisco-v\(version)_\(pattern)".data(using: .ascii)!
    }
    
    var aborted = false
    let sender: GStrobe
    var senderNonce: UInt64 = 0
    let receiver: GStrobe
    var receiverNonce: UInt64 = 0
    
    init(sender: GStrobe, receiver: GStrobe) {
        self.sender = sender
        self.receiver = receiver
    }
    
    public func encrypt<D: DataProtocol, MD: MutableDataProtocol>
        (additionalData: D? = nil, plaintext: D, into ciphertext: inout MD) {
        precondition(!aborted)
        precondition(plaintext.count + 16 <= GDisco.maximumMessageLength)
        precondition(senderNonce < UInt64.max)
        
        let ephemeralStrobe = GStrobe(from: sender)
        ephemeralStrobe.additionalData(senderNonce.data())
        if let additionalData = additionalData {
            ephemeralStrobe.additionalData(additionalData)
        }
        ephemeralStrobe.send(plaintext, into: &ciphertext)
        ephemeralStrobe.sendMAC(&ciphertext, count: 16)
        senderNonce += 1
    }
    
    public func decrypt<D: DataProtocol, MD: MutableDataProtocol>
        (additionalData: D? = nil, ciphertext: D, into plaintext: inout MD) throws {
        precondition(!aborted)
        precondition(ciphertext.count >= 16)
        precondition(ciphertext.count <= GDisco.maximumMessageLength)
        precondition(receiverNonce < UInt64.max)
        
        let ephemeralStrobe = GStrobe(from: receiver)
        ephemeralStrobe.additionalData(receiverNonce.data())
        if let additionalData = additionalData {
            ephemeralStrobe.additionalData(additionalData)
        }
        ephemeralStrobe.receive(ciphertext.prefix(ciphertext.count - 16), into: &plaintext)
        guard ephemeralStrobe.receiveMAC(ciphertext.suffix(16)) else {
            aborted = true
            throw GDiscoError.badMAC
        }
        receiverNonce += 1
    }
}

extension UInt64 {
    func data() -> Data {
        var le = self.littleEndian
        return withUnsafeBytes(of: &le, { Data($0) })
    }
}
