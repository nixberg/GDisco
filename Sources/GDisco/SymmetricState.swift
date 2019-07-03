import Foundation
import GStrobe

public final class SymmetricState {
    static let macLength = 16
    
    let strobe: GStrobe
    var isKeyed = false
    
    init(pattern: String) {
        strobe = GStrobe(customization: GDisco.protocolName(for: pattern))
    }
    
    func mixKey<D: DataProtocol>(_ key: D) {
        strobe.additionalData(key) // NOTE: .key?
        isKeyed = true
    }
    
    func mixHash<D: DataProtocol>(_ data: D) {
        strobe.additionalData(data)
    }
    
    func encryptAndHash<D: DataProtocol, MD: MutableDataProtocol>
        (_ plaintext: D, into ciphertext: inout MD) {
        precondition(isKeyed)
        strobe.send(plaintext, into: &ciphertext)
        strobe.sendMAC(&ciphertext, count: SymmetricState.macLength)
    }
    
    func decryptAndHash<D: DataProtocol>(_ ciphertext: D) throws -> [UInt8] { // TODO: some DataProtocol?
        var data = [UInt8]()
        data.reserveCapacity(ciphertext.count - SymmetricState.macLength)
        try decryptAndHash(ciphertext, into: &data)
        return data
    }
    
    func decryptAndHash<D: DataProtocol, MD: MutableDataProtocol>
        (_ ciphertext: D, into plaintext: inout MD) throws {
        precondition(isKeyed)
        guard ciphertext.count >= SymmetricState.macLength else {
            throw GDiscoError.messageTooShort
        }
        let prefix = ciphertext.prefix(ciphertext.count - SymmetricState.macLength)
        strobe.receive(prefix, into: &plaintext)
        guard strobe.receiveMAC(ciphertext.suffix(SymmetricState.macLength)) else {
            throw GDiscoError.badMAC
        }
    }
    
    func split() -> (GStrobe, GStrobe) {
        precondition(isKeyed)
        let s1 = strobe
        let s2 = GStrobe(from: strobe)
        s1.metaAdditionalData("one".data(using: .utf8)!)
        s2.metaAdditionalData("two".data(using: .utf8)!)
        s1.ratchet(count: 16)
        s2.ratchet(count: 16)
        return (s1, s2)
    }
}
