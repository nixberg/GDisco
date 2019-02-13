import Foundation
import GStrobe

public final class SymmetricState {
    let strobe: GStrobe
    var isKeyed = false
    
    init(pattern: String) {
        strobe = GStrobe(customization: GDisco.protocolName(for: pattern))
    }
    
    func mixKey(_ key: Data) {
        strobe.additionalData(key) // NOTE: .key?
        isKeyed = true
    }
    
    func mixHash(_ data: Data) {
        strobe.additionalData(data)
    }
    
    func encryptAndHash(_ plaintext: Data, into ciphertext: inout Data) {
        precondition(isKeyed)
        strobe.send(plaintext, into: &ciphertext)
        strobe.sendMAC(&ciphertext, count: 16)
    }
    
    func decryptAndHash(_ ciphertext: Data) throws -> Data {
        var data = Data(capacity: ciphertext.count - 16)
        try decryptAndHash(ciphertext, into: &data)
        return data
    }
    
    func decryptAndHash(_ ciphertext: Data, into plaintext: inout Data) throws {
        precondition(isKeyed)
        guard ciphertext.count >= 16 else {
            throw Error.messageTooShort
        }
        let macIndex = ciphertext.endIndex - 16
        strobe.receive(ciphertext[..<macIndex], into: &plaintext)
        guard strobe.receiveMAC(ciphertext[macIndex...]) else {
            throw Error.badMAC
        }
    }
    
    func split() -> (GStrobe, GStrobe) {
        precondition(isKeyed)
        let s1 = strobe
        let s2 = GStrobe(cloning: strobe)
        s1.metaAdditionalData("one".data(using: .utf8)!)
        s2.metaAdditionalData("two".data(using: .utf8)!)
        s1.ratchet(count: 16)
        s2.ratchet(count: 16)
        return (s1, s2)
    }
}
