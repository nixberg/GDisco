import Foundation
import Ristretto255

enum Role {
    case initiator
    case responder
}

public class Handshake {
    let role: Role
    let symmetricState: SymmetricState
    var operation = 1
    var offset = 0
    var done = false
    
    init(_ role: Role, _ pattern: String) {
        self.role = role
        symmetricState = SymmetricState(pattern: pattern)
    }
    
    func operation(order: Int) {
        precondition(!done)
        precondition(self.operation == order)
        self.operation += 1
        offset = PublicKey.length
    }
    
    func longOperation(order: Int) {
        operation(order: order)
        self.offset += PublicKey.length + SymmetricState.macLength
    }
    
    public func writePayload<D: DataProtocol, M: MutableDataProtocol>(_ payload: D, to buffer: inout M) {
        precondition(!done)
        precondition(payload.count <= GDisco.maximumMessageLength - offset)
        symmetricState.encryptAndHash(payload, into: &buffer)
    }
    
    func readPayload<D: DataProtocol, M: MutableDataProtocol>(_ payload: inout M, from buffer: D) throws {
        precondition(!done)
        precondition(buffer.count <= GDisco.maximumMessageLength)
        try symmetricState.decryptAndHash(buffer.suffix(buffer.count - offset), into: &payload)

    }

    public func finalize() -> GDisco {
        precondition(!done)
        done.toggle()
        let (s1, s2) = symmetricState.split()
        return role == .initiator ? GDisco(sender: s1, receiver: s2) : GDisco(sender: s2, receiver: s1)
    }
}

public final class Initiator {}
public final class Responder {}

// Helper methods:

extension MutableDataProtocol {
    public mutating func append(_ keyPair: KeyPair) {
        self.append(contentsOf: keyPair.publicKey.data)
    }
}

extension SymmetricState {
    func mixHash(_ keyPair: KeyPair) {
        mixHash(keyPair.publicKey.data)
    }
    
    func mixHash(_ publicKey: PublicKey) {
        mixHash(publicKey.data)
    }
    
    func encryptAndHash<M: MutableDataProtocol>(_ keyPair: KeyPair, into ciphertext: inout M) {
        encryptAndHash(keyPair.publicKey.data, into: &ciphertext)
    }
}
