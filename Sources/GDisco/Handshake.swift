import Foundation

enum Role {
    case initiator
    case responder
}

enum Operation {
    case write((SymmetricState, inout Data) -> ())
    case read((SymmetricState, Data) throws -> ())
    case readStatic((SymmetricState, Data) throws -> (Int, PublicKey))
}

public final class Handshake {
    public final class I { } // Initiator
    public final class R { } // Responder
    
    let role: Role
    var operations: [Operation]
    let symmetricState: SymmetricState
    
    init(_ pattern: String, _ role: Role, _ operations: [Operation]) {
        self.symmetricState = SymmetricState(pattern: pattern)
        self.role = role
        self.operations = operations
    }
    
    public func write(to buffer: inout Data) {
        guard case .write(let write) = operations.removeFirst() else {
            fatalError("Out of turn.")
        }
        write(symmetricState, &buffer)
    }
    
    public func write(to buffer: inout Data, payload: Data) throws {
        let initialCount = buffer.count
        write(to: &buffer)
        guard (buffer.count - initialCount) + payload.count <= GDisco.maximumMessageLength else {
            throw Error.payloadTooLong
        }
        symmetricState.encryptAndHash(payload, into: &buffer)
    }
    
    public func read(from buffer: Data) throws {
        precondition(!operations.isEmpty)
        guard case .read(let read) = operations.removeFirst() else {
            fatalError("Out of turn.")
        }
        guard buffer.count <= GDisco.maximumMessageLength else {
            throw Error.payloadTooLong
        }
        try read(symmetricState, buffer)
    }
    
    public func read(from buffer: Data, payload: inout Data) throws {
        try read(from: buffer)
        try symmetricState.decryptAndHash(buffer.advanced(by: 32), into: &payload)
    }
    
    public func readStatic(from buffer: Data) throws -> PublicKey {
        let (_, rs) = try privateReadStatic(from: buffer)
        return rs
    }
    
    private func readStatic(from buffer: Data, payload: inout Data) throws -> PublicKey {
        let (bytesRead, rs) = try privateReadStatic(from: buffer)
        try symmetricState.decryptAndHash(buffer.advanced(by: bytesRead), into: &payload)
        return rs
    }
    
    private func privateReadStatic(from buffer: Data) throws -> (Int, PublicKey) {
        precondition(!operations.isEmpty)
        guard case .readStatic(let readStatic) = operations.removeFirst() else {
            fatalError("Out of turn.")
        }
        guard buffer.count <= GDisco.maximumMessageLength else {
            throw Error.payloadTooLong
        }
        return try readStatic(symmetricState, buffer)
    }
    
    public func finalize() -> GDisco {
        precondition(operations.isEmpty)
        let (s1, s2) = symmetricState.split()
        return role == .initiator ?
            GDisco(sender: s1, receiver: s2) : GDisco(sender: s2, receiver: s1)
    }
}
