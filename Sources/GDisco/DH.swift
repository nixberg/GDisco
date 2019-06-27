import Foundation
import Monocypher

// TODO: resetBytes(in:) somewhere?
// TODO: X25519

// TODO: Waiting for `newtype`.
// NOTE: `typealias` is dangerous: For example, it’s possible to override `.init()`. Bug?

public struct SecretKey {
    static let length = 32

    let data: [UInt8]
    
    public init() {
        data = .init(Data.random(count: SecretKey.length)!)
    }
    
    public func publicKey() -> PublicKey {
        return .init(from: KeyExchange.publicKey(from: Data(data)))
    }
    
    public func DH(_ their: PublicKey) -> [UInt8] {
        return .init(KeyExchange.sharedKey(mySecret: Data(data), theirPublic: Data(their.data))!)
    }
}

public struct PublicKey {
    static let length = 32

    let data: [UInt8]
    
    public init<D: DataProtocol>(from data: D) {
        precondition(data.count >= PublicKey.length)
        self.data = .init(data.prefix(PublicKey.length))
    }
}

public struct KeyPair {
    public let publicKey: PublicKey
    public let secretKey: SecretKey
    
    public init() {
        secretKey = .init()
        publicKey = secretKey.publicKey()
    }
    
    public func DH(_ their: PublicKey) -> [UInt8] {
        return secretKey.DH(their)
    }
}

