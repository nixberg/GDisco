import Foundation
import Monocypher

public final class PublicKey {
    let data: Data
    
    public init(from secretKey: SecretKey) {
        precondition(secretKey.data.count == 32)
        data = KeyExchange.publicKey(from: secretKey.data)
    }
    
    public init(from data: Data) throws {
        guard data.count >= 32 else {
            throw Error.messageTooShort
        }
        self.data = data[..<data.startIndex.advanced(by: 32)]
    }
}

public final class SecretKey {
    let data: Data
    
    public init() {
        data = Data.random(count: 32)!
    }
    
    public func DH(their: PublicKey) -> Data {
        return KeyExchange.sharedKey(mySecret: data, theirPublic: their.data)!
    }
}

public final class KeyPair {
    public let publicKey: PublicKey
    public let secretKey: SecretKey
    
    public init() {
        secretKey = SecretKey()
        publicKey = PublicKey(from: secretKey)
    }
    
    public func DH(their: PublicKey) -> Data {
        return secretKey.DH(their: their)
    }
}
