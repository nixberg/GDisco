import Foundation

// First character:
//  N = No static key for initiator
//  K = Static key for initiator Known to responder
//  X = Static key for initiator Xmitted ("transmitted") to responder
//  I = Static key for initiator Immediately transmitted to responder
//
// Second character:
//  N = No static key for responder
//  K = Static key for responder Known to initiator
//  X = Static key for responder Xmitted ("transmitted") to initiator

// K:
//  -> s
//  <- s
//  ...
//  -> e, es, ss

extension Initiator {
    public class K: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey

        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "K")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(rs))
            symmetricState.mixKey(s.DH(rs))
        }
    }
}

extension Responder {
    public class K: Handshake {
        let s: KeyPair
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.responder, "K")
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(s.DH(re))
            symmetricState.mixKey(s.DH(rs))
        }
    }
}


// N:
//  <- s
//  ...
//  -> e, es

extension Initiator {
    public class N: Handshake {
        let e = KeyPair()
        let rs: PublicKey

        public init(their rs: PublicKey) {
            self.rs = rs
            super.init(.initiator, "N")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(rs))
        }
    }
}

extension Responder {
    public class N: Handshake {
        let s: KeyPair
        let e = KeyPair()
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "N")
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(s.DH(re))
        }
    }
}


// X:
//  <- s
//  ...
//  -> e, es, s, ss

extension Initiator {
    public class X: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "X")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            longOperation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(rs))
            symmetricState.encryptAndHash(s.publicKey.data, into: &buffer) // TODO: offfset!
            symmetricState.mixKey(s.DH(rs))
        }
    }
}

extension Responder {
    public class X: Handshake {
        let s: KeyPair
        
        public var rs: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "X")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 1)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(s.DH(re))
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = PublicKey(from: try symmetricState.decryptAndHash(suffix))
            symmetricState.mixKey(s.DH(rs!))
            offset = 2 * PublicKey.length + 16
        }
    }
}


// NNpsk2:
//  -> e
//  <- e, ee, psk

extension Initiator {
    public class NNpsk2: Handshake {
        let psk: [UInt8]
        let e = KeyPair()
        
        public init<D: DataProtocol>(psk: D) {
            self.psk = .init(psk)
            super.init(.initiator, "NNpsk2")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 2)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(e.DH(re))
            symmetricState.mixKey(psk)
        }
    }
}

extension Responder {
    public class NNpsk2: Handshake {
        let psk: [UInt8]
        let e = KeyPair()
        var re: PublicKey?
        
        public init<D: DataProtocol>(psk: D) {
            self.psk = .init(psk)
            super.init(.responder, "NNpsk2")
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 2)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(re!))
            symmetricState.mixKey(psk)
        }
    }
}


// KK:
//  -> s
//  <- s
//  ...
//  -> e, es, ss
//  <- e, ee, se

extension Initiator {
    public class KK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "KK")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(rs))
            symmetricState.mixKey(s.DH(rs))
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 2)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(e.DH(re))
            symmetricState.mixKey(s.DH(re))
        }
    }
}

extension Responder {
    public class KK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        var re: PublicKey?

        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.responder, "KK")
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
            symmetricState.mixKey(s.DH(re!))
            symmetricState.mixKey(s.DH(rs))
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 2)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(re!))
            symmetricState.mixKey(e.DH(rs))
        }
    }
}


// NK:
//  <- s
//  ...
//  -> e, es
//  <- e, ee

extension Initiator {
    public class NK: Handshake {
        let e = KeyPair()
        let rs: PublicKey
        
        public init(their rs: PublicKey) {
            self.rs = rs
            super.init(.initiator, "NK")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(rs))
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 2)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(e.DH(re))
        }
    }
}

extension Responder {
    public class NK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "NK")
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
            symmetricState.mixKey(s.DH(re!))
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 2)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(re!))
        }
    }
}

// NX:
//  -> e
//  <- e, ee, s, es

extension Initiator {
    public class NX: Handshake {
        let e = KeyPair()
        
        public var rs: PublicKey?
        
        public init() {
            super.init(.initiator, "NX")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 2)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(e.DH(re))
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = PublicKey(from: try symmetricState.decryptAndHash(suffix))
            symmetricState.mixKey(e.DH(rs!))
        }
    }
}

extension Responder {
    public class NX: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?

        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "NX")
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            longOperation(order: 2)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(re!))
            symmetricState.encryptAndHash(s.publicKey.data, into: &buffer)
            symmetricState.mixKey(s.DH(re!))
        }
    }
}


// XX:
//  -> e
//  <- e, ee, s, es
//  -> s, se

extension Initiator {
    public class XX: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public var rs: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.initiator, "XX")
        }
        
        public func firstWrite<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 2)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
            symmetricState.mixKey(e.DH(re!))
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = PublicKey(from: try symmetricState.decryptAndHash(suffix))
            symmetricState.mixKey(e.DH(rs!))
        }
        
        public func secondWrite<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 3)
            symmetricState.encryptAndHash(s.publicKey.data, into: &buffer)
            symmetricState.mixKey(s.DH(re!))
        }
    }
}

extension Responder {
    public class XX: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public var rs: PublicKey?

        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "XX")
        }
        
        public func firstRead<D: DataProtocol>(from buffer: D) {
            operation(order: 1)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            longOperation(order: 2)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(re!))
            symmetricState.encryptAndHash(s.publicKey.data, into: &buffer)
            symmetricState.mixKey(s.DH(re!))
        }
        
        public func secondRead<D: DataProtocol>(from buffer: D) throws {
            operation(order: 3)
            rs = PublicKey(from: try symmetricState.decryptAndHash(buffer))
            symmetricState.mixKey(e.DH(rs!))
        }
    }
}

// IK:
//  <- s
//  ...
//  -> e, es, s, ss
//  <- e, ee, se

extension Initiator {
    public class IK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        var re: PublicKey?
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "IK")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            longOperation(order: 1)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(rs))
            symmetricState.encryptAndHash(s.publicKey.data, into: &buffer)
            symmetricState.mixKey(s.DH(rs))
        }
        
        public func read<D: DataProtocol>(from buffer: D) {
            operation(order: 2)
            let re = PublicKey(from: buffer)
            symmetricState.mixHash(re.data)
            symmetricState.mixKey(e.DH(re))
            symmetricState.mixKey(s.DH(re))
        }
    }
}

extension Responder {
    public class IK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public var rs: PublicKey?

        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "IK")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 1)
            re = PublicKey(from: buffer)
            symmetricState.mixHash(re!.data)
            symmetricState.mixKey(s.DH(re!))
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = PublicKey(from: try symmetricState.decryptAndHash(suffix))
            symmetricState.mixKey(s.DH(rs!))
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 2)
            buffer.append(contentsOf: e.publicKey.data)
            symmetricState.mixHash(e.publicKey.data)
            symmetricState.mixKey(e.DH(re!))
            symmetricState.mixKey(e.DH(rs!))
        }
    }
}
