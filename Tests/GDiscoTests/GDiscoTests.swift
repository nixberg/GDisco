import XCTest
@testable import GDisco

final class GDiscoTests: XCTestCase {
    let iStatic = KeyPair()
    let rStatic = KeyPair()
    
    func greet(_ a: Handshake, _ b: Handshake, line: UInt = #line) {
        let a = a.finalize()
        let b = b.finalize()
        
        let m1 = "Hi, Bob!".data(using: .utf8)!
        let m2 = "Also, ...".data(using: .utf8)!

        var e1 = Data()
        var e2 = Data()
        var d1 = Data()
        var d2 = Data()
        
        a.encrypt(plaintext: m1, into: &e1)
        a.encrypt(plaintext: m2, into: &e2)
        try! b.decrypt(ciphertext: e1, into: &d1)
        try! b.decrypt(ciphertext: e2, into: &d2)
        XCTAssertEqual(m1, d1, line: line)
        XCTAssertEqual(m2, d2, line: line)
        
        e1 = Data()
        e2 = Data()
        d1 = Data()
        d2 = Data()
        
        b.encrypt(plaintext: m1, into: &e1)
        b.encrypt(plaintext: m2, into: &e2)
        try! a.decrypt(ciphertext: e1, into: &d1)
        try! a.decrypt(ciphertext: e2, into: &d2)
        XCTAssertEqual(m1, d1, line: line)
        XCTAssertEqual(m2, d2, line: line)
    }
    
    func testK() {
        let iHandshake = Handshake.I.K(my: iStatic, their: rStatic.publicKey)
        let rHandshake = Handshake.R.K(my: rStatic, their: iStatic.publicKey)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        
        greet(iHandshake, rHandshake)
    }
    
    func testN() {
        let iHandshake = Handshake.I.N(their: rStatic.publicKey)
        let rHandshake = Handshake.R.N(my: rStatic)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        
        greet(iHandshake, rHandshake)
    }
    
    func testX() {
        let iHandshake = Handshake.I.X(my: iStatic, their: rStatic.publicKey)
        let rHandshake = Handshake.R.X(my: rStatic)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        let rrs = try! rHandshake.readStatic(from: networkBuffer)
        
        XCTAssertEqual(iStatic.publicKey.data, rrs.data)

        greet(iHandshake, rHandshake)
    }
    
    func testNNpsk2() {
        let psk = Data.random(count: 32)!
        
        let iHandshake = Handshake.I.NNpsk2(psk: psk)
        let rHandshake = Handshake.R.NNpsk2(psk: psk)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        rHandshake.write(to: &networkBuffer)
        try! iHandshake.read(from: networkBuffer)

        greet(iHandshake, rHandshake)
    }
    
    func testKK() {
        let iHandshake = Handshake.I.KK(my: iStatic, their: rStatic.publicKey)
        let rHandshake = Handshake.R.KK(my: rStatic, their: iStatic.publicKey)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        rHandshake.write(to: &networkBuffer)
        try! iHandshake.read(from: networkBuffer)
        
        greet(iHandshake, rHandshake)
    }

    func testNK() {
        let iHandshake = Handshake.I.NK(their: rStatic.publicKey)
        let rHandshake = Handshake.R.NK(my: rStatic)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        rHandshake.write(to: &networkBuffer)
        try! iHandshake.read(from: networkBuffer)
        
        greet(iHandshake, rHandshake)
    }
    
    func testNX() {
        let iHandshake = Handshake.I.NX()
        let rHandshake = Handshake.R.NX(my: rStatic)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        rHandshake.write(to: &networkBuffer)
        let irs = try! iHandshake.readStatic(from: networkBuffer)
        
        XCTAssertEqual(rStatic.publicKey.data, irs.data)

        greet(iHandshake, rHandshake)
    }
    
    func testXX() {
        let iHandshake = Handshake.I.XX(my: iStatic)
        let rHandshake = Handshake.R.XX(my: rStatic)

        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        try! rHandshake.read(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        rHandshake.write(to: &networkBuffer)
        let irs = try! iHandshake.readStatic(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        iHandshake.write(to: &networkBuffer)
        let rrs = try! rHandshake.readStatic(from: networkBuffer)
        
        XCTAssertEqual(iStatic.publicKey.data, rrs.data)
        XCTAssertEqual(rStatic.publicKey.data, irs.data)

        greet(iHandshake, rHandshake)
    }
    
    func testIK() {
        let iHandshake = Handshake.I.IK(my: iStatic, their: rStatic.publicKey)
        let rHandshake = Handshake.R.IK(my: rStatic)
        
        var networkBuffer = Data()
        iHandshake.write(to: &networkBuffer)
        let rrs = try! rHandshake.readStatic(from: networkBuffer)
        networkBuffer.removeAll(keepingCapacity: true)
        rHandshake.write(to: &networkBuffer)
        try! iHandshake.read(from: networkBuffer)
        
        XCTAssertEqual(iStatic.publicKey.data, rrs.data)
        
        greet(iHandshake, rHandshake)
    }
    
    static var allTests = [
        ("K", testK),
        ("N", testN),
        ("X", testX),
        ("NNpsk2", testNNpsk2),
        ("KK", testKK),
        ("NK", testNK),
        ("NX", testNX),
        ("XX", testXX),
        ("IK", testIK),
    ]
}
