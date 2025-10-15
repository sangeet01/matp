# Basic Usage Examples

## Python Quick Start

### Installation
```bash
pip install matp
```

### Simple Messaging
```python
from matp import MatryoshkaProtocol

# Initialize protocol
alice = MatryoshkaProtocol()
bob = MatryoshkaProtocol()

# Exchange keys (in practice, use DHT)
shared_key = b"shared_secret_key_32_bytes_long!"

# Alice sends message
message = "Hello Bob!"
ciphertext = alice.encrypt(message, shared_key)

# Bob receives message
plaintext = bob.decrypt(ciphertext, shared_key)
print(plaintext)  # "Hello Bob!"
```

### Steganography (Ghost Mode)
```python
# Alice sends hidden message
cover_traffic = alice.send_message(
    message="Secret message",
    key=shared_key,
    cover_type="json_api"
)

# Looks like normal API response:
# {"users": [...], "status": "ok", "timestamp": 1234567890}

# Bob extracts message
extracted = bob.receive_message(cover_traffic, shared_key)
print(extracted)  # "Secret message"
```

### Fractal Recovery
```python
# Simulate key compromise
compromised_key = shared_key

# Continue with 3 new exchanges
for i in range(3):
    msg = alice.send_message(f"Recovery {i}", shared_key)
    bob.receive_message(msg, shared_key)

# Security restored! Old compromised_key can't decrypt new messages
```

### Innocence Proof (ZKP)
```python
# Alice generates proof she could have sent innocent traffic
proof = alice.generate_innocence_proof(cover_traffic)

# Anyone can verify (without learning the secret)
is_innocent = bob.verify_innocence_proof(cover_traffic, proof)
print(is_innocent)  # True - plausible deniability achieved
```

## Rust Quick Start

### Add Dependency
```toml
[dependencies]
matryoshka-protocol = "0.1"
```

### Simple Messaging
```rust
use matryoshka_protocol::{Session, SessionConfig};

fn main() {
    // Initialize sessions
    let alice = Session::new(SessionConfig::default());
    let bob = Session::new(SessionConfig::default());
    
    // Exchange keys
    let shared_key = b"shared_secret_key_32_bytes_long!";
    
    // Alice encrypts
    let ciphertext = alice.encrypt(b"Hello Bob!", shared_key).unwrap();
    
    // Bob decrypts
    let plaintext = bob.decrypt(&ciphertext, shared_key).unwrap();
    println!("{}", String::from_utf8(plaintext).unwrap());
}
```

### Ghost Steganography
```rust
use matryoshka_protocol::ghost::{GhostEngine, CoverType};

fn main() {
    let ghost = GhostEngine::new();
    
    // Embed message
    let cover = ghost.embed(
        b"Secret message",
        CoverType::JsonApi,
        None
    ).unwrap();
    
    // Extract message
    let message = ghost.extract(&cover).unwrap();
    println!("{}", String::from_utf8(message).unwrap());
}
```

## Advanced Examples

### Custom Cover Traffic
```python
# Train on your own traffic patterns
alice.train_cover_model("my_traffic_logs.json")

# Generate matching cover
cover = alice.send_message(
    message="Hidden",
    key=shared_key,
    cover_type="custom",
    cover_template={"pattern": "my_api"}
)
```

### Quantum-Resistant Mode
```rust
use matryoshka_protocol::crypto::HybridCrypto;

let crypto = HybridCrypto::new();
let ciphertext = crypto.encrypt_quantum_safe(message, key);
```

### DHT Key Discovery
```rust
use matryoshka_protocol::dht::KademliaNode;

let node = KademliaNode::new("0.0.0.0:8080");
node.put(user_id, public_key).await?;
let peer_key = node.get(peer_id).await?;
```

## Performance Tips

1. **Reuse Sessions**: Don't create new protocol instances per message
2. **Batch Messages**: Send multiple messages in one cover traffic
3. **Cache Cover Templates**: Pre-generate cover traffic patterns
4. **Async I/O**: Use async for network operations
5. **Hardware Acceleration**: Enable AES-NI for encryption

## Security Best Practices

1. **Key Storage**: Never hardcode keys, use secure storage
2. **Random Keys**: Generate keys with cryptographic RNG
3. **Verify Peers**: Use out-of-band verification for public keys
4. **Update Regularly**: Rotate keys every 30 days
5. **Audit Logs**: Monitor for unusual patterns
