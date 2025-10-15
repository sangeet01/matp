# Contributing to Matryoshka Protocol

Thank you for your interest in contributing to Matryoshka Protocol!

## Areas of Interest

We welcome contributions in:
- **Cryptographic Review** - Security analysis and formal verification
- **Performance Optimization** - Faster encryption, steganography, ZKP generation
- **Cover Traffic Types** - New steganography methods (images, video, DNS)
- **Mobile Implementations** - iOS and Android SDKs
- **Documentation** - Tutorials, examples, translations
- **Testing** - Unit tests, integration tests, fuzzing

## Getting Started

1. **Fork the repository**
2. **Clone your fork**: `git clone https://github.com/YOUR_USERNAME/matp.git`
3. **Create a branch**: `git checkout -b feature/your-feature`
4. **Make changes**
5. **Test**: Run test suite to ensure nothing breaks
6. **Commit**: `git commit -m "Add: your feature description"`
7. **Push**: `git push origin feature/your-feature`
8. **Open Pull Request**

## Code Standards

### Python
- Follow PEP 8 style guide
- Add docstrings to all functions
- Include type hints where possible
- Write tests for new features

### Rust
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Add documentation comments (`///`)
- Write unit tests for new modules

## Security Contributions

If you discover a security vulnerability:
1. **DO NOT** open a public issue
2. Email the maintainer directly (see README)
3. Include detailed description and proof-of-concept
4. Allow time for patch before public disclosure

## Pull Request Process

1. Update documentation for any API changes
2. Add tests covering your changes
3. Ensure all tests pass
4. Update CHANGELOG.md with your changes
5. Request review from maintainers

## Questions?

Open an issue with the `question` label or contact the maintainer.

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
