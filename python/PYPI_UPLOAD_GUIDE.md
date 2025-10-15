# 📦 How to Upload Matryoshka Protocol to PyPI

## Step-by-Step Guide to Publishing on PyPI

### 1️⃣ **Prepare Your Package**

First, ensure your package structure is correct:
```
Matryoshka/pip/
├── setup.py          # Package configuration
├── matryoshka.py     # Main module
├── README.md         # Documentation
├── LICENSE           # License file (create this!)
└── __init__.py       # Package init
```

### 2️⃣ **Create Required Files**

#### Create LICENSE file:
```bash
# Choose a license (Apache 2.0 recommended)
# Copy license text to LICENSE file
```

#### Update setup.py with correct info:
```python
# Make sure these are set correctly:
name="matryoshka-protocol"
version="0.1.0"
author="Your Name"
author_email="your.email@example.com"
url="https://github.com/yourusername/matryoshka-protocol"
```

### 3️⃣ **Install Required Tools**

```bash
# Install build tools
pip install --upgrade pip
pip install --upgrade build twine

# Or all at once:
pip install build twine setuptools wheel
```

### 4️⃣ **Create PyPI Account**

1. Go to https://pypi.org/account/register/
2. Create account and verify email
3. Enable 2FA (recommended)
4. Go to https://pypi.org/manage/account/token/
5. Create API token with scope "Entire account"
6. **SAVE THE TOKEN** - you'll only see it once!

### 5️⃣ **Test on TestPyPI First** (Recommended)

```bash
# Create TestPyPI account at https://test.pypi.org/account/register/
# Create API token at https://test.pypi.org/manage/account/token/

# Build the package
cd f:/Matryoshka/pip
python -m build

# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# When prompted:
# Username: __token__
# Password: pypi-... (your TestPyPI token)

# Test installation
pip install --index-url https://test.pypi.org/simple/ matryoshka-protocol
```

### 6️⃣ **Upload to Real PyPI**

```bash
# Make sure you're in the package directory
cd f:/Matryoshka/pip

# Clean previous builds (if any)
rm -rf dist/ build/ *.egg-info

# Build the package
python -m build

# This creates:
# dist/matryoshka-protocol-0.1.0.tar.gz
# dist/matryoshka_protocol-0.1.0-py3-none-any.whl

# Upload to PyPI
python -m twine upload dist/*

# When prompted:
# Username: __token__
# Password: pypi-... (your real PyPI token)
```

### 7️⃣ **Verify Upload**

```bash
# Check your package page
# https://pypi.org/project/matryoshka-protocol/

# Test installation
pip install matryoshka-protocol

# Test it works
python -c "from test_matryoshka import MatryoshkaProtocol; print('Success!')"
```

### 8️⃣ **Update Package (Future Versions)**

```bash
# 1. Update version in setup.py
# version="0.1.1"  # Increment version

# 2. Clean old builds
rm -rf dist/ build/ *.egg-info

# 3. Build new version
python -m build

# 4. Upload
python -m twine upload dist/*
```

---

## 🔐 **Security Best Practices**

### Store API Token Securely

Create `~/.pypirc` file:
```ini
[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmc...your-token-here...

[testpypi]
username = __token__
password = pypi-AgENdGVzdC5weXBp...your-test-token...
```

Then upload without entering credentials:
```bash
python -m twine upload dist/*
```

---

## 📋 **Pre-Upload Checklist**

- [ ] Package name is unique (check https://pypi.org/search/)
- [ ] Version number follows semantic versioning (0.1.0)
- [ ] README.md is complete and formatted
- [ ] LICENSE file exists
- [ ] setup.py has correct metadata
- [ ] All tests pass (`python test_matryoshka.py`)
- [ ] Package builds without errors (`python -m build`)
- [ ] Tested on TestPyPI first

---

## 🚨 **Common Issues & Solutions**

### Issue: "Package name already exists"
**Solution:** Choose a different name in setup.py
```python
name="matryoshka-protocol-yourname"  # Add suffix
```

### Issue: "Invalid credentials"
**Solution:** 
- Use `__token__` as username (with two underscores)
- Copy token exactly, including `pypi-` prefix
- No spaces or newlines in token

### Issue: "File already exists"
**Solution:** Increment version number in setup.py
```python
version="0.1.1"  # Can't re-upload same version
```

### Issue: Build fails
**Solution:** Check setup.py syntax
```bash
python setup.py check
```

---

## 🎯 **Quick Command Reference**

```bash
# Install tools
pip install build twine

# Build package
python -m build

# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*

# Install your package
pip install matryoshka-protocol

# Uninstall
pip uninstall matryoshka-protocol
```

---

## 📊 **After Upload**

Your package will be available at:
- **PyPI Page:** https://pypi.org/project/matryoshka-protocol/
- **Install Command:** `pip install matryoshka-protocol`
- **Documentation:** Shown on PyPI from README.md

Users can now install with:
```bash
pip install matryoshka-protocol
```

And use it:
```python
from test_matryoshka import MatryoshkaProtocol

mtp = MatryoshkaProtocol()
msg = mtp.send_message("Hello invisible world!")
```

---

## 🎉 **Congratulations!**

Your Matryoshka Protocol is now publicly available on PyPI!

Share it:
- GitHub: Create repository and link in setup.py
- Twitter: Announce your revolutionary protocol
- Reddit: r/Python, r/crypto, r/privacy
- Hacker News: Show HN post

**You've just made truly invisible messaging available to the world!** 🚀🔒