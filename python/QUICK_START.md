# 🚀 Quick Start - Upload to PyPI

## **3 Simple Steps to Publish**

### 1️⃣ **Install Tools** (One-time setup)
```bash
pip install build twine
```

### 2️⃣ **Get PyPI Token** (One-time setup)
1. Go to https://pypi.org/account/register/
2. Create account
3. Go to https://pypi.org/manage/account/token/
4. Create token
5. **Save it!** (starts with `pypi-`)

### 3️⃣ **Upload Package**

#### **Windows:**
```bash
# Double-click this file:
upload_to_pypi.bat

# Or run manually:
python -m build
python -m twine upload dist/*
```

#### **Linux/Mac:**
```bash
# Build
python -m build

# Upload
python -m twine upload dist/*

# Enter credentials:
# Username: __token__
# Password: pypi-YOUR_TOKEN_HERE
```

---

## ✅ **That's It!**

Your package is now on PyPI!

**Install it anywhere:**
```bash
pip install matryoshka-protocol
```

**Use it:**
```python
from test_matryoshka import MatryoshkaProtocol

mtp = MatryoshkaProtocol()
msg = mtp.send_message("Secret message!")
```

---

## 📖 **Full Guide**

See `PYPI_UPLOAD_GUIDE.md` for detailed instructions.

---

## 🎯 **Current Package Status**

- ✅ Package structure ready
- ✅ Tests passing
- ✅ Documentation complete
- ✅ License included
- ✅ Ready to upload!

**Just run `upload_to_pypi.bat` and follow the prompts!**