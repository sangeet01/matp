@echo off
echo ========================================
echo Matryoshka Protocol - PyPI Upload Script
echo ========================================
echo.

echo Step 1: Installing build tools...
pip install --upgrade build twine
echo.

echo Step 2: Cleaning old builds...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist matryoshka_protocol.egg-info rmdir /s /q matryoshka_protocol.egg-info
echo.

echo Step 3: Running tests...
python test_matryoshka.py
if errorlevel 1 (
    echo Tests failed! Fix errors before uploading.
    pause
    exit /b 1
)
echo.

echo Step 4: Building package...
python -m build
if errorlevel 1 (
    echo Build failed! Check setup.py
    pause
    exit /b 1
)
echo.

echo Step 5: Ready to upload!
echo.
echo Choose upload destination:
echo 1. TestPyPI (recommended for first upload)
echo 2. Real PyPI (production)
echo 3. Cancel
echo.
set /p choice="Enter choice (1-3): "

if "%choice%"=="1" (
    echo.
    echo Uploading to TestPyPI...
    echo Username: __token__
    echo Password: [paste your TestPyPI token]
    python -m twine upload --repository testpypi dist/*
    echo.
    echo Test installation with:
    echo pip install --index-url https://test.pypi.org/simple/ matryoshka-protocol
)

if "%choice%"=="2" (
    echo.
    echo WARNING: Uploading to REAL PyPI!
    echo This cannot be undone. Are you sure? (Y/N)
    set /p confirm="Confirm: "
    if /i "%confirm%"=="Y" (
        echo.
        echo Uploading to PyPI...
        echo Username: __token__
        echo Password: [paste your PyPI token]
        python -m twine upload dist/*
        echo.
        echo Package uploaded! Install with:
        echo pip install matryoshka-protocol
    )
)

if "%choice%"=="3" (
    echo Upload cancelled.
)

echo.
pause