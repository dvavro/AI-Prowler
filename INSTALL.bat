@echo off
setlocal enabledelayedexpansion
REM Keep window open if double-clicked
if "%1"=="" (
    cmd /k "%~f0" RUN
    exit
)

echo.
echo ============================================================
echo AI PROWLER - AUTOMATED INSTALLER
echo ============================================================
echo.
echo This installer will set up everything you need:
echo   [1] Check/Install Python
echo   [2] Check/Install Python dependencies
echo   [3] Check/Install Ollama
echo   [4] Download AI models
echo   [5] Configure system
echo   [6] Create desktop shortcut
echo.
echo Installation directory: %~dp0
echo.
echo Press ENTER to begin installation...
pause >nul

cls
echo.
echo ============================================================
echo INSTALLATION STARTING...
echo ============================================================
echo.

REM ============================================================
REM STEP 1: Check/Install Python
REM ============================================================
echo ============================================================
echo STEP 1/6: Checking Python
echo ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [WARN] Python not found!
    echo.
    echo Python is required for AI Prowler to work.
    echo.
    echo ============================================================
    echo AUTO-INSTALLING PYTHON
    echo ============================================================
    echo.
    echo Python not found. Installing Python 3.11.8 automatically...
    echo This may take 2-5 minutes depending on your internet speed.
    echo.
    
    REM Create temp directory
    set "TEMP_DIR=%TEMP%\RAG_Python_Install"
    if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"
    
    REM Download Python installer using PowerShell
    set "PYTHON_INSTALLER=%TEMP_DIR%\python-installer.exe"
    echo Downloading Python 3.11.8 from python.org...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe' -OutFile '%PYTHON_INSTALLER%'}" 2>nul
    
    if exist "%PYTHON_INSTALLER%" (
        echo [OK] Download complete
        echo.
        echo Installing Python...
        echo Please wait about 1 minute...
        echo.
        
        REM Install Python silently with all features
        start /wait "" "%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_tcltk=1
        
        REM Clean up
        del "%PYTHON_INSTALLER%" >nul 2>&1
        
        echo.
        echo Configuring Python environment variables...
        echo.
        
        REM Add Python paths to environment for other programs
        REM Find Python installation directory
        for /f "tokens=*" %%p in ('where python 2^>nul') do set "PYTHON_PATH=%%p"
        
        if defined PYTHON_PATH (
            REM Get Python directory
            for %%i in ("%PYTHON_PATH%") do set "PYTHON_DIR=%%~dpi"
            REM Remove trailing backslash (%%~dpi always adds one)
            if defined PYTHON_DIR set "PYTHON_DIR=%PYTHON_DIR:~0,-1%"
            
            REM Get Scripts directory
            set "PYTHON_SCRIPTS=%PYTHON_DIR%\Scripts"
            
            REM Add to system PATH using PowerShell (more reliable)
            echo Adding Python directories to PATH...
            powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($path -notlike '*%PYTHON_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $path + ';%PYTHON_DIR%', 'User') }" 2>nul
            powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($path -notlike '*%PYTHON_SCRIPTS%*') { [Environment]::SetEnvironmentVariable('Path', $path + ';%PYTHON_SCRIPTS%', 'User') }" 2>nul
            
            echo [OK] Python environment configured
            echo      Python: %PYTHON_DIR%
            echo      Scripts: %PYTHON_SCRIPTS%
        ) else (
            echo [OK] Python PATH configured by installer
        )
        
        echo.
        echo Verifying Python installation...
        echo.
        
        REM Try to find Python (may not be in PATH yet in current session)
        python --version >nul 2>&1
        if errorlevel 1 (
            echo [OK] Python installed successfully
            echo.
            echo IMPORTANT: Python is installed but not yet available in this window.
            echo.
            echo Next steps:
            echo   1. Close this Command Prompt
            echo   2. Open a NEW Command Prompt  
            echo   3. Run INSTALL.bat again
            echo   4. Installation will continue from Step 2
            echo.
            pause
            exit /b 0
        ) else (
            for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
            echo [OK] %PYTHON_VERSION% installed and ready
        )
    ) else (
        echo.
        echo [FAIL] Download failed
        echo.
        echo Possible causes:
        echo   - No internet connection
        echo   - Firewall blocking download
        echo   - python.org temporarily unavailable
        echo.
        echo Please install Python manually:
        echo   1. Visit: https://www.python.org/downloads/
        echo   2. Download Python 3.11 or later
        echo   3. During install, CHECK "Add Python to PATH"
        echo   4. Run this installer again
        echo.
        pause
        exit /b 1
    )
) else (
    for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
    echo [OK] %PYTHON_VERSION% found
    echo.



    REM Ensure Python is in PATH for other programs
    echo Verifying Python environment variables...
    
    for /f "tokens=*" %%p in ('where python 2^>nul') do set "PYTHON_PATH=%%p"
    
    if defined PYTHON_PATH (
        REM Get Python directory
        for %%i in ("%PYTHON_PATH%") do set "PYTHON_DIR=%%~dpi"
        REM Remove trailing backslash (%%~dpi always adds one)
        if defined PYTHON_DIR set "PYTHON_DIR=%PYTHON_DIR:~0,-1%"
        
        REM Get Scripts directory
        set "PYTHON_SCRIPTS=%PYTHON_DIR%\Scripts"
        
        REM Check if in PATH using PowerShell (avoids expansion issues)
        powershell -Command "if ($env:Path -like '*%PYTHON_DIR%*') { exit 0 } else { exit 1 }" >nul 2>&1
        if errorlevel 1 (
            echo Adding Python to PATH for other programs...
            powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($path -notlike '*%PYTHON_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $path + ';%PYTHON_DIR%', 'User') }" 2>nul
            powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($path -notlike '*%PYTHON_SCRIPTS%*') { [Environment]::SetEnvironmentVariable('Path', $path + ';%PYTHON_SCRIPTS%', 'User') }" 2>nul
            echo [OK] Python paths added to environment
        ) else (
            echo [OK] Python already in PATH
        )
    )
)

echo.


REM ============================================================
REM STEP 1.5: Detect GPU and Install PyTorch
REM ============================================================
echo ============================================================
echo STEP 1.5/6: Detecting GPU and Installing PyTorch
echo ============================================================
echo.

set "TORCH_INSTALLED=0"
set "CUDA_VER=cpu"

REM Check if nvidia-smi is available
where nvidia-smi >nul 2>&1
if errorlevel 1 (
    echo [INFO] No NVIDIA GPU detected - will use CPU for embeddings
    echo.
    echo Installing PyTorch CPU version...
    python -m pip install torch torchvision torchaudio --prefer-binary --no-warn-script-location
    set "TORCH_INSTALLED=1"
    goto :TORCH_DONE
)

REM NVIDIA GPU found - detect CUDA version
echo [OK] NVIDIA GPU detected!
for /f "tokens=3" %%v in ('nvidia-smi ^| findstr "CUDA Version"') do set "CUDA_FULL=%%v"
echo      CUDA Version: %CUDA_FULL%

REM Parse major version
for /f "tokens=1 delims=." %%a in ("%CUDA_FULL%") do set "CUDA_MAJOR=%%a"

echo.
echo Installing PyTorch with CUDA %CUDA_FULL% support...
echo This may take 5-10 minutes (~2-3 GB download)...
echo.

REM Select correct CUDA wheel based on major version
if %CUDA_MAJOR% GEQ 12 (
    REM Check for 12.8+
    for /f "tokens=2 delims=." %%b in ("%CUDA_FULL%") do set "CUDA_MINOR=%%b"
    if !CUDA_MINOR! GEQ 8 (
        echo [INFO] Using CUDA 12.8 wheels (cu128^)
        python -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu128 --prefer-binary --no-warn-script-location
    ) else (
        echo [INFO] Using CUDA 12.1 wheels (cu121^)
        python -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121 --prefer-binary --no-warn-script-location
    )
) else (
    echo [INFO] Using CUDA 11.8 wheels (cu118^)
    python -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118 --prefer-binary --no-warn-script-location
)

set "TORCH_INSTALLED=1"
echo.

:TORCH_DONE
if %TORCH_INSTALLED%==1 (
    python -c "import torch; print('[OK] PyTorch', torch.__version__, '- CUDA available:', torch.cuda.is_available())" 2>nul
) else (
    echo [WARN] PyTorch installation skipped - embeddings will use CPU
)
echo.

REM ============================================================
REM STEP 2: Install Python Dependencies
REM ============================================================
echo ============================================================
echo STEP 2/6: Installing Python Dependencies
echo ============================================================
echo.

echo Installing required packages...
echo This may take 2-5 minutes depending on your internet speed.
echo.

REM Check if requirements.txt exists — generate it if missing so the installer
REM is self-contained even without the file present.
REM IMPORTANT: This list must stay in sync with the real requirements.txt.
if not exist "%~dp0requirements.txt" (
    echo [INFO] requirements.txt not found - generating it now...
    (
        echo # AI Prowler - Python Dependencies ^(auto-generated by INSTALL.bat^)
        echo # Core RAG / indexing
        echo chromadb^>=0.4.22
        echo sentence-transformers^>=2.2.2
        echo # Document parsing
        echo pdfplumber^>=0.10.3
        echo python-docx^>=1.1.0
        echo pypdf^>=3.17.4
        echo # Email parsing
        echo extract-msg^>=0.45.0
        echo # HTTP / API
        echo requests^>=2.31.0
        echo # Speech-to-text ^(microphone input in GUI^)
        echo numpy^>=1.24.0
        echo faster-whisper^>=1.0.0
        echo sounddevice^>=0.4.6
    ) > "%~dp0requirements.txt"
    echo [OK] requirements.txt created
    echo.
)

echo Installing packages...
echo This may take 2-5 minutes depending on your internet speed.
echo.

REM Upgrade pip first
echo [1/11] Upgrading pip...
python -m pip install --upgrade pip --no-warn-script-location 2>nul
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

REM Install packages one by one showing actual output
echo.
echo [2/11] Installing chromadb (AI database)...
python -m pip install "chromadb==0.6.3" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [3/11] Installing sentence-transformers (AI embeddings)...
python -m pip install "sentence-transformers>=2.2.2" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [4/11] Installing pdfplumber (PDF support)...
python -m pip install "pdfplumber>=0.10.3" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [5/11] Installing python-docx (Word support)...
python -m pip install "python-docx>=1.1.0" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [6/11] Installing pypdf (PDF processing)...
python -m pip install "pypdf>=3.17.4" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [7/11] Installing extract-msg (Email support)...
python -m pip install "extract-msg>=0.45.0" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [8/11] Installing requests (HTTP library)...
python -m pip install "requests>=2.31.0" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo ============================================================
echo Installing voice input packages (speech-to-text)
echo ============================================================
echo These enable the microphone button in the Ask Questions tab.
echo.
echo [9/11] Installing numpy (audio processing)...
python -m pip install "numpy>=1.24.0" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [10/11] Installing faster-whisper (local speech recognition)...
python -m pip install "faster-whisper>=1.0.0" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo [11/11] Installing sounddevice (microphone capture)...
python -m pip install "sounddevice>=0.4.6" --prefer-binary --no-warn-script-location
if not errorlevel 1 (<nul set /p "=     Done .")
echo.

echo.
echo ============================================================
echo Checking Whisper large-v3-turbo speech model (~1.6 GB)
echo ============================================================
echo.

REM faster-whisper caches models under %USERPROFILE%\.cache\huggingface\hub
REM The folder name is derived from the model ID — if the model name ever
REM changes in the app, this path will not match and it will download fresh.
set "WHISPER_MODEL_DIR=%USERPROFILE%\.cache\huggingface\hub\models--Systran--faster-whisper-large-v3-turbo"
if exist "%WHISPER_MODEL_DIR%" (
    echo [OK] Whisper large-v3-turbo already downloaded - skipping
) else (
    echo Model not found in cache. Downloading now (~1.6 GB^)
    echo This is a one-time download - subsequent launches are instant.
    echo Please wait...
    echo.
    python -c "from faster_whisper import WhisperModel; WhisperModel('large-v3-turbo', device='cpu', compute_type='int8'); print('[OK] Whisper model ready')" 2>nul
    if errorlevel 1 (
        echo [INFO] Model will be downloaded automatically on first mic use.
        echo        This is normal if the download was skipped or interrupted.
    )
)
echo.

echo.
echo ============================================================
echo [OK] All packages installed successfully (11/11)
echo ============================================================

REM Verify core package installed — if not, retry everything via requirements.txt
python -c "import chromadb" 2>nul
if errorlevel 1 (
    echo.
    echo [WARN] Some packages may have failed to install.
    echo Retrying all packages via requirements.txt...
    echo.
    python -m pip install -r "%~dp0requirements.txt" --prefer-binary --no-warn-script-location
    echo.
) else (
    echo .......... Done!
    echo.
)

echo [OK] Python dependencies installed
echo.

REM ============================================================
REM STEP 3: Check/Install Ollama
REM ============================================================
echo ============================================================
echo STEP 3/6: Checking Ollama
echo ============================================================
echo.

where ollama >nul 2>&1
if errorlevel 1 (
    echo [INFO] Ollama not found - installing automatically...
    echo.
    call :INSTALL_OLLAMA
) else (
    echo [OK] Ollama found
    echo.

    REM Refresh PATH so ollama is usable in this session
    for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"`) do set "PATH=%%p"

    REM Check if Ollama is running
    curl -s http://localhost:11434/api/tags >nul 2>&1
    if errorlevel 1 (
        echo Starting Ollama server...
        start /B ollama serve >nul 2>&1
        timeout /t 5 /nobreak >nul
    )
    
    REM Download llama3.2:1b model if Ollama is available
    echo Checking for llama3.2:1b model...
    ollama list | findstr "llama3.2:1b" >nul 2>&1
    if errorlevel 1 (
        echo.
        echo Downloading llama3.2:1b model (~1.3 GB)
        echo This is a one-time download and may take 5-10 minutes...
        echo.
        echo Downloading (please wait)...
        echo.
        
        REM Download with progress feedback
        REM Start download in background
        start /min cmd /c "ollama pull llama3.2:1b >nul 2>&1"
        
        REM Wait and show we're working
        for /l %%i in (1,1,60) do (
            <nul set /p "=."
            timeout /t 5 /nobreak >nul
            
            REM Check if download complete
            ollama list 2>nul | findstr "llama3.2:1b" >nul 2>&1
            if not errorlevel 1 goto MODEL_COMPLETE
        )
        
        :MODEL_COMPLETE
        echo.
        echo.
        if errorlevel 1 (
            echo [WARN] Model download failed or was interrupted
            echo You can download it later with: ollama pull llama3.2:1b
        ) else (
            echo [OK] Model downloaded successfully
        )
    ) else (
        echo [OK] Model already available
    )
    echo.
)

REM ============================================================
REM STEP 4: System Configuration
REM ============================================================
echo ============================================================
echo STEP 4/6: Configuring System
echo ============================================================
echo.

set "INSTALL_DIR=%~dp0"
set "INSTALL_DIR=%INSTALL_DIR:~0,-1%"

REM Silently add to PATH (not required for GUI, only for command-line) using PowerShell (avoids expansion issues)
powershell -Command "if ($env:Path -like '*%INSTALL_DIR%*') { exit 0 } else { exit 1 }" >nul 2>&1
if errorlevel 1 (
    REM Add to PATH using PowerShell to avoid expansion issues with Intel\iCLS
    powershell -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'User'); [Environment]::SetEnvironmentVariable('Path', $path + ';%INSTALL_DIR%', 'User')" >nul 2>&1
)

echo [OK] System configuration complete
echo.

REM ============================================================
REM STEP 5: Final Setup
REM ============================================================
echo ============================================================
echo STEP 5/6: Final Setup
echo ============================================================
echo.

echo Initializing session tracking...
echo. > "%USERPROFILE%\.rag_session_new_install"
echo [OK] Session initialized
echo.

REM ============================================================
REM STEP 6: Verify Installation
REM ============================================================
echo ============================================================
echo STEP 6/6: Verifying Installation
echo ============================================================
echo.

set INSTALL_SUCCESS=1

python --version >nul 2>&1
if errorlevel 1 (
    set INSTALL_SUCCESS=0
    echo [FAIL] Python: Not found
) else (
    echo [OK] Python: Installed
)

where ollama >nul 2>&1
if errorlevel 1 (
    echo [WARN] Ollama: Not installed
    echo        Install from: https://ollama.com/download/windows
    echo        (Required for queries, indexing will work without it)
) else (
    echo [OK] Ollama: Installed
)

if exist "%INSTALL_DIR%\rag_preprocessor.py" (
    echo [OK] AI Prowler Scripts: Ready
) else (
    set INSTALL_SUCCESS=0
    echo [FAIL] AI Prowler Scripts: Missing
    echo        Make sure rag_preprocessor.py is in: %INSTALL_DIR%
)

echo.
echo Installation directory: %INSTALL_DIR%
echo.

REM ============================================================
REM Installation Complete
REM ============================================================

if %INSTALL_SUCCESS%==1 (
    call :INSTALLATION_SUCCESS
) else (
    echo ============================================================
    echo INSTALLATION ISSUES DETECTED
    echo ============================================================
    echo.
    echo The installation encountered problems with one or more components.
    echo.
    echo WHAT FAILED:
    echo   Check the messages above for specific error details.
    echo.
    echo COMMON ISSUES:
    echo   - Python not installed: Re-run installer, it will auto-install
    echo   - Packages failed: Check internet connection
    echo   - Ollama not found: Visit https://ollama.com/download/windows
    echo   - Model download failed: Run: ollama pull llama3.2:1b
    echo.
    echo NEXT STEPS:
    echo   1. Review error messages above
    echo   2. Fix the specific issue mentioned
    echo   3. Re-run INSTALL.bat
    echo.
    echo   OR run components individually:
    echo   - Python packages: pip install -r requirements.txt
    echo   - Ollama: Download from https://ollama.com/download/windows
    echo   - Model: ollama pull llama3.2:1b
    echo.
)

echo.
echo Press any key to exit...
pause >nul

REM ============================================================
REM Helper Subroutine: Add directory to session PATH
REM ============================================================
:ADD_TO_SESSION_PATH
REM Safely add OLLAMA_DIR to PATH without expanding %PATH% in batch
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "[System.Environment]::GetEnvironmentVariable('Path','Process') + ';%OLLAMA_DIR%'"`) do set "PATH=%%p"
goto :EOF

REM ============================================================
REM Helper Subroutine: Installation Success
REM ============================================================
:INSTALLATION_SUCCESS
echo ============================================================
echo INSTALLATION COMPLETE!
echo ============================================================
echo.
echo Your AI Prowler system is ready to use!
echo.
echo ============================================================
echo QUICK START GUIDE
echo ============================================================
echo.
echo 1. Double-click "AI Prowler" icon on your Desktop
echo.
echo 2. Or run from this directory:
echo    python rag_gui.py
echo.
echo 3. In the GUI:
echo    - Index Tab: Select a folder to index
echo    - Query Tab: Ask questions about your documents
echo    - Settings Tab: Change AI model
echo.
echo 4. Command line (optional - for advanced users):
echo    python rag_preprocessor.py index C:\Users\%USERNAME%\Documents
echo    python rag_preprocessor.py query "What is in my documents?"
echo.
echo First query will take 2-3 minutes (one-time model loading)
echo All other queries: 10-20 seconds
echo.

REM ============================================================
REM Create Desktop Shortcut
REM ============================================================

echo ============================================================
echo Creating Desktop Shortcut
echo ============================================================
echo.

echo Creating AI PROWLER shortcut on Desktop...

set "DESKTOP=%USERPROFILE%\Desktop"
set "SHORTCUT=%DESKTOP%\AI Prowler.lnk"
set "TARGET=%INSTALL_DIR%\RAG_RUN.bat"
set "ICON=%INSTALL_DIR%\rag_icon.ico"

REM Check if icon exists
if exist "%ICON%" (
    echo [OK] Using custom icon: rag_icon.ico
) else (
    echo [INFO] Custom icon not found
    
    REM Check if SVG exists instead
    if exist "%INSTALL_DIR%\rag_icon.svg" (
        echo.
        echo [NOTICE] Found rag_icon.svg but need rag_icon.ico
        echo.
        echo Windows shortcuts require ICO format, not SVG.
        echo.
        echo To use your custom icon:
        echo   1. Convert rag_icon.svg to rag_icon.ico
        echo   2. Use online converter: cloudconvert.com/svg-to-ico
        echo   3. Place rag_icon.ico in this folder
        echo   4. Re-run INSTALL.bat
        echo.
        echo See: SVG_TO_ICO_CONVERSION.md for detailed instructions
        echo.
        echo For now, using default Windows icon...
    ) else (
        echo        Using default Windows icon
    )
)

REM Use Python to create the shortcut (handles OneDrive Desktop and spaces cleanly)
python "%~dp0create_shortcut.py"

echo [OK] Desktop shortcut created on your Desktop!
echo.

echo.
goto :EOF

REM ============================================================
REM Helper Subroutine: Install Ollama
REM ============================================================
:INSTALL_OLLAMA
setlocal
echo.
echo ============================================================
echo STEP: Check / Install Ollama
echo ============================================================
echo.

REM ── Already installed? ────────────────────────────────────────────────────
where ollama >nul 2>&1
if not errorlevel 1 (
    echo [OK] Ollama is already installed!
    goto :INSTALL_OLLAMA_FOUND
)

if exist "C:\Program Files\Ollama\ollama.exe" (
    echo [OK] Ollama found at: C:\Program Files\Ollama\
    set "OLLAMA_DIR=C:\Program Files\Ollama"
    endlocal & set "OLLAMA_DIR=%OLLAMA_DIR%"
    call :ADD_TO_SESSION_PATH
    goto :INSTALL_OLLAMA_FOUND
)

if exist "%USERPROFILE%\AppData\Local\Programs\Ollama\ollama.exe" (
    echo [OK] Ollama found at AppData location
    set "OLLAMA_DIR=%USERPROFILE%\AppData\Local\Programs\Ollama"
    endlocal & set "OLLAMA_DIR=%OLLAMA_DIR%"
    call :ADD_TO_SESSION_PATH
    goto :INSTALL_OLLAMA_FOUND
)

REM ── Not found — install automatically via PowerShell one-liner ───────────
echo Ollama not found. Installing automatically...
echo.
echo Running: irm https://ollama.com/install.ps1 ^| iex
echo Please wait (usually 30-60 seconds)...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://ollama.com/install.ps1 | iex"

REM Refresh PATH in this session so ollama.exe is usable immediately
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"`) do set "PATH=%%p"

REM ── Verify auto-install succeeded ────────────────────────────────────────
where ollama >nul 2>&1
if not errorlevel 1 (
    echo.
    echo [OK] Ollama installed successfully!
    goto :INSTALL_OLLAMA_FOUND
)

if exist "C:\Program Files\Ollama\ollama.exe" (
    echo [OK] Ollama installed at: C:\Program Files\Ollama\
    set "OLLAMA_DIR=C:\Program Files\Ollama"
    endlocal & set "OLLAMA_DIR=%OLLAMA_DIR%"
    call :ADD_TO_SESSION_PATH
    goto :INSTALL_OLLAMA_FOUND
)

if exist "%USERPROFILE%\AppData\Local\Programs\Ollama\ollama.exe" (
    echo [OK] Ollama installed at AppData location
    set "OLLAMA_DIR=%USERPROFILE%\AppData\Local\Programs\Ollama"
    endlocal & set "OLLAMA_DIR=%OLLAMA_DIR%"
    call :ADD_TO_SESSION_PATH
    goto :INSTALL_OLLAMA_FOUND
)

REM ── Auto-install failed — open browser as last resort ────────────────────
echo.
echo [WARN] Automatic install did not complete. Opening download page...
echo.
start https://ollama.com/download/windows
echo.
echo ============================================================
echo MANUAL INSTALL REQUIRED
echo ============================================================
echo.
echo Steps:
echo   1. Download and run the Ollama installer from the browser window
echo   2. Wait for installation to complete
echo   3. Press any key here to continue
echo.
pause

REM Final check after manual install
where ollama >nul 2>&1
if not errorlevel 1 (
    echo [OK] Ollama detected after manual install!
    goto :INSTALL_OLLAMA_FOUND
)

if exist "C:\Program Files\Ollama\ollama.exe" (
    set "OLLAMA_DIR=C:\Program Files\Ollama"
    endlocal & set "OLLAMA_DIR=%OLLAMA_DIR%"
    call :ADD_TO_SESSION_PATH
    goto :INSTALL_OLLAMA_FOUND
)

if exist "%USERPROFILE%\AppData\Local\Programs\Ollama\ollama.exe" (
    set "OLLAMA_DIR=%USERPROFILE%\AppData\Local\Programs\Ollama"
    endlocal & set "OLLAMA_DIR=%OLLAMA_DIR%"
    call :ADD_TO_SESSION_PATH
    goto :INSTALL_OLLAMA_FOUND
)

echo.
echo [WARN] Ollama could not be detected after installation.
echo.
echo The installer will continue. Once finished:
echo   1. Restart your computer (or open a new Command Prompt)
echo   2. Run: ollama pull llama3.2:1b
echo   3. Then launch AI Prowler normally
echo.
endlocal
goto :EOF

:INSTALL_OLLAMA_FOUND
REM Check if Ollama is running
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo Starting Ollama server...
    start /B ollama serve >nul 2>&1
    timeout /t 5 /nobreak >nul
)

REM Download llama3.2:1b model
echo Checking for llama3.2:1b model...
ollama list 2>nul | findstr "llama3.2:1b" >nul 2>&1
if errorlevel 1 (
    echo.
    echo Downloading llama3.2:1b model (~1.3 GB)
    echo This is a one-time download and may take 5-10 minutes...
    echo.
    echo Downloading (please wait)...
    echo.
    
    REM Start download in background
    start /min cmd /c "ollama pull llama3.2:1b >nul 2>&1"
    
    REM Wait and show we're working
    for /l %%i in (1,1,60) do (
        <nul set /p "=."
        timeout /t 5 /nobreak >nul
        
        REM Check if download complete
        ollama list 2>nul | findstr "llama3.2:1b" >nul 2>&1
        if not errorlevel 1 goto :INSTALL_OLLAMA_MODEL_DONE
    )
    
    :INSTALL_OLLAMA_MODEL_DONE
    echo.
    echo.
    
    REM Check if successful
    ollama list 2>nul | findstr "llama3.2:1b" >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Model download may have failed or was interrupted
        echo You can download it later with: ollama pull llama3.2:1b
    ) else (
        echo [OK] Model downloaded successfully
    )
) else (
    echo [OK] Model already available
)
echo.

endlocal
goto :EOF
