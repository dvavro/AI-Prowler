@echo off
setlocal EnableExtensions
REM =====================================================================
REM  AI-Prowler - Post-Upgrade Reindex  (run AFTER installing v7)
REM ---------------------------------------------------------------------
REM  Rebuilds the fresh chromadb 1.0.x index from data that survived the
REM  pre-upgrade cleanup:
REM    - re-indexes every tracked folder / file
REM    - rebuilds the learnings collection from self_learning_data.json
REM
REM  No admin rights needed. Make sure the AI-Prowler GUI is CLOSED so it
REM  doesn't fight this script over the database.
REM
REM  Keep this .bat in the SAME FOLDER as AI-Prowler_PostUpgrade_Reindex.py
REM =====================================================================
title AI-Prowler Post-Upgrade Reindex

set "INSTALL_DIR=C:\Program Files\AI-Prowler"
set "LOCAL_PYTHON=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

REM Mirror RAG_RUN.bat's environment so indexing behaves identically.
set PYTHONNOUSERSITE=1
if not defined HF_HUB_CACHE set "HF_HUB_CACHE=%USERPROFILE%\.cache\huggingface\hub"

if not exist "%LOCAL_PYTHON%" (
    echo ERROR: Python not found at:
    echo   %LOCAL_PYTHON%
    pause
    goto :eof
)
if not exist "%INSTALL_DIR%\rag_preprocessor.py" (
    echo ERROR: AI-Prowler not found at %INSTALL_DIR%
    echo        Install the new version first, then run this script.
    pause
    goto :eof
)
if not exist "%~dp0AI-Prowler_PostUpgrade_Reindex.py" (
    echo ERROR: AI-Prowler_PostUpgrade_Reindex.py not found next to this .bat
    pause
    goto :eof
)

echo.
echo Rebuilding AI-Prowler indexes. This can take several minutes
echo depending on how many documents are tracked ...
echo.

"%LOCAL_PYTHON%" "%~dp0AI-Prowler_PostUpgrade_Reindex.py"

echo.
pause
endlocal
