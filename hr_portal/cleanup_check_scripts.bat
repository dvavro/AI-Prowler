@echo off
cd /d "C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal"
del /q check_syntax.js find_unclosed.js find_unbalanced.js extract_block.js check_block.bat acorn_check.js bracket_balance.js install_acorn.bat block_4.js 2>nul
rd /s /q node_modules 2>nul
echo Done.
