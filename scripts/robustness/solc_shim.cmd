@echo off
rem solc launcher for forge on Windows (forge test --use <this file>): runs the solc-js shim.
rem PQID_NODE may name node.exe; otherwise node is taken from PATH.
if defined PQID_NODE (
  "%PQID_NODE%" "%~dp0solcjs_shim.cjs" %*
) else (
  node "%~dp0solcjs_shim.cjs" %*
)
exit /b %ERRORLEVEL%
