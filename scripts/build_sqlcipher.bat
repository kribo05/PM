@echo off
set VSCMD_START_DIR=%CD%
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd ..\dependencies\crypto\sqlcipher\sqlcipher-4.7.0

echo Building SQLite3 DLL for x64...

nmake /f Makefile.msc clean
nmake /f Makefile.msc sqlite3.dll USE_NATIVE_LIBPATHS=1 "OPTS=-DSQLITE_ENABLE_FTS3=1 -DSQLITE_ENABLE_FTS4=1 -DSQLITE_ENABLE_FTS5=1 -DSQLITE_ENABLE_RTREE=1 -DSQLITE_ENABLE_JSON1=1 -DSQLITE_ENABLE_GEOPOLY=1 -DSQLITE_ENABLE_SESSION=1 -DSQLITE_ENABLE_PREUPDATE_HOOK=1 -DSQLITE_ENABLE_SERIALIZE=1 -DSQLITE_ENABLE_MATH_FUNCTIONS=1" PLATFORM=x64

if exist sqlite3.dll (
    echo Copying sqlite3.dll to dependencies folder...
    copy /Y sqlite3.dll ..\sqlite3.dll
    echo Done!
) else (
    echo Error: sqlite3.dll was not created!
    exit /b 1
)

pause
