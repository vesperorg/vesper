@echo off
setlocal
cd /d "%~dp0"
title Vesper - publish to GitHub
set PRIV=%~dp0..\vesper-private
set PAT=%PRIV%\forbidden.txt
where gh >nul 2>nul
if errorlevel 1 (
  echo GitHub CLI not found. Install it with:  winget install GitHub.cli   then run this again.
  pause
  exit /b 1
)
if not exist "%PAT%" (
  echo STOP: the private pattern list is missing: %PAT%
  pause
  exit /b 1
)
gh auth status >nul 2>nul
if errorlevel 1 (
  echo Not signed in to GitHub yet. Sign in as the Vesper account, NOT a personal one. Follow the prompts.
  gh auth login
)
gh auth status >nul 2>nul
if errorlevel 1 (
  echo Sign-in did not complete.
  pause
  exit /b 1
)
for /f "tokens=*" %%u in ('gh api user --jq .login') do set LOGIN=%%u
echo.
echo Signed in to GitHub as: %LOGIN%
set OK=
set /p OK=Is this the pseudonymous Vesper account, not a personal one? Type YES to continue:
if /i not "%OK%"=="YES" (
  echo Stopped. Run:  gh auth logout   and then   gh auth login   as the Vesper account.
  pause
  exit /b 1
)
echo.
echo === Gate 1: no identifying text in any tracked file ===
git grep -I -i -E -l -f "%PAT%" -- . >nul 2>nul
if not errorlevel 1 (
  echo STOP: these files still carry identifying text:
  git grep -I -i -E -l -f "%PAT%" -- .
  pause
  exit /b 1
)
for /f "delims=" %%f in ('git ls-files -- "*.docx"') do (
  python -I "%PRIV%\check_docx.py" "%%f" "%PAT%" || (
    echo STOP: a Word document carries identifying text.
    pause
    exit /b 1
  )
)
for /f "tokens=*" %%n in ('git config user.name') do set GITNAME=%%n
if not "%GITNAME%"=="Vesper" (
  echo STOP: git user.name is "%GITNAME%", expected "Vesper". Run:  git config user.name Vesper
  pause
  exit /b 1
)
echo === Gate 2: no secret-looking file is tracked ===
git ls-files | findstr /i /r "\.env$ \.viewkey\.json$ \.scan$ \.rings$ wallet.*\.json$ ^data" >nul 2>nul
if not errorlevel 1 (
  echo STOP: these tracked files look like secrets or chain data:
  git ls-files | findstr /i /r "\.env$ \.viewkey\.json$ \.scan$ \.rings$ wallet.*\.json$ ^data"
  pause
  exit /b 1
)
echo Both gates passed.
echo.
set ORG=vesperorg
set /p ORG=GitHub organisation [vesperorg]:
if "%ORG%"=="" set ORG=vesperorg
gh api orgs/%ORG% >nul 2>nul
if errorlevel 1 (
  echo STOP: organisation "%ORG%" does not exist or this account is not a member of it.
  echo Create it at https://github.com/account/organizations/new on the Free plan, then run this again.
  pause
  exit /b 1
)
set REPO=vesper
set /p REPO=Repository name [vesper]:
if "%REPO%"=="" set REPO=vesper
echo.
echo Uncommitted and untracked files that will be included (blank means none):
git status --short
echo.
echo About to publish https://github.com/%ORG%/%REPO% as ONE fresh commit authored "Vesper", dated in UTC.
echo The private working history is saved to %PRIV% and removed from this repository.
echo Press Ctrl+C to stop, or
pause
rem Point the Join page and README at the real repository so the first public commit has no placeholder.
powershell -NoProfile -ExecutionPolicy Bypass -File "%PRIV%\set_links.ps1" -Org %ORG% -Repo %REPO% -Root "%~dp0."
rem Commit times in UTC so the time zone does not say where the developer lives.
for /f "usebackq tokens=*" %%d in (`powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' +0000'"`) do set NOWUTC=%%d
set GIT_AUTHOR_DATE=%NOWUTC%
set GIT_COMMITTER_DATE=%NOWUTC%
git add -A
git branch -f private-history
git checkout -q --orphan publish-tmp
git -c commit.gpgsign=false commit -q -m "Vesper (VESP): private-by-default cryptocurrency, initial public release" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
if errorlevel 1 (
  echo Commit failed. Nothing was published.
  git checkout -q master
  pause
  exit /b 1
)
git branch -D master >nul 2>nul
git branch -m master
gh repo create %ORG%/%REPO% --public --source=. --remote=origin --push --description "Vesper (VESP): a private-by-default cryptocurrency. Stealth addresses, sealed amounts, ring signatures, auditable dev fund. Reference implementation; not audited."
if errorlevel 1 (
  echo Repository creation failed. If it already exists, run:  git push -u origin master
  pause
  exit /b 1
)
gh api -X POST repos/%ORG%/%REPO%/pages -f "source[branch]=master" -f "source[path]=/site" >nul 2>nul
rem Move the private history out of the repository: a bundle in the private folder, then purge.
for /f "usebackq tokens=*" %%d in (`powershell -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmm')"`) do set STAMP=%%d
git bundle create "%PRIV%\private-history-%STAMP%.bundle" private-history >nul 2>nul
if exist "%PRIV%\private-history-%STAMP%.bundle" (
  git branch -D private-history >nul 2>nul
  git reflog expire --expire=now --all
  git gc --prune=now --quiet
  echo Private history saved to %PRIV%\private-history-%STAMP%.bundle and removed from this repository.
) else (
  echo WARNING: could not save the private history bundle; branch private-history was left in place. Never push it.
)
echo.
echo Repository : https://github.com/%ORG%/%REPO%
echo Pages site : https://%ORG%.github.io/%REPO%/   (may take a minute to appear)
echo Tell Claude both URLs so the pages can link to them.
echo.
pause
