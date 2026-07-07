!ifndef VERSION
!define VERSION "0.0.0"
!endif

!define APP_NAME "AutomateSTIG"
!define PUBLISHER "AutomateSTIG"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AutomateSTIG"
!define SOURCE_DIR "${__FILEDIR__}"

Unicode true
RequestExecutionLevel admin

Name "${APP_NAME}"
OutFile "AutomateSTIG-${VERSION}-windows-x64-setup.exe"
InstallDir "$PROGRAMFILES64\AutomateSTIG"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"

Icon "${SOURCE_DIR}\AutomateSTIG.ico"
UninstallIcon "${SOURCE_DIR}\AutomateSTIG.ico"

!include "MUI2.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON "${SOURCE_DIR}\AutomateSTIG.ico"
!define MUI_UNICON "${SOURCE_DIR}\AutomateSTIG.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\automatestig-gui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch AutomateSTIG"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function .onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "AutomateSTIG" SEC_MAIN
  SectionIn RO
  SetRegView 64
  SetShellVarContext all

  SetOutPath "$INSTDIR"
  File "${SOURCE_DIR}\automatestig.exe"
  File "${SOURCE_DIR}\automatestig-gui.exe"
  File "${SOURCE_DIR}\AutomateSTIG.ico"

  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\AutomateSTIG"
  CreateShortcut "$SMPROGRAMS\AutomateSTIG\AutomateSTIG.lnk" "$INSTDIR\automatestig-gui.exe" "" "$INSTDIR\AutomateSTIG.ico" 0
  CreateShortcut "$DESKTOP\AutomateSTIG.lnk" "$INSTDIR\automatestig-gui.exe" "" "$INSTDIR\AutomateSTIG.ico" 0

  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\AutomateSTIG.ico"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  ; PATH is intentionally not modified because the stock NSIS runner does not
  ; guarantee the EnVar plugin. The installer provides clickable GUI shortcuts.
SectionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all

  Delete "$DESKTOP\AutomateSTIG.lnk"
  Delete "$SMPROGRAMS\AutomateSTIG\AutomateSTIG.lnk"
  RMDir "$SMPROGRAMS\AutomateSTIG"

  Delete "$INSTDIR\automatestig.exe"
  Delete "$INSTDIR\automatestig-gui.exe"
  Delete "$INSTDIR\AutomateSTIG.ico"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd
