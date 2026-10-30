; Removes the optional "Unlock with PuirkleUninstaller" File Explorer menu entry on uninstall,
; so PuirkleUninstaller doesn't leave leftovers of its own (see src/unlock.rs, MENU_KEYS).
!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Classes\*\shell\PuirkleUnlock"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\PuirkleUnlock"
!macroend
