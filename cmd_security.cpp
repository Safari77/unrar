#include "rar.hpp"
#include "cmd_security.hpp"

bool SecurityPatches::ProcessSwitch(CommandData *Cmd, const wchar *Switch)
{
  // 1. Handle our custom "-fs" (Force Sync) switch
  if (wcsicomp(Switch, L"FS") == 0)
  {
    Cmd->ForceSync = true;
    return true;
  }

  return false; // Not our switch, let unrar handle it normally
}
