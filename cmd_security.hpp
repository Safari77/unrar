#ifndef _CMD_SECURITY_
#define _CMD_SECURITY_

class CommandData; // Forward declaration

class SecurityPatches
{
  public:
    // Returns true if the switch was handled by us
    static bool ProcessSwitch(CommandData *Cmd, const wchar *Switch);
};

#endif
