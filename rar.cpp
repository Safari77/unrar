#include "rar.hpp"

#ifdef __linux__
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#warning compiling seccomp and landlock support

#include <fcntl.h>
#include <libgen.h>
#include <linux/landlock.h>
#include <seccomp.h>
#include <set>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void setup_seccomp(void)
{
  scmp_filter_ctx ctx;
  int rc = 0;

  ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
  if (ctx) {
    const int BAD_MODES = S_ISUID | S_ISGID;

    // Allow (f)chmod ONLY if the dangerous bits are NOT set.
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 1,
                           SCMP_A1(SCMP_CMP_MASKED_EQ, BAD_MODES, 0));
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, BAD_MODES, 0));

    // Only allow clone if the flags (Arg 0) include CLONE_THREAD
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                        SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, CLONE_THREAD));
#ifdef __SNR_clone2
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone2), 1,
                        SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, CLONE_THREAD));
#endif
#ifdef __SNR_clone3
rc |= seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
#endif

    // Deny execute permissions in mmap/mprotect
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
                        SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));

    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
                        SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));

    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0);
#ifdef __SNR_rseq
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);
#endif
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);

    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 1, SCMP_A1(SCMP_CMP_EQ, SIGTSTP));
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, TIOCGWINSZ));
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, TCGETS));
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, TCSETSW));
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, TCSETSF));
#ifdef FIONREAD
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, FIONREAD));
#endif
#ifdef FIONWRITE
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, FIONWRITE));
#endif
#ifdef FIONSPACE
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, FIONSPACE));
#endif

    int ret = seccomp_load(ctx);
    if (ret != 0) {
      fprintf(stderr, "seccomp_load failed with error %d\n", ret);
      exit(RARX_FATAL);
    }
    seccomp_release(ctx);
  } else {
    fprintf(stderr, "seccomp_init failed: %s\n", strerror(errno));
    exit(RARX_FATAL);
  }
}
#endif

#if !defined(RARDLL)
int main(int argc, char *argv[])
{
#ifdef _UNIX
  setlocale(LC_ALL,"");
  tzset();
#endif

  InitConsole();
  ErrHandler.SetSignalHandlers(true);

#ifdef SFX_MODULE
  std::wstring ModuleName;
#ifdef _WIN_ALL
  ModuleName=GetModuleFileStr();
#else
  CharToWide(argv[0],ModuleName);
#endif
#endif

#ifdef _WIN_ALL
  SetErrorMode(SEM_NOALIGNMENTFAULTEXCEPT|SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX);


#endif

#if defined(_WIN_ALL) && !defined(SFX_MODULE)
  // Must be initialized, normal initialization can be skipped in case of
  // exception.
  POWER_MODE ShutdownOnClose=POWERMODE_KEEP;
#endif

  try
   {

    // Use std::unique_ptr to free Cmd in case of exception.
    std::unique_ptr<CommandData> Cmd(new CommandData);
#ifdef SFX_MODULE
    Cmd->Command=L"X";
    char *Switch=argc>1 ? argv[1]:NULL;
    if (Switch!=NULL && Cmd->IsSwitch(Switch[0]))
    {
      int UpperCmd=etoupper(Switch[1]);
      switch(UpperCmd)
      {
        case 'T':
        case 'V':
          // Also copy 't' and 'a' modifiers for -v[t,a], if present.
          Cmd->Command.clear();
          for (char *c=Switch+1;*c!=0;c++)
            Cmd->Command+=etoupper(*c);
          break;
        case '?':
          Cmd->OutHelp(RARX_SUCCESS);
          break;
      }
    }
    Cmd->AddArcName(ModuleName);
    Cmd->ParseDone();
    Cmd->AbsoluteLinks=true; // If users runs SFX, he trusts an archive source.
#else // !SFX_MODULE
    Cmd->ParseCommandLine(true,argc,argv);
    if (!Cmd->ConfigDisabled)
    {
      Cmd->ReadConfig();
      Cmd->ParseEnvVar();
    }
    Cmd->ParseCommandLine(false,argc,argv);
#endif

#if defined(_WIN_ALL) && !defined(SFX_MODULE)
    ShutdownOnClose=Cmd->Shutdown;
    if (ShutdownOnClose!=POWERMODE_KEEP)
      ShutdownCheckAnother(true);
#endif

    uiInit(Cmd->Sound);
    InitLogOptions(Cmd->LogName,Cmd->ErrlogCharset);
    ErrHandler.SetSilent(Cmd->AllYes || Cmd->MsgStream==MSG_NULL);

    Cmd->OutTitle();

#ifdef __linux__
    // landlock
    struct landlock_ruleset_attr ruleset_attr = {
      .handled_access_fs =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SYM,
    };

    int ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd == -1) {
      fprintf(stderr, "landlock_create_ruleset failed: %s\n", strerror(errno));
      exit(RARX_FATAL);
    }

    std::set<std::string> read_only_paths;
    std::set<std::string> read_write_paths;

    if (!Cmd->ArcName.empty()) {
      std::string NameA;
      WideToChar(Cmd->ArcName, NameA);

      char *path_copy = strdup(NameA.c_str());
      read_only_paths.insert(dirname(path_copy));
      // dirname can modify the path
      free(path_copy);
    }
    // multiarchive
    Cmd->ArcNames.Rewind();
    std::wstring NameW;
    while (Cmd->ArcNames.GetString(NameW)) {
      std::string NameA;
      WideToChar(NameW, NameA);

      char *path_copy = strdup(NameA.c_str());
      read_only_paths.insert(dirname(path_copy));
      free(path_copy);
    }
    Cmd->ArcNames.Rewind(); // Reset cursor

    std::string out_dir = ".";
    // Check if -op (ExtrPath) is specified, otherwise use "."
    if (!Cmd->ExtrPath.empty()) {
      std::string ExtrPathA;
      WideToChar(Cmd->ExtrPath, ExtrPathA);
      out_dir = ExtrPathA;
    }
    read_write_paths.insert(out_dir);

    // Apply output rules (read/write)
    for (const auto& dir : read_write_paths) {
      //fprintf(stderr, "adding RW path \"%s\" for landlock\n", dir.c_str());
      int fd = open(dir.c_str(), O_PATH | O_CLOEXEC);
      if (fd >= 0) {
        struct landlock_path_beneath_attr path_rw = {
          .allowed_access = ruleset_attr.handled_access_fs, // Full Access
          .parent_fd = fd
        };
        syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_rw, 0);
        close(fd);
      } else {
        fprintf(stderr, "landlock warning: Output directory '%s' must exist before running.\n", dir.c_str());
      }
    }

    // Apply input rules (read only)
    for (const auto& dir : read_only_paths) {
      // Skip if this path is already covered by Read/Write rules
      if (read_write_paths.count(dir)) continue;

      int fd = open(dir.c_str(), O_PATH | O_CLOEXEC);
      if (fd >= 0) {
        struct landlock_path_beneath_attr path_ro = {
          .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
          .parent_fd = fd
        };
        if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_ro, 0) == -1) {
          fprintf(stderr, "landlock_add_rule failed: %s\n", strerror(errno));
          exit(RARX_FATAL);
        }
        close(fd);
      }
    }

    // Enforce
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) == -1) {
      fprintf(stderr, "landlock_restrict_self failed: %s\n", strerror(errno));
      exit(RARX_FATAL);
    }
    close(ruleset_fd);
    setup_seccomp();
#endif
    Cmd->ProcessCommand();
  }
  catch (RAR_EXIT ErrCode)
  {
    ErrHandler.SetErrorCode(ErrCode);
  }
  catch (std::bad_alloc&)
  {
    ErrHandler.MemoryErrorMsg();
    ErrHandler.SetErrorCode(RARX_MEMORY);
  }
  catch (std::length_error&)
  {
    ErrHandler.MemoryErrorMsg();
    ErrHandler.SetErrorCode(RARX_MEMORY);
  }
  catch (...)
  {
    ErrHandler.SetErrorCode(RARX_FATAL);
  }

#if defined(_WIN_ALL) && !defined(SFX_MODULE)
  if (ShutdownOnClose!=POWERMODE_KEEP && ErrHandler.IsShutdownEnabled() &&
      !ShutdownCheckAnother(false))
    Shutdown(ShutdownOnClose);
#endif
  ErrHandler.MainExit=true;
  CloseLogOptions();
  return ErrHandler.GetErrorCode();
}
#endif


