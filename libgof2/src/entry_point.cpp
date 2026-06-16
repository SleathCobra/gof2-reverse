#include <entry_point.h>
#include <hooks.h>
#include <log.h>

void EntryPoint()
{
    SetLogFile("dbg.log");
    LogInfo("Starting....");

    InstallAllHooks();
}