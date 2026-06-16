#include <hooks.h>
#include <hook_table.inc>
#include <hookmanager.h>

void InstallAllHooks() {
    constexpr size_t g_hookTableSize = sizeof(g_hookTable) / sizeof(HookEntry);

    for (int i=0; i< g_hookTableSize; i++)
    {
        auto entry = g_hookTable[i];
        if (entry.detour != nullptr)
        {
            HookManager::Install(reinterpret_cast<void*>(entry.address), entry.detour);
        }
    }
}

