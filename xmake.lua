--! Rules
add_rules("mode.debug", "mode.release")
set_arch("x86")

--! Dependencies
add_requires("microsoft-detours", "minhook")

--! Targets
includes("proxydll", "libgof2")