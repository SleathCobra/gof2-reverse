target("libgof2")
    set_kind("shared")
    add_files("src/*.cpp")
    add_includedirs("include", {public = true})
    add_defines("NOMINMAX")

    add_syslinks("user32")
    add_packages("minhook", "microsoft-detours")

    set_languages("c++23")

    after_build(function (target)
        os.cp(target:targetfile(), "build")
    end)

     on_clean(function (target)
        os.tryrm("build/.deps")
        os.tryrm("build/.objs")
        os.tryrm("build/windows")
        os.tryrm("build/libgof2.dll")
    end)

-- TODO : Add docs