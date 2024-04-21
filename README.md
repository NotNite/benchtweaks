# benchtweaks

Small tweaks for the [FINAL FANTASY XIV: Dawntrail benchmark](https://na.finalfantasyxiv.com/benchmark/).

## How to use

- Download or build it
- Put it next to `ffxiv_dx11.exe` in the benchmark installation named `version.dll`
  - Do not install this into the actual game client, things *will* break
- Create a `benchtweaks.toml` next to the .dll and .exe

The `benchtweaks.toml` contains multiple options - open in Notepad and edit accordingly. Add what you like from below:

```toml
# Disables the cutscene borders on widescreen
# May cause issues with the UI or show things being weird out of scene
widescreen_fix = true

# Load files from disk (think of it as a mini Penumbra)
mod_dir = "F:/glomble"
```
