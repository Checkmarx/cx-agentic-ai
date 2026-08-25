# Quick Start - Deploy by MDM Tool

## ⏱️ Timeline Expectations
- **Script runtime:** 2-5 minutes per device
- **Intune deployment:** 15 minutes to 2 hours (depends on device sync frequency)
- **Jamf deployment:** 5-15 minutes (typically faster than Intune)
- **InfiniPoint deployment:** 5-10 minutes
- **User visibility:** Plugin appears in Claude Code after device restarts the app

## 📋 Prerequisites (Check Before Starting)
- ✅ Claude Code installed on target devices (any recent version)
- ✅ Administrator access to your MDM tool (Intune, Jamf, or InfiniPoint)
- ✅ Target devices are enrolled in MDM
- ✅ Network access to GitHub (scripts may download dependencies)
- ✅ Device restart capability (if required by your MDM tool)

---

## 🚀 Find Your Tool & Deploy

### 📋 Microsoft Intune (Windows)

**1. Copy the script:**
```
scripts/intune/Deploy-Cx-Claude-Cli.ps1
```

**2. Upload to Intune:**
- Go to **Apps** → **All apps** → **+ New app**
- Choose **Windows app (Win32)**
- Upload the PowerShell script (`Deploy-Cx-Claude-Cli.ps1`)
- Set install command: `powershell.exe -ExecutionPolicy Bypass -File .\Deploy-Cx-Claude-Cli.ps1`
- Deploy to device group

**3. Verify:**
```powershell
Get-Content "C:\Program Files\ClaudeCode\managed-settings.json" | ConvertFrom-Json
```

---

### 📋 Jamf Pro (macOS)

**1. Copy the script:**
```
scripts/jamf-pro/Deploy-Cx-Claude-Cli.sh
```

**2. Upload to Jamf Pro:**
- Go to **Computers** → **Configuration Profiles** → **+ New** (or **Management Settings** → **Scripts** → **+ New**)
- Paste the bash script content
- Create policy with the script
- Deploy to device group
- **Note:** Jamf Pro typically deploys within 5-15 minutes after policy assignment

**3. Verify:**
```bash
cat "/Library/Application Support/ClaudeCode/managed-settings.json" | python3 -m json.tool
```

---

### 📋 InfiniPoint (Windows)

**1. Copy the script:**
```
scripts/infinipoint/Deploy-Cx-Claude-Cli.ps1
```

**2. Deploy via InfiniPoint:**
- Use script execution feature
- Upload PowerShell script
- Deploy to Windows devices

**3. Verify:**
```powershell
Get-Content "C:\Program Files\ClaudeCode\managed-settings.json" | ConvertFrom-Json
```

---

## 📚 For More Details

- **Intune users:** Read [scripts/intune/README.md](scripts/intune/README.md)
- **Jamf Pro users:** Read [scripts/jamf-pro/README.md](scripts/jamf-pro/README.md)
- **InfiniPoint users:** Read [scripts/infinipoint/README.md](scripts/infinipoint/README.md)

---

## ✅ After Deployment

Users should:
1. **Open Claude Code**
2. **Run `/plugin list`** — verify cx-devassist appears
3. **Run `/cx-cli-setup`** — authenticate with Checkmarx (one-time)
4. **Start coding** — plugin scans automatically
