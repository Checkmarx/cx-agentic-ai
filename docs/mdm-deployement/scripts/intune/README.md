# Microsoft Intune - Claude Code MDM Deployment

Deploy Checkmarx cx-devassist plugin to Claude Code via Microsoft Intune.

## 🚀 Quick Deploy

```powershell
cd scripts/intune
.\Deploy-Cx-Claude-Cli.ps1
```

## 📋 Intune Step-by-Step Deployment

### Step 1: Prepare the Script
- Location: `scripts/intune/Deploy-Cx-Claude-Cli.ps1`
- No modifications needed - script handles everything

### Step 2: Create Win32 App in Intune

1. **Open Intune Admin Center**
   - URL: `https://intune.microsoft.com`
   - Navigate: **Apps** → **All apps** → **+ New app**

2. **Select App Type**
   - Choose: **Windows app (Win32)**

3. **Upload Script**
   - Click **Select app package file**
   - Upload: `Deploy-Cx-Claude-Cli.ps1` (from scripts/intune/)
   - Click **Next**

4. **Configure Program**
   - **Install command:**
     ```
     powershell.exe -ExecutionPolicy Bypass -File .\Deploy-Cx-Claude-Cli.ps1
     ```
   - **Uninstall command:** (leave empty or `exit 0`)
   - **Install behavior:** System
   - **Device restart behavior:** No specific action
   - Click **Next**

5. **Configure Detection Rules**
   - **Rule type:** File
   - **Path:** `C:\Program Files\ClaudeCode`
   - **File:** `managed-settings.json`
   - **Detection method:** File exists
   - Click **Add** → **Next**

6. **Review and Create**
   - Verify all settings
   - Click **Create**

### Step 3: Assign to Devices

1. **Select App**
   - In Intune, find the app you just created
   - Click **Assignments** → **+ Add group**

2. **Select Groups**
   - Choose: **Required**
   - Select your device groups
   - Click **Assign**

3. **Deployment Policy**
   - **Intent:** Required
   - **Availability:** As soon as possible
   - Click **Save**

### Step 4: Monitor Deployment

1. **Check Compliance**
   - **Apps** → **Monitor** → **App install status**
   - Look for your app in the list
   - Check deployment status by device group

2. **Check Device Status**
   - **Devices** → **Windows** → **Manage devices**
   - Select a device
   - Check app installation status

## ✅ Verification

### On Target Device

```powershell
# 1. Check file exists
Test-Path "C:\Program Files\ClaudeCode\managed-settings.json"
# Should return: True

# 2. View configuration
Get-Content "C:\Program Files\ClaudeCode\managed-settings.json" | ConvertFrom-Json | ConvertTo-Json

# 3. Verify in Claude Code
# Open Claude Code → Run `/plugin list` → Should see cx-devassist
```

## 🔧 Troubleshooting

### Common Issues & Solutions

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| **App fails to install** | Device policy not synced | Wait 5-10 minutes, force Intune sync, check device is compliant |
| **File not created at `C:\Program Files\ClaudeCode`** | Script didn't execute | Check app installation status in Intune; run script manually as admin |
| **Script execution fails** | Insufficient permissions | Ensure "Install behavior" is set to "System" (not User) |
| **Plugin doesn't load in Claude Code** | JSON validation error | Check JSON syntax: `Get-Content "C:\Program Files\ClaudeCode\managed-settings.json" \| ConvertFrom-Json` |
| **Access denied / Permission error** | File ownership issue | Run as admin, verify target directory permissions, check user has read access |
| **Deployment shows "Failed"** | Various causes | Run script manually on device with `powershell -ExecutionPolicy Bypass -File .\Deploy-Cx-Claude-Cli.ps1` to see actual error |
| **Plugin doesn't appear after installation** | Claude Code cache issue | Restart Claude Code completely; check `/plugin list` command |
| **Installation takes too long** | Normal for Intune | Large deployments can take 30 min - 2 hours; check sync frequency in device settings |

### Most Common Issues (80% of problems)

1. **Device didn't sync policy yet**
   - Wait 10-15 minutes for automatic sync
   - Force sync: Settings → Accounts → Access work or school → [device] → Info → Sync
   - Restart device after sync

2. **Install behavior set to "User" instead of "System"**
   - Edit app → **Program** tab
   - Change "Install behavior" to **System**
   - Re-assign to device groups

3. **Claude Code not restarted after file creation**
   - Close Claude Code completely (not just minimize)
   - Re-open it
   - Run `/plugin list` to verify

## 🆘 Debug Steps

1. **Check Deployment Status**
   - In Intune: **Apps** → **All apps** → Select app → **Device install status**

2. **Check Device Logs**
   - On device, run: `Get-Content "C:\Program Files\ClaudeCode\managed-settings.json"`
   - If file doesn't exist, script didn't run

3. **Run Manually**
   - As Administrator: `.\Deploy-Cx-Claude-Cli.ps1`
   - Check output for errors

4. **Verify Intune Installation**
   - Check device last contacted Intune
   - Force sync if needed
   - Wait a few minutes for policy to apply

## 📚 More Information

- **Main guide:** [../README.md](../README.md)
- **Quick start:** [../QUICK-START.md](../QUICK-START.md)
- **Script location:** `scripts/intune/Deploy-Cx-Claude-Cli.ps1`

## 🎯 Success Indicators

✅ File created: `C:\Program Files\ClaudeCode\managed-settings.json`
✅ Valid JSON with `cx-devassist-marketplace` configured
✅ Plugin appears in Claude Code `/plugin list`
✅ Plugin is marked as enabled
