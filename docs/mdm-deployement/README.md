# Claude Code MDM Deployment - By MDM Tool

Deploy Checkmarx cx-devassist plugin to Claude Code using your organization's MDM tool.

## ⏱️ Timeline at a Glance

| Phase | Duration |
|-------|----------|
| **Preparation & Setup** | 5-10 minutes |
| **Script Upload to MDM** | 5 minutes |
| **Device Policy Deployment** | 15 min - 2 hours (varies by MDM) |
| **Script Execution on Device** | 2-5 minutes per device |
| **Plugin Visibility to Users** | After Claude Code restart |

**Total time from start to user availability:** 30 minutes to 3 hours depending on MDM tool and device refresh timing.

## ✅ Prerequisites - Check Before Starting

Before deploying, ensure you have:

- **Claude Code** installed on target devices (works with any recent version)
- **Administrator access** to your MDM tool (Intune, Jamf Pro, or InfiniPoint)
- **Enrolled devices** — target devices must be enrolled in your MDM system
- **Network connectivity** — devices need internet access for script execution
- **File permissions** — ability to write to `C:\Program Files\ClaudeCode` (Windows) or `/Library/Application Support/ClaudeCode` (macOS)
- **PowerShell 5.0+** (Windows scripts) or Bash 3.0+ (macOS scripts)
- **(Optional) Backup** — consider backing up existing Claude Code configs before deployment

## 🎯 Choose Your MDM Tool

### 📋 **Microsoft Intune** (Windows)
👉 **[Intune Deployment Guide →](scripts/intune/README.md)**

For deploying to Windows devices via Microsoft Intune.

**Quick Start:**
```powershell
cd scripts/intune
.\Deploy-ClaudeCode.ps1
```

---

### 📋 **Jamf Pro** (macOS)
👉 **[Jamf Pro Deployment Guide →](scripts/jamf-pro/README.md)**

For deploying to macOS devices via Jamf Pro.

**Quick Start:**
```bash
cd scripts/jamf-pro
sudo bash deploy-claude-code.sh
```

---

### 📋 **InfiniPoint** (Windows)
👉 **[InfiniPoint Deployment Guide →](scripts/infinipoint/README.md)**

For deploying to Windows devices via InfiniPoint.

**Quick Start:**
```powershell
cd scripts/infinipoint
.\Deploy-ClaudeCode.ps1
```

---

## 📊 MDM Tool Comparison

| MDM Tool | Platform | Documentation | Script |
|----------|----------|---|---|
| **Intune** | Windows | [scripts/intune/README.md](scripts/intune/README.md) | scripts/intune/Deploy-Cx-Claude-Cli.ps1 |
| **Jamf Pro** | macOS | [scripts/jamf-pro/README.md](scripts/jamf-pro/README.md) | scripts/jamf-pro/Deploy-Cx-Claude-Cli.sh |
| **InfiniPoint** | Windows | [scripts/infinipoint/README.md](scripts/infinipoint/README.md) | scripts/infinipoint/Deploy-Cx-Claude-Cli.ps1 |

## 📦 What Gets Deployed

All MDM tools deploy the same configuration:

**Claude Code Plugin Registration**
- Plugin: `cx-devassist`
- Marketplace: `cx-devassist-marketplace`
- Repository: `Checkmarx/cx-agentic-ai`
- Status: Force-enabled for all users

**File Created**
- Windows: `C:\Program Files\ClaudeCode\managed-settings.json`
- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`

## ⚡ Quick Start by Role

### **IT Administrator** (Deploying to Organization)
1. Find your MDM tool folder above
2. Read the tool-specific README
3. Follow step-by-step deployment instructions
4. Deploy to device groups
5. Verify deployment success

### **Developer** (Manual Testing)
1. Find your MDM tool folder above
2. Navigate to `scripts/` folder
3. Run the deployment script with appropriate privileges
4. Verify with the commands shown in documentation

### **IT Support** (Troubleshooting)
1. Check the Troubleshooting section in your MDM tool's README
2. Verify Claude Code version and configuration
3. Check managed-settings.json exists and is valid JSON
4. Restart Claude Code and check plugin list

## ✅ Verification Commands

After deployment, verify using your platform:

**Windows:**
```powershell
Get-Content "C:\Program Files\ClaudeCode\managed-settings.json" | ConvertFrom-Json | ConvertTo-Json
```

**macOS:**
```bash
cat "/Library/Application Support/ClaudeCode/managed-settings.json" | python3 -m json.tool
```

Expected output should show:
- `cx-devassist-marketplace` in `extraKnownMarketplaces`
- `cx-devassist@cx-devassist-marketplace: true` in `enabledPlugins`

## 🔍 Find Your MDM Tool

| If using... | Go to... |
|---|---|
| Microsoft Intune | [scripts/intune/](scripts/intune/) |
| Jamf Pro | [scripts/jamf-pro/](scripts/jamf-pro/) |
| InfiniPoint | [scripts/infinipoint/](scripts/infinipoint/) |
| Something else? | Check [QUICK-START.md](QUICK-START.md) for manual deployment |

## 📚 All Documentation

- **[README.md](README.md)** — This file (overview by MDM tool)
- **[QUICK-START.md](QUICK-START.md)** — Quick reference guide
- **[scripts/intune/README.md](scripts/intune/README.md)** — Intune detailed guide
- **[scripts/jamf-pro/README.md](scripts/jamf-pro/README.md)** — Jamf Pro detailed guide
- **[scripts/infinipoint/README.md](scripts/infinipoint/README.md)** — InfiniPoint detailed guide

## 🚀 Deploy in 5 Minutes

1. **Locate your MDM tool** above
2. **Read that tool's README**
3. **Run the deployment script** from scripts/ folder
4. **Verify** using the commands shown
5. **Done!** Users can now use Claude Code with security scanning

## 🔄 Rollback & Cleanup

If you need to undo the deployment:

### **Option 1: Remove via MDM (Recommended)**
- **Intune:** Delete the app assignment or uninstall the app
- **Jamf Pro:** Delete the policy assignment
- **InfiniPoint:** Remove the script deployment

The managed configuration will be removed from devices.

### **Option 2: Manual Cleanup on Devices**

**Windows:**
```powershell
# Remove the managed settings file
Remove-Item "C:\Program Files\ClaudeCode\managed-settings.json" -Force

# Or rename it to disable (keeping backup)
Rename-Item "C:\Program Files\ClaudeCode\managed-settings.json" "managed-settings.json.bak"
```

**macOS:**
```bash
# Remove the managed settings file
sudo rm "/Library/Application Support/ClaudeCode/managed-settings.json"

# Or rename it to disable (keeping backup)
sudo mv "/Library/Application Support/ClaudeCode/managed-settings.json" "/Library/Application Support/ClaudeCode/managed-settings.json.bak"
```

### **Option 3: Re-enable After Accidental Removal**

The scripts create automatic backups:
- **Windows:** `managed-settings.json.backup-YYYYMMDDHHMMSS`
- **macOS:** `managed-settings.json.backup-YYYYMMDDHHMMSS`

To restore from backup:
```powershell
# Windows
Copy-Item "C:\Program Files\ClaudeCode\managed-settings.json.backup-*" "C:\Program Files\ClaudeCode\managed-settings.json" -Force
```

```bash
# macOS
sudo cp "/Library/Application Support/ClaudeCode/managed-settings.json.backup-"* "/Library/Application Support/ClaudeCode/managed-settings.json"
```

**Then restart Claude Code.**

## 📞 Support

For help:
1. Read the Troubleshooting section in your MDM tool's README
2. Verify file exists at correct location
3. Verify JSON is valid
4. Check Claude Code version
5. Contact your Checkmarx or MDM support team

## 🎯 Key Features

All deployments include:
- ✅ Idempotent scripts (safe to run multiple times)
- ✅ Automatic backups of existing configs
- ✅ JSON validation
- ✅ Clear success/failure messages
- ✅ Proper file permissions and ownership
- ✅ UTF-8 encoding compatibility

---

**Ready to deploy?** Choose your MDM tool above and follow the guide! 🚀
