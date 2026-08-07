# InfiniPoint - Claude Code MDM Deployment

Deploy Checkmarx cx-devassist plugin to Claude Code via InfiniPoint.

## ⏱️ Expected Timeline
- **Script upload:** 5 minutes
- **Policy creation:** 5 minutes
- **Policy sync to devices:** 5-10 minutes
- **Script execution:** 2-5 minutes per device
- **Total:** 15-20 minutes from start to user availability

## ✅ Prerequisites
- ✅ Windows devices enrolled in InfiniPoint
- ✅ InfiniPoint administrator access
- ✅ Claude Code installed on target devices
- ✅ PowerShell 5.0+ installed (standard on Windows 10+)
- ✅ Administrator-level execution allowed on devices
- ✅ Network connectivity for policy delivery
- ✅ Device status is "Compliant" or "Active" in InfiniPoint

## 🚀 Quick Deploy

```powershell
cd scripts/infinipoint
.\Deploy-Cx-Claude-Cli.ps1
```

## 📋 InfiniPoint Step-by-Step Deployment

### Step 1: Prepare the Script
- Location: `scripts/Deploy-Cx-Claude-Cli.ps1`
- No modifications needed - script handles everything

### Step 2: Upload Script to InfiniPoint

1. **Open InfiniPoint Admin Console**
   - Navigate: **Administration** → **Scripts** → **New Script**

2. **Configure Script**
   - **Name:** `Deploy Checkmarx - Claude Code`
   - **Platform:** Windows
   - **Type:** PowerShell
   - **Execution:** System

3. **Upload Script Content**
   - Copy entire content from `Deploy-Cx-Claude-Cli.ps1`
   - Paste into script editor
   - Click **Save**

### Step 3: Create Deployment Policy

1. **Navigate to Policies**
   - **Administration** → **Policies** → **+ New Policy**

2. **Configure Policy**
   - **Name:** `Deploy Checkmarx Claude Code Plugin`
   - **Type:** Script Execution
   - **Category:** Software Management

3. **Assign Script**
   - Select the script created above
   - Set execution frequency: **Once per device**
   - Or **Recurring** if you want continuous enforcement

4. **Set Target Devices**
   - Select device groups
   - Or target by device attributes

### Step 4: Deploy Policy

1. **Activate Policy**
   - Review all settings
   - Click **Deploy** or **Activate**

2. **Monitor Deployment**
   - **Reports** → **Policy Compliance**
   - Check deployment status
   - Verify policy execution on devices

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
| **Script fails to run / Policy shows failed** | Device not in correct compliance state | Check device status in InfiniPoint is "Compliant"; retry policy deployment |
| **File not created at `C:\Program Files\ClaudeCode`** | Script didn't execute or access denied | Run manually as admin: `powershell -ExecutionPolicy Bypass -File .\Deploy-Cx-Claude-Cli.ps1`; check for error messages |
| **Access denied error** | Insufficient permissions | Verify script execution mode is "System"; ensure admin privileges on device |
| **Plugin doesn't appear in Claude Code** | Cache issue or file not readable | Restart Claude Code completely; verify file: `Get-Content "C:\Program Files\ClaudeCode\managed-settings.json"` |
| **Policy status shows "Pending"** | Device hasn't synced yet | Wait 5-10 minutes for policy sync; force sync: **Device Management → Sync Device**; restart InfiniPoint agent |
| **JSON validation error** | File content corrupted or invalid | Check file format: `Get-Content "C:\Program Files\ClaudeCode\managed-settings.json" \| ConvertFrom-Json \| ConvertTo-Json` |
| **InfiniPoint agent not communicating** | Network or agent issue | Verify device has network access; restart InfiniPoint agent service on device |

### Most Common Issues (80% of problems)

1. **Device not in correct compliance state**
   - Open InfiniPoint Console → Check device status
   - If "Non-Compliant" or "Offline," fix device enrollment first
   - Wait for device to sync and return to "Compliant" status
   - Retry policy deployment

2. **Policy not deploying to device**
   - Verify device is included in policy target groups
   - Open policy → Review targeting conditions
   - Check device matches all targeting criteria (OS version, device attributes, etc.)
   - Force policy sync or restart InfiniPoint agent on device

3. **Script times out or takes too long**
   - Check network connectivity on device
   - Verify no other scripts are running concurrently
   - Check device disk space (need ~100MB free)
   - Increase policy timeout if available in InfiniPoint settings

4. **File exists but Claude Code doesn't load plugin**
   - Fully close Claude Code (kill process if needed)
   - Reopen Claude Code
   - Run `/plugin list` to verify
   - Check JSON syntax: manually validate in JSON viewer

## 🆘 Debug Steps

1. **Check Policy Status**
   - In InfiniPoint: **Reports** → **Policy Compliance**
   - Select device and check execution status

2. **Run Script Manually**
   - On device (as Administrator): `.\Deploy-Cx-Claude-Cli.ps1`
   - Check output for error messages

3. **Verify Configuration**
   - On device: `Get-Content "C:\Program Files\ClaudeCode\managed-settings.json"`
   - Verify JSON is valid and includes cx-devassist

4. **Check Device Connection**
   - Verify device is enrolled in InfiniPoint
   - Check last policy sync timestamp
   - Force sync if policy hasn't applied yet

## 📚 More Information

- **Main guide:** [../README.md](../README.md)
- **Quick start:** [../QUICK-START.md](../QUICK-START.md)
- **Script location:** `scripts/Deploy-Cx-Claude-Cli.ps1`

## 🎯 Success Indicators

✅ File created: `C:\Program Files\ClaudeCode\managed-settings.json`
✅ Valid JSON with `cx-devassist-marketplace` configured
✅ Plugin appears in Claude Code `/plugin list`
✅ Plugin is marked as enabled
✅ Policy shows successful deployment in InfiniPoint console
