# Jamf Pro - Claude Code MDM Deployment

Deploy Checkmarx cx-devassist plugin to Claude Code via Jamf Pro.

## ⏱️ Expected Timeline
- **Script upload:** 5 minutes
- **Policy creation:** 5 minutes
- **Policy sync to devices:** 5-15 minutes (faster than Intune)
- **Script execution:** 2-5 minutes per device
- **Total:** 15-25 minutes from start to user availability

## ✅ Prerequisites
- ✅ macOS devices enrolled in Jamf Pro
- ✅ Jamf Pro administrator access
- ✅ Claude Code installed on target Macs
- ✅ Bash shell available (standard on macOS)
- ✅ Root/sudo execution permissions on devices
- ✅ Network access for policy delivery
- **(Optional)** Xcode Command Line Tools installed (for Python JSON parsing)

## 🚀 Quick Deploy

```bash
cd scripts/jamf-pro
sudo bash Deploy-Cx-Claude-Cli.sh
```

## 📋 Jamf Pro Step-by-Step Deployment

### Step 1: Prepare the Script
- Location: `scripts/jamf-pro/Deploy-Cx-Claude-Cli.sh`
- No modifications needed - script handles everything

### Step 2: Create Script in Jamf

1. **Open Jamf Pro Console**
   - Navigate to: **Computers** → **Management Settings** → **Scripts**

2. **Create New Script**
   - Click **+ New**
   - **Display Name:** `Deploy Checkmarx - Claude Code`
   - **Priority:** High
   - **Category:** (optional)

3. **Upload Script Content**
   - Copy entire content from `Deploy-Cx-Claude-Cli.sh` (from scripts/jamf-pro/)
   - Paste into **Script** field
   - Leave other options as default
   - Click **Save**

### Step 3: Create Policy

1. **Navigate to Policies**
   - **Computers** → **Policies** → **+ New**

2. **Name the Policy**
   - **Display Name:** `Deploy Checkmarx Claude Code Plugin`
   - **Category:** (optional)

3. **Add Script**
   - **Scripts** tab → **Configure**
   - Click **+ Add**
   - Select the script you created
   - Click **Save**

4. **Configure Scope**
   - **Targets** tab
   - Select target **Categories** and **Smart Groups**
   - Or select specific **Computers**

5. **Set Execution Frequency**
   - **Frequency:** Once per computer
   - Or **Ongoing** if you want continuous enforcement

6. **Review and Save**
   - Verify all settings
   - Click **Save**

### Step 4: Deploy to Devices

1. **Push Policy to Devices**
   - Find created policy
   - Click **Scope** → Push to devices
   - Or wait for devices to check in

2. **Monitor Deployment**
   - **Computers** → **Smart Groups**
   - Create a group to monitor deployment status

## ✅ Verification

### On Target Device

```bash
# 1. Check file exists
test -f "/Library/Application Support/ClaudeCode/managed-settings.json" && echo "✅ File exists"

# 2. View configuration
cat "/Library/Application Support/ClaudeCode/managed-settings.json" | python3 -m json.tool

# 3. Check permissions
ls -la "/Library/Application Support/ClaudeCode/managed-settings.json"
# Should show: -rw-r--r-- root wheel

# 4. Verify in Claude Code
# Open Claude Code → Run `/plugin list` → Should see cx-devassist
```

## 🔧 Troubleshooting

### Common Issues & Solutions

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| **Script doesn't run / Policy shows as failed** | Scope targeting incorrect | Verify policy scope targets correct smart groups/computers; check device is in scope |
| **File not created at `/Library/Application Support/ClaudeCode`** | Script error or insufficient permissions | Run script manually: `sudo bash Deploy-Cx-Claude-Cli.sh`; check error output |
| **Permission denied error** | Script not running as root | Jamf policy must execute with root privileges; verify in policy settings |
| **Python3 not found** | Missing Xcode Command Line Tools | Run: `xcode-select --install`; retry deployment |
| **Plugin doesn't appear in Claude Code** | App cache issue or file not readable | Restart Claude Code; verify file exists: `ls -la "/Library/Application Support/ClaudeCode/"` |
| **Deployment takes longer than expected** | Normal for Jamf distribution | Jamf waits for device check-in; wait 10-15 minutes; force re-inventory if urgent |
| **JSON parsing fails on verification** | Python3 issue or file not created | Install Xcode tools or view file directly: `cat "/Library/Application Support/ClaudeCode/managed-settings.json"` |
| **File exists but has wrong permissions** | Script didn't set ownership correctly | Manual fix: `sudo chown root:wheel "/Library/Application Support/ClaudeCode/managed-settings.json"` |

### Most Common Issues (85% of problems)

1. **Device not in policy scope**
   - Open Jamf → Policy → Verify "Scope" section includes target device
   - Add device to correct smart group or select explicitly
   - Force re-inventory on device if needed

2. **Policy shows as "Pending" or not running**
   - Wait for device next check-in (typically 15 minutes)
   - Force device to check in: **Jamf Console → Computer → Inventory → Update Inventory**
   - Or on device: `sudo jamf policy`

3. **Script error: "line X: python3: command not found"**
   - Install Xcode Command Line Tools: `xcode-select --install`
   - Verify: `which python3`
   - Retry deployment

4. **File created but Claude Code doesn't see plugin**
   - Close and fully restart Claude Code (quit and reopen)
   - Run `/plugin list` to check
   - Verify JSON validity: `cat "/Library/Application Support/ClaudeCode/managed-settings.json" | python3 -m json.tool`

## 🆘 Debug Steps

1. **Check Policy Status**
   - In Jamf: **Computers** → **Policies** → Select policy
   - View deployment status

2. **Check Device Logs**
   - On device: `cat "/Library/Application Support/ClaudeCode/managed-settings.json"`
   - If not found, policy hasn't run yet

3. **Run Manually**
   - As root: `sudo bash Deploy-Cx-Claude-Cli.sh`
   - Check output for errors

4. **Verify Jamf Connection**
   - Check device last checked in with Jamf
   - Force re-inventory if needed
   - Wait a few minutes for policy to apply

## 📚 More Information

- **Main guide:** [../README.md](../README.md)
- **Quick start:** [../QUICK-START.md](../QUICK-START.md)
- **Script location:** `scripts/deploy-claude-code-jamf.sh`

## 🎯 Success Indicators

✅ File created: `/Library/Application Support/ClaudeCode/managed-settings.json`
✅ Owned by root:wheel with mode 644
✅ Valid JSON with `cx-devassist-marketplace` configured
✅ Plugin appears in Claude Code `/plugin list`
✅ Plugin is marked as enabled
