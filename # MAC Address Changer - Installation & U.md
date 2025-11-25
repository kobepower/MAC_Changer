# MAC Address Changer - Installation & Usage Guide

## What You Need:
1. Python installed on Windows (download from python.org if you don't have it)
2. Administrator rights

## Installation Steps:

### Step 1: Install Python (if not installed)
1. Go to: https://www.python.org/downloads/
2. Download Python (latest version)
3. Run installer
4. ✅ CHECK "Add Python to PATH" during install
5. Click "Install Now"

### Step 2: Run the Program
1. Double-click: `run_mac_changer.bat`
2. Click "Yes" when Windows asks for admin permission
3. Program will open!

## How to Use:

### One-Click Random MAC Change:
1. Select a network adapter from the list
2. Click the big blue "🔄 CHANGE MAC (Random)" button
3. Done! Your MAC is changed and adapter restarts

### Custom MAC Change:
1. Select an adapter
2. Enter your MAC in "Custom MAC" field (format: 00:11:22:33:44:55)
3. Click "Change to Custom MAC"

### Restore Original:
1. Select adapter
2. Click "↺ Restore Original MAC"
3. Your hardware MAC is restored

## Features:
- ✅ Shows all network adapters
- ✅ One-click random MAC generation
- ✅ Custom MAC input
- ✅ Restore original MAC
- ✅ Auto-restart adapter after change

## Troubleshooting:

**"Not running as admin" error**
- Right-click `run_mac_changer.bat` → Run as Administrator

**"Python not found" error**
- Install Python (see Step 1)
- Make sure "Add to PATH" was checked

**Adapter doesn't show up**
- Click "🔃 Refresh Adapters"
- Make sure adapter is enabled in Windows

**MAC didn't change**
- Some adapters don't support MAC changing
- Try a different adapter
- Check if adapter driver allows MAC override

## Notes:
- You need admin rights to change MAC addresses
- Changing MAC will disconnect/reconnect your network briefly
- Some networks may detect MAC changes
- Original MAC is stored in hardware and can always be restored

## Legal Notice:
Use responsibly and only on networks you own or have permission to use.