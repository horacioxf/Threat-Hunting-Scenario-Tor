# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/horacioxf/Threat-Hunting-Scenario-Tor/blob/main/Threat_Hunt_Event_(TOR%20Usage).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Queried for events using DeviceFileEvents and searched for files that start with `tor`. There was a user named `0xhoracio` who installed `tor-browser-windows-x86_64-portable-14.5.4.exe`. After installing and running Tor, the user then created a text file named `tor-shopping-list.txt` that was saved on the Desktop. These events began at `2025-07-11T18:02:46.1388825Z`. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "windows-vm" and FileName startswith "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1634" height="497" alt="image" src="https://github.com/user-attachments/assets/68416ab6-2e2a-409c-b38a-a5f862318394" />

---

### 2. Searched the `DeviceProcessEvents` Table

Queried for events using DeviceProcessEvents, it was discovered that there was a process created by using the command `tor-browser-windows-x86_64-portable-14.5.4.exe  /S` at the given date `2025-07-11T18:04:40.6860661Z`. The command installs the executable file silently without having a setup wizard show up or asking for user input.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "windows-vm"
|where Timestamp >= datetime(2025-07-11T18:02:46.1388825Z)
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
|project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

```
<img width="1640" height="379" alt="image" src="https://github.com/user-attachments/assets/5889f3de-893b-402b-8e48-c27158fde5af" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Queried for events using DeviceProcessEvents, it was discovered that the user `0xhoracio` did in fact opened and used the Tor browser. This started at `2025-07-11T18:05:12.1388675Z` and since then, there have been multiple instances of using Tor and Firefox. Tor is based on Firefox, which is why some file names are under `firefox.exe`. 

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName == "windows-vm"
|where Timestamp >= datetime(2025-07-11T18:02:46.1388825Z)
|where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc

```
<img width="1651" height="503" alt="image" src="https://github.com/user-attachments/assets/97968cc9-5427-48c7-affc-896a273c2f07" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Queried for events using DeviceNetworkEvents, it was discovered that the user `0xhoracio` did in fact use the Tor browser. There was a successful connection with the browser using the port `9150` with the process file name `firefox.exe`. This connection was made at `2025-07-11T18:05:38.3070996Z`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-vm"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName

```
<img width="1642" height="385" alt="image" src="https://github.com/user-attachments/assets/ca6b73f6-9430-4997-ae29-b28e4bbcd054" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-11T18:02:46.1388825Z`
- **Event:** User `0xhoracio` downloaded a file named `tor-browser-windows-x86_64-portable-14.5.4.exe` to the Downloads folder. 
- **Action:** File download detected.
- **File Path:** `C:\Users\0xhoracio\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-11T18:04:40.6860661Z`
- **Event:** User `0xhoracio` silently installed the file `tor-browser-windows-x86_64-portable-14.5.4.exe`.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- **File Path:** `C:\Users\0xhoracio\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-11T18:05:12.1388675Z`
- **Event:** User `0xhoracio` launched the Tor browser. This caused subsequent processes associated with Tor, such as `firefox.exe` and `tor.exe`, to be created.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** ` C:\Users\0xhoracio\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-11T18:05:38.3070996Z`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` was established using `tor.exe`.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `C:\Users\0xhoracio\Desktop\Tor Browser\Browser\firefox.exe`

<!--### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.
-->
### 5. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-11T18:02:46.1388825Z`
- **Event:** User `0xhoracio` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list related to their Tor browsing activities. 
- **Action:** File creation detected.
- **File Path:** `C:\Users\0xhoracio\Desktop\tor-shopping-list.txt`

---

## Summary

The user `0xhoracio` on the `windows-vm` device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish a connection within the Tor network, and create a file named `tor-shopping-list.txt` on their Desktop. This sequence of activities indicates that the user actively installed and used the Tor browser for anonymous browsing purposes, with documentation in the form of a shopping list text file. 

---

## Response Taken

TOR usage was confirmed on the endpoint `windows-vm` by the user `0xhoracio`. The device was isolated, and the user's direct manager was notified.

---
