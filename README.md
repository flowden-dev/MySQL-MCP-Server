# MCP MySQL Server

A read-only MCP server for MySQL and MariaDB. ChatGPT can inspect database structures, read stored code and query data. A PowerShell manager for Windows Server handles installation, settings, credentials and startup.

**Tested with a ChatGPT subscription account.** Other MCP clients and providers have not been tested.

The Python server uses **stdio**. OpenAI's tunnel client launches it and connects ChatGPT to it without exposing the database publicly.

## Requirements

- Windows Server 2016 or newer, with Windows PowerShell 5.1
- Standard 64-bit CPython **3.14.8 or a later 3.14 patch**, with the `py` launcher; free-threaded builds are not supported
- MariaDB **10.4+** or MySQL **8.0.20+**, and administrator access for the initial database setup
- OpenAI's `tunnel-client.exe`, a tunnel ID and a runtime API key, available through [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels)
- A trusted TLS CA certificate for remote database connections

For tunnel and ChatGPT access permissions, see the [OpenAI setup guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

## Setup

### 1. Open the manager

Place the package files and `tunnel-client.exe` in a permanent folder, such as `C:\MCP\MySQL`. Use the Windows account that will run the server.

```powershell
cd C:\MCP\MySQL
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\MCP_Manager.ps1
```

### 2. Install dependencies and configure the database

Choose **1: Install Python dependencies**, then **2: Configure database**. Enter the connection details, a fresh reader username, its password and a separate metadata schema for inspecting stored code.

If Python is installed without the `py` launcher, run Setup with its executable path:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\MCP_Manager.ps1 -Action Setup -PythonPath C:\Python314\python.exe
```

### 3. Create the read-only database account

Choose **13: Export database setup SQL**, then select your database engine. For a local database, keep the client host `127.0.0.1`; for a remote database, use the address from which this server connects.

Review the generated setup SQL in the printed output folder. Replace its password placeholders and run it as a database administrator, with the SQL client set to stop on errors. Use the reader password from step 2, account names not already used at any host and an unused metadata schema.

Export only creates files. Applying the SQL creates accounts, grants and metadata objects. Keep files containing passwords private.

### 4. Configure the tunnel

In a second PowerShell window, open the installation folder and create the tunnel profile:

```powershell
.\tunnel-client.exe init --sample sample_mcp_stdio_local --profile default --tunnel-id "YOUR_FULL_TUNNEL_ID" --mcp-command "C:\MCP\MySQL\.venv\Scripts\python.exe -I C:\MCP\MySQL\server.py"
```

Replace the tunnel ID and adjust both paths for your installation. The tunnel must forward `MCP_MYSQL_CONFIG` and `MCP_MYSQL_API_KEY_ENV` to Python without overrides. Profile creation is separate from the manager.

Return to the manager:

| Menu option | What to do |
| --- | --- |
| **12: Configure tunnel** | Select the executable and profile `default`; keep `CONTROL_PLANE_API_KEY` for the OpenAI client |
| **3: Install / replace API key** | Enter the tunnel's runtime API key; this is separate from the database password |
| **11: Test database access** | Verify the database connection, read-only grants and stored-code access |
| **5: Start** | Start the instance; you can then close the manager window |

### 5. Connect ChatGPT

Create a developer-mode app in ChatGPT, choose **Tunnel** and select your tunnel. Keep the instance running. If the tunnel is missing, check its workspace association and permissions using the OpenAI guide above.

For boot startup, reopen the manager **as administrator under the same Windows account**, choose **9: Enable boot autostart** and enter the account's Windows password. Startup runs with limited privileges after 30 seconds. Reinstall autostart after changing the password.

## Daily use

Open the manager for **Start**, **Stop**, **Restart**, **Status** and **Test**, or run an action directly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\MCP_Manager.ps1 -Action Status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\MCP_Manager.ps1 -Instance production -Action Restart
```

`-Instance` selects separate settings, credentials, logs and a startup task; the default is `default`. Use a different tunnel profile for each running instance. Python dependencies are shared, so stop every instance in the installation before running Setup.

Settings and logs are in `%LOCALAPPDATA%\MCP-MySQL\<instance>`. Secrets use Windows DPAPI encryption tied to your account. Stop the instance before changing credentials or editing `mcp-db.json`; menu-based database reconfiguration resets custom limits and table restrictions.

**Status** reports process state; **Test** checks database access. **RemoveKey** stops the instance, removes autostart and deletes the tunnel key. **DisableAutostart** stops it too. An ordinary Stop preserves boot startup. Before moving or replacing an installation, stop it and remove autostart with its original manager.

## Database tools

| Purpose | Tools |
| --- | --- |
| Connection and permissions | `database_info`, `database_permissions` |
| Tables, columns and indexes | `list_tables`, `describe_table`, `show_create_table` |
| Stored procedures and functions | `list_procedures`, `show_routine`, `routine_parameters` |
| Triggers and events | `list_logic`, `show_logic` |
| Data and query plans | `query_readonly`, `explain_readonly` |
| Pages and large values | `read_table_page`, `read_value`, `read_definition` |

Start with `database_info` and `list_tables`. Routines can be inspected, but not executed. Use returned continuation values for pages or chunks; calls do not share a database snapshot.

MariaDB metadata stays live. MySQL uses a snapshot: after schema migrations, run the exported `refresh-mysql8-metadata.sql` as a database administrator.

For direct stdio use, configure the MCP client to launch:

```powershell
.\.venv\Scripts\python.exe -I .\server.py --config C:\path\mcp-db.json
```

## Security and limits

Database grants enforce the primary read-only boundary. The server validates privileges, permits approved SELECT/CTE queries and uses read-only transactions. Writes, routine execution and file operations are rejected. Timeouts and resource limits bound database work.

Setup grants reads across the application schema. For sensitive data, use reviewed reporting views or table-level grants and restrict `allowed_tables` in `mcp-db.json`. Existing views and functions must be trusted. Protect the installation folder from untrusted changes; never publish credentials.

Dependencies are hash-verified using `requirements.lock.txt`. Default limits: 5-second statement timeout, up to 500 rows per page, 256 KiB per response and two concurrent reads per process.

## License

[MIT](LICENSE) - use, modify and redistribute the code, including commercially, with the license notice retained.
