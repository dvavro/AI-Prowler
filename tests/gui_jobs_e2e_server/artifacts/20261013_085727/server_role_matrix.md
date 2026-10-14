# Server role matrix (SRV-API-01)

| Probe | Tool | U1 owner | U2 manager | U3 field_crew |
|---|---|---|---|---|
| read Jobs_Schedule | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ ok |
| read Customers | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ ok |
| read TimeLog | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ ok |
| read Route_Planner | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ ok |
| read Invoices | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ denied |
| read Quotes | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ denied |
| read Services_Pricing | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ denied |
| read Settings | `read_job_spreadsheet` | ✅ ok | ✅ ok | ✅ denied |
| board feed Jobs_Schedule | `get_board_updates` | ✅ ok | ✅ ok | ✅ ok |
| board feed Customers | `get_board_updates` | ✅ ok | ✅ ok | ✅ ok |
| board feed Invoices | `get_board_updates` | ✅ ok | ✅ ok | ✅ denied |
| board feed Settings | `get_board_updates` | ✅ ok | ✅ ok | ✅ denied |
| columns Jobs_Schedule | `get_sheet_columns` | ✅ ok | ✅ ok | ✅ ok |
| columns Customers | `get_sheet_columns` | ✅ ok | ✅ ok | ✅ ok |
| status | `check_ai_prowler_status` | ✅ ok | ✅ ok | ✅ ok |
| SMS configured? | `check_sms_configured` | ✅ ok | ✅ ok | ✅ ok |
| email configured? | `check_email_configured` | ✅ ok | ✅ ok | ✅ ok |
| route start options | `get_route_start_options` | ✅ ok | ✅ ok | ✅ ok |
| stale customers (Reports) | `find_stale_customers` | ✅ ok | ✅ ok | ✅ denied |
| AR aging report (Reports) | `get_ar_aging_report` | ✅ ok | ✅ ok | ✅ denied |
| search learnings (G-06) | `search_learnings` | ✅ ok | ✅ ok | ✅ ok |
| geocode address (G-06) | `geocode_address` | ✅ ok | ✅ ok | ✅ ok |
| Tier A run_script | `run_script` | ✅ unknown | ✅ unknown | ✅ unknown |
| Tier A check_sms_inbox | `check_sms_inbox` | ✅ unknown | ✅ unknown | ✅ unknown |
| Tier A read_file_lines | `read_file_lines` | ✅ unknown | ✅ unknown | ✅ unknown |
| Tier A write_file | `write_file` | ✅ unknown | ✅ unknown | ✅ unknown |
| made-up tool | `ztest_no_such_tool` | ✅ unknown | ✅ unknown | ✅ unknown |

No differences from spec §6.11.1.
