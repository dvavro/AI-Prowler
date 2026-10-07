"""ZTEST test data + cleanup for the Jobs-app E2E suite (spec §4.1, §4.5).

Everything lives on the sandbox date (2030-01-07) under 'ZTEST E2E' names,
attached to ONE customer 'ZTEST E2E Customer' — so deleting that customer
removes every job, route stop, time entry, invoice and quote in one step
(one safety backup instead of dozens). The customer never gets a Frequency,
so the app's once-a-day recurring-job sweep can't spawn jobs from it.
"""
from __future__ import annotations

from api import ApiClient, iso_date
from safety import SANDBOX_DATE, SANDBOX_DATES, ZTEST_PREFIX, ZTEST_CODE_PREFIX, sandbox_day  # noqa: F401

CUSTOMER_NAME = f"{ZTEST_PREFIX} Customer"

# Public New Smyrna Beach places (David's decision #3). Coordinates are set
# explicitly so routing doesn't depend on the geocoder.
PLACES = {
    "city_hall":  ("210 Sams Ave",         29.0258, -80.9270),
    "brannon":    ("105 S Riverside Dr",   29.0263, -80.9216),
    "library":    ("1001 S Dixie Fwy",     29.0122, -80.9303),
    "flagler":    ("1 Flagler Ave",        29.0413, -80.8965),
    "sports":     ("201 Sports Complex Dr", 29.0060, -80.9458),
}


class TestData:
    def __init__(self, api: ApiClient, log=None):
        self.api = api
        self.guard = api.guard
        self.log = log or (lambda *a: None)
        self._cust_id = None

    # ── creation ─────────────────────────────────────────────────────────────
    def customer_id(self) -> str:
        if self._cust_id:
            return self._cust_id
        out = self.api.call("create_customer", {"updates": {"Company Name": CUSTOMER_NAME,
                                                "City": "New Smyrna Beach", "State": "FL",
                                                "ZIP": "32168", "Status Active/Inactive": "Active"}})
        self._cust_id = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
        return self._cust_id

    def job(self, label: str, place: str = "city_hall", *, date: str = SANDBOX_DATE,
            street: str | None = None, lat=None, lon=None, **fields) -> str:
        st, la, lo = PLACES[place]
        f = {"CustomerID": self.customer_id(), "Customer Name / Company": f"{ZTEST_PREFIX} {label}",
             "Service Date": date, "Street Address": st if street is None else street,
             "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168",
             "Latitude (AI Geocode)": la if lat is None else lat,
             "Longitude (AI Geocode)": lo if lon is None else lon,
             "Service Type": "Window", "Job Status": "Scheduled",
             "Schedule Type (Hard/Soft)": "Soft", "Est. Duration": 30, "Est. Duration Unit": "min"}
        f.update(fields)
        out = self.api.call("create_job", {"updates": f})
        return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

    # ── cleanup ──────────────────────────────────────────────────────────────
    def sweep(self, reason: str) -> dict:
        """Delete ALL test data (this run's and any leftovers). Never touches
        anything that isn't provably test data (Guard.adopt enforces that)."""
        api, g, n = self.api, self.guard, {"route_days": 0, "customers": 0, "jobs": 0, "prices": 0}
        self.log(f"sweep ({reason}): start")

        # 1. every sandbox-window day's route, one call per day that has one
        days = sorted({iso_date(s.get("Route Date", "")) for s in api.read("Route_Planner")} & SANDBOX_DATES)
        for day in days:
            api.call("delete_route", {"route_date": day, "confirm": True})
        n["route_days"] = len(days)

        # 2. test customers (cascades their jobs, stops, time entries, invoices, quotes)
        for c in api.read("Customers"):
            name, cid = c.get("Company Name", ""), c.get("CustomerID (CUST-####)", "")
            if cid and name.startswith(ZTEST_PREFIX):
                g.adopt(cid, name=name, reason=reason)
                if c.get("Status Active/Inactive", "") != "Inactive":
                    api.call("update_job_spreadsheet", {"job_identifier": cid, "sheet_name": "Customers",
                             "id_column": "CustomerID (CUST-####)",
                             "updates": {"Status Active/Inactive": "Inactive"}})
                api.call("delete_customer", {"customer_identifier": cid, "confirm": True})
                n["customers"] += 1
        self._cust_id = None

        # 3. any remaining test job (e.g. created without the test customer)
        for j in api.read("Jobs_Schedule"):
            jid, name = j.get("JobID (JOB-####)", ""), j.get("Customer Name / Company", "")
            d = iso_date(j.get("Service Date", ""))
            if jid and (name.startswith(ZTEST_PREFIX) or d in SANDBOX_DATES):
                g.adopt(jid, name=name, date=d, reason=reason)
                if j.get("Job Status", "").lower() != "cancelled":
                    api.call("update_job_spreadsheet", {"job_identifier": jid, "id_column": "JobID (JOB-####)",
                             "updates": {"Job Status": "Cancelled"}})
                api.call("delete_job", {"job_identifier": jid, "confirm": True})
                n["jobs"] += 1

        # 4. test price codes
        for p in api.read("Services_Pricing"):
            code = p.get("Service Code", "")
            if code.upper().startswith(ZTEST_CODE_PREFIX):
                api.call("delete_service_pricing", {"service_code": code, "confirm": True})
                n["prices"] += 1

        self.log(f"sweep ({reason}): removed {n}")
        return n

    def leftovers(self) -> list[str]:
        """What test data still exists (should be empty after a sweep)."""
        api, out = self.api, []
        for c in api.read("Customers"):
            if c.get("Company Name", "").startswith(ZTEST_PREFIX):
                out.append(f"customer {c.get('CustomerID (CUST-####)')} {c.get('Company Name')}")
        for j in api.read("Jobs_Schedule"):
            if (j.get("Customer Name / Company", "").startswith(ZTEST_PREFIX)
                    or iso_date(j.get("Service Date", "")) in SANDBOX_DATES):
                out.append(f"job {j.get('JobID (JOB-####)')} {j.get('Customer Name / Company')}")
        for s in api.read("Route_Planner"):
            d = iso_date(s.get("Route Date", ""))
            if d in SANDBOX_DATES:
                out.append(f"route stop {s.get('ID')} on {d}")
        for p in api.read("Services_Pricing"):
            if p.get("Service Code", "").upper().startswith(ZTEST_CODE_PREFIX):
                out.append(f"price {p.get('Service Code')}")
        return out
