"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

SEVERITY_MAPPING = {
    "SEV-1 (Critical)": "SEV-1",
    "SEV-2 (High)": "SEV-2",
    "SEV-3 (Moderate)": "SEV-3",
    "SEV-4 (Low)": "SEV-4",
    "SEV-5 (Minor)": "SEV-5",
    "Unknown": "UNKNOWN"
}

SORT_MAPPING = {
    "Ascending": "asc",
    "Descending": "desc"
}

INPUT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
