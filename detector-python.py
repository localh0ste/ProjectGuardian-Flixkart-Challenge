
import csv
import json
import re
import sys
from typing import Dict, Any, Tuple

# --- Regular Expressions for Standalone PII ---
# Matches 10-digit phone numbers
PHONE_REGEX = re.compile(r'\b\d{10}\b')
# Matches 12-digit Aadhar numbers, with or without spaces
AADHAR_REGEX = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
# Matches a common passport format (e.g., P1234567)
PASSPORT_REGEX = re.compile(r'\b[A-Z]\d{7}\b')
# Matches UPI IDs (username@bank or phone@bank)
UPI_REGEX = re.compile(r'[\w.-]+@[\w.-]+')
# Matches standard email formats (used for combinatorial check)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


# --- PII Definitions ---
# Standalone PII fields that are always sensitive
STANDALONE_PII_FIELDS = {
    "phone": PHONE_REGEX,
    "contact": PHONE_REGEX,
    "aadhar": AADHAR_REGEX,
    "passport": PASSPORT_REGEX,
    "upi_id": UPI_REGEX,
}

# Combinatorial PII fields: sensitive only if >= 2 are present
COMBINATORIAL_PII_FIELDS = [
    "name", "email", "address", "device_id", "ip_address"
]

# --- Redaction Functions ---

def redact_phone(value: str) -> str:
    """Redacts a 10-digit phone number."""
    return f"{value[:2]}XXXXXX{value[-2:]}"

def redact_aadhar(value: str) -> str:
    """Redacts a 12-digit Aadhar number."""
    clean_value = value.replace(" ", "")
    return f"{clean_value[:4]} XXXX {clean_value[-4:]}"

def redact_passport(value: str) -> str:
    """Redacts a passport number."""
    return f"{value[0]}XXXXXX{value[-1]}"

def redact_generic_id(value: str) -> str:
    """Redacts email or UPI ID."""
    try:
        user, domain = value.split('@')
        redacted_user = f"{user[:2]}{'X' * (len(user) - 3)}{user[-1]}" if len(user) > 2 else "X"
        return f"{redacted_user}@{domain}"
    except ValueError:
        return "[REDACTED_ID]"

def redact_name(value: str) -> str:
    """Redacts a full name."""
    parts = value.split()
    redacted_parts = [f"{p[0]}{'X' * (len(p) - 1)}" if len(p) > 1 else p for p in parts]
    return " ".join(redacted_parts)

def redact_text(value: str) -> str:
    """Generic redaction for fields like address, IP, etc."""
    return f"[REDACTED_{len(value)}_CHARS]"


# --- Main Detection Logic ---

def process_record(data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Processes a single JSON record to detect and redact PII.

    Returns:
        A tuple containing the redacted data dictionary and a boolean indicating if PII was found.
    """
    is_pii_record = False
    redacted_data = data.copy()
    combinatorial_pii_found = []

    # 1. Check for Standalone PII
    for key, value in data.items():
        if isinstance(value, str):
            # Check against predefined standalone fields and their regex
            if key in STANDALONE_PII_FIELDS and STANDALONE_PII_FIELDS[key].match(value):
                is_pii_record = True
                if key in ["phone", "contact"]:
                    redacted_data[key] = redact_phone(value)
                elif key == "aadhar":
                    redacted_data[key] = redact_aadhar(value)
                elif key == "passport":
                    redacted_data[key] = redact_passport(value)
                elif key == "upi_id":
                    redacted_data[key] = redact_generic_id(value)

    # 2. Identify potential Combinatorial PII
    for key in COMBINATORIAL_PII_FIELDS:
        if key in data and data[key]:
            # Specific check for full names vs. single names
            if key == "name" and len(str(data[key]).split()) < 2:
                continue # Skip single names as they are not PII
            # Specific check for valid email format
            if key == "email" and not EMAIL_REGEX.match(str(data[key])):
                continue
            combinatorial_pii_found.append(key)

    # 3. Process Combinatorial PII if criteria are met
    if len(combinatorial_pii_found) >= 2:
        is_pii_record = True
        for key in combinatorial_pii_found:
            value = str(data[key])
            if key == "name":
                redacted_data[key] = redact_name(value)
            elif key == "email":
                redacted_data[key] = redact_generic_id(value)
            elif key in ["address", "ip_address", "device_id"]:
                redacted_data[key] = redact_text(value)

    return redacted_data, is_pii_record


def main(input_file: str):
    """
    Main function to read, process, and write the CSV data.
    """
    output_file = "redacted_output.csv"
    print(f"Processing '{input_file}'...")

    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
             open(output_file, 'w', newline='', encoding='utf-8') as outfile:

            reader = csv.DictReader(infile)
            writer = csv.writer(outfile)
            writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])

            processed_count = 0
            for row in reader:
                try:
                    record_id = row['record_id']
                    data_json = json.loads(row['Data_json'])

                    redacted_json, is_pii = process_record(data_json)

                    # Write the new row
                    writer.writerow([
                        record_id,
                        json.dumps(redacted_json),
                        is_pii
                    ])
                    processed_count += 1
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"Skipping malformed row {row.get('record_id', '')}: {e}")

            print(f"Processing complete. Processed {processed_count} records.")
            print(f"Output saved to '{output_file}'")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector-localh0ste.py <input_csv_file>")
        sys.exit(1)
    
    input_filename = sys.argv[1]
    main(input_filename)
