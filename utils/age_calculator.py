from datetime import date


def calculate_age(dob: str) -> int:
    """Calculate age in years from a DOB string.

    Accepts:
      - full dates like "DD/MM/YYYY", "DD-MM-YYYY" (separators normalised)
      - year-only strings like "YYYY"

    Raises ValueError on malformed or impossible dates (e.g. 31/02/2000).
    """
    if not dob:
        raise ValueError("Empty DOB")

    today = date.today()
    cleaned = dob.strip().replace("-", "/").replace(" ", "")

    parts = cleaned.split("/")

    # Year-only case.
    if len(parts) == 1 and len(parts[0]) == 4 and parts[0].isdigit():
        year = int(parts[0])
        if not (1900 <= year <= today.year):
            raise ValueError("Implausible year of birth: %s" % parts[0])
        return today.year - year

    if len(parts) != 3:
        raise ValueError("Unrecognised DOB format: %r" % dob)

    try:
        day, month, year = (int(p) for p in parts)
        birth_date = date(year, month, day)  # validates the calendar date
    except (ValueError, TypeError):
        raise ValueError("Invalid DOB: %r" % dob)

    if birth_date > today:
        raise ValueError("DOB is in the future: %r" % dob)

    age = today.year - birth_date.year
    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1
    return age
