from datetime import date

def calculate_age(dob):
    today = date.today()

    # Case: Only year available
    if len(dob) == 4:
        return today.year - int(dob)

    # Normalize DOB
    dob = dob.replace("-", "/").replace(" ", "")
    day, month, year = map(int, dob.split("/"))

    birth_date = date(year, month, day)

    age = today.year - birth_date.year
    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1

    return age
