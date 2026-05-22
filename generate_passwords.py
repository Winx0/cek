#!/usr/bin/env python3
"""Generate password variations from known passwords for brute-force."""

BASE_PASSWORDS = [
    "Sipil@1991",
    "SWT@1991",
    "Ernisyach595830",
    "Syah@1991",
    "syah1991",
    "erniwati11",
    "Sipil1991",
]

WORDS = [
    "sipil", "Sipil", "SIPIL",
    "syah", "Syah", "SYAH",
    "erwin", "Erwin", "ERWIN",
    "erni", "Erni", "ERNI",
    "ernisyach", "Ernisyach", "ERNISYACH",
    "erniwati", "Erniwati", "ERNIWATI",
    "swt", "SWT", "Swt",
    "antek", "Antek", "ANTEK",
    "bitcoin", "Bitcoin",
    "blockchain", "Blockchain",
]

NUMBERS = [
    "", "1", "11", "12", "123", "1234", "12345",
    "1991", "1992", "1993", "1990", "1989",
    "2014", "2020", "2021",
    "91", "92", "93", "90", "89",
    "595830", "59583", "5958",
    "01", "02", "03", "04", "05",
    "001", "007", "99", "100",
    "0", "00", "000",
]

SYMBOLS = ["", "@", "!", "#", "$", "%", "&", "*", ".", "_", "-"]

YEARS = ["1989", "1990", "1991", "1992", "1993", "2014", "2020", "2021"]


def generate_variations():
    passwords = set()

    for p in BASE_PASSWORDS:
        passwords.add(p)

    for base in BASE_PASSWORDS:
        passwords.add(base)
        passwords.add(base.lower())
        passwords.add(base.upper())
        passwords.add(base.capitalize())
        passwords.add(base.swapcase())
        passwords.add(base + "1")
        passwords.add(base + "!")
        passwords.add(base + "@")
        passwords.add(base + "#")
        passwords.add(base + "123")
        if len(base) > 1:
            passwords.add(base[:-1])
            passwords.add(base[1:])

        for sym in SYMBOLS:
            passwords.add(base.replace("@", sym))

        stripped = base.rstrip("0123456789")
        for num in NUMBERS:
            passwords.add(stripped + num)

        for year in YEARS:
            passwords.add(stripped + year)
            passwords.add(stripped + "@" + year)

    for word in WORDS:
        for num in NUMBERS:
            passwords.add(word + num)
            for sym in SYMBOLS:
                passwords.add(word + sym + num)
                passwords.add(word + num + sym)

    prefixes = ["Sipil", "sipil", "Syah", "syah", "SWT", "swt",
                "Erwin", "erwin", "Erni", "erni", "Ernisyach", "ernisyach",
                "Erniwati", "erniwati", "Antek", "antek"]

    for prefix in prefixes:
        for sym in SYMBOLS:
            for year in YEARS:
                passwords.add(prefix + sym + year)
                passwords.add(prefix + year + sym)

        for num in ["11", "12", "123", "1991", "595830", "1234"]:
            passwords.add(prefix + num)
            passwords.add(prefix + "@" + num)
            passwords.add(prefix + "!" + num)
            passwords.add(prefix + "#" + num)

    email_bases = ["ernisyach", "ernisyach595830", "595830ernisyach"]
    for eb in email_bases:
        passwords.add(eb)
        passwords.add(eb.capitalize())
        for sym in SYMBOLS:
            for num in NUMBERS:
                passwords.add(eb + sym + num)

    return sorted(passwords)


def main():
    passwords = generate_variations()
    passwords = [p for p in passwords if p and len(p) >= 4]
    passwords = sorted(set(passwords))

    output_file = "passwords.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for p in passwords:
            f.write(p + "\n")

    print(f"Generated {len(passwords)} password variations")
    print(f"Saved to: {output_file}")
    print(f"At 155 passwords/sec, ETA: {len(passwords) / 155:.0f} seconds ({len(passwords) / 155 / 60:.1f} minutes)")


if __name__ == "__main__":
    main()
