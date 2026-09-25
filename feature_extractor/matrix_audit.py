import pandas as pd
from itertools import product

DATASET = "dataset.csv"

# ============================================================
# EXPECTED CRYPTOGRAPHIC VALUES
# ============================================================

EXPECTED = {
    "encryption": ["AES128", "AES256"],
    "hash": ["SHA256", "SHA384"],
    "dh_group": ["DH14", "DH15"],
    "pfs_group": ["NOPFS", "PFS14", "PFS15"],
}

# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 90)
print("IPsec EXPERIMENT MATRIX AUDIT")
print("=" * 90)

df = pd.read_csv(DATASET)

print(f"\nDataset: {DATASET}")
print(f"Rows   : {len(df)}")

# ============================================================
# BASIC COUNTS
# ============================================================

print("\n" + "=" * 90)
print("AVAILABLE VALUES")
print("=" * 90)

for column, values in EXPECTED.items():
    print(f"\n{column}:")
    for value in values:
        count = (df[column] == value).sum()
        print(f"  {value:<10} {count}")

# ============================================================
# FULL 4-D CRYPTOGRAPHIC COMBINATIONS
# ============================================================

print("\n" + "=" * 90)
print("FULL CRYPTOGRAPHIC COMBINATION MATRIX")
print("=" * 90)

all_combinations = list(
    product(
        EXPECTED["encryption"],
        EXPECTED["hash"],
        EXPECTED["dh_group"],
        EXPECTED["pfs_group"],
    )
)

observed = set(
    zip(
        df["encryption"],
        df["hash"],
        df["dh_group"],
        df["pfs_group"],
    )
)

missing = []
present = []

for combo in all_combinations:
    if combo in observed:
        count = len(
            df[
                (df["encryption"] == combo[0])
                & (df["hash"] == combo[1])
                & (df["dh_group"] == combo[2])
                & (df["pfs_group"] == combo[3])
            ]
        )
        present.append((*combo, count))
    else:
        missing.append(combo)

print(f"\nPossible combinations : {len(all_combinations)}")
print(f"Observed combinations : {len(present)}")
print(f"Missing combinations  : {len(missing)}")

print("\nPRESENT:")
for encryption, hash_, dh, pfs, count in present:
    print(
        f"  {encryption:<7} {hash_:<7} "
        f"{dh:<5} {pfs:<6} -> {count} samples"
    )

print("\nMISSING:")
if missing:
    for encryption, hash_, dh, pfs in missing:
        print(
            f"  {encryption:<7} {hash_:<7} "
            f"{dh:<5} {pfs:<6}"
        )
else:
    print("  None")

# ============================================================
# PAIRWISE MATRIX AUDIT
# ============================================================

def audit_pair(column_a, column_b):
    print("\n" + "-" * 90)
    print(f"{column_a.upper()} × {column_b.upper()}")
    print("-" * 90)

    expected_pairs = list(
        product(EXPECTED[column_a], EXPECTED[column_b])
    )

    observed_pairs = set(
        zip(df[column_a], df[column_b])
    )

    for a, b in expected_pairs:
        count = len(
            df[
                (df[column_a] == a)
                & (df[column_b] == b)
            ]
        )

        status = "PRESENT" if count > 0 else "MISSING"

        print(
            f"{a:<10} + {b:<10} "
            f"-> {count:>3} samples [{status}]"
        )


print("\n" + "=" * 90)
print("PAIRWISE MATRIX AUDIT")
print("=" * 90)

pairs = [
    ("encryption", "hash"),
    ("encryption", "dh_group"),
    ("encryption", "pfs_group"),
    ("hash", "dh_group"),
    ("hash", "pfs_group"),
    ("dh_group", "pfs_group"),
]

for a, b in pairs:
    audit_pair(a, b)

# ============================================================
# CRYPTOGRAPHIC BALANCE
# ============================================================

print("\n" + "=" * 90)
print("CRYPTOGRAPHIC BALANCE")
print("=" * 90)

for column, values in EXPECTED.items():
    counts = df[column].value_counts()

    print(f"\n{column}:")
    for value in values:
        count = counts.get(value, 0)
        print(f"  {value:<10}: {count}")

# ============================================================
# FINAL DIAGNOSIS
# ============================================================

print("\n" + "=" * 90)
print("AUDIT SUMMARY")
print("=" * 90)

if missing:
    print("\nWARNING: The experiment matrix is incomplete.")
    print(f"Missing full combinations: {len(missing)}")
else:
    print("\nThe full cryptographic matrix is complete.")

print("\nImportant:")
print("This audit checks whether combinations exist.")
print("It does NOT judge whether the ML features can correctly")
print("identify those combinations.")

print("\n" + "=" * 90)
print("AUDIT COMPLETE")
print("=" * 90)