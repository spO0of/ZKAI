from generate_keys import generate_keys
from generate_dataset import generate_dataset


KEYS_NAME = input("KEYS_NAME (default : id_rsa) >") or 'id_rsa'

raw = input("DATASET_ARGS (default : name, email): ")
DATASET_ARGS = raw.replace(' ', '').split(',') if raw else ['name', 'email']

DATASET_DATA = {}
for KEY in DATASET_ARGS:
    DATASET_DATA[KEY] = input(f"{KEY} (default : random) >") or 'random'


generate_keys(KEYS_NAME)
generate_dataset(DATASET_DATA, KEYS_NAME)
