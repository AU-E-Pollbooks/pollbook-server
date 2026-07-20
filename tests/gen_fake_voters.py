from faker import Faker
import csv
import random

def generate_fake_data(num_rows, output_file):
    fake = Faker("en_US")
    Faker.seed(0)
    random.seed(0)

    with open(output_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        # Header
        writer.writerow([
            "UID", "PIN", "Last Name", "First Name", "Middle Name",
            "Street Address", "City", "State", "Zip"
        ])

        uid = 100000
        for _ in range(num_rows):
            last_name = fake.last_name()
            first_name = fake.first_name()
            middle_name = fake.first_name()
            street_address = fake.street_address()
            city = "Augusta"
            state = "GA"
            zip_code = fake.zipcode_in_state("GA")
            pin = random.randint(100, 999)  # random PIN

            writer.writerow([
                uid, pin, last_name, first_name, middle_name,
                street_address, city, state, zip_code
            ])

            # Increment UID with some randomness
            uid += random.choice([1, random.randint(2, 500)])

if __name__ == "__main__":
    generate_fake_data(100, "voters.csv")

