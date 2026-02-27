import pathlib
from configparser import ConfigParser

# Initialize a new instance of the `ConfigParser` object.
config = ConfigParser()

# Define a new section called `main`.
config.add_section('main')

# Set the values for the `main` section.
config.set('main', 'REGULAR_ACCOUNT', 'YOUR_ACCOUNT_NUMBER')
config.set('main', 'REGULAR_USERNAME', 'YOUR_ACCOUNT_USERNAME')

config.set('main', 'PAPER_ACCOUNT', 'DUP212569')
config.set('main', 'PAPER_USERNAME', 'andreiwerribee')

# Make the `config` folder for the user.
new_directory = pathlib.Path("config/").mkdir(parents=True, exist_ok=True)

# Write the contents of the `ConfigParser` object to the `config.ini` file.
with open('config/config.ini', 'w+') as f:
    config.write(f)